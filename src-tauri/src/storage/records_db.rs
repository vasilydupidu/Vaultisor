// RecordsDb — SQLCipher-зашифрованная база с записями и полями.
//
// Использует SQLCipher (форк SQLite + AES-256-CBC + HMAC-SHA512 на каждую
// страницу). Ключ деривируется из master_key через HKDF-SHA256:
//
//     sqlcipher_key = HKDF(master_key, "vaultisor:sqlcipher-records:v1", 32)
//
// Это означает: кто имеет master_key, тот имеет доступ к records.db.
// Master_key получается одним из путей:
//   - PIN (Argon2id + Device Secret из TPM, затем DPAPI);
//   - FIDO2-ключ (hmac-secret + Device Secret);
//   - восстановление по частям B и C.
//
// На чужой машине Device Secret и DPAPI не разворачиваются → остаётся
// восстановление по частям B и C → master_key → ключ SQLCipher → records.db.
// Записи читаются без потерь.
//
// Защита: даже на той же машине файл records.db без master_key — это AES-CBC
// шифротекст. Атакующий, имеющий только vault.records.db, не сможет
// прочитать ни имена записей, ни их содержимое.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use rusqlite::Connection;
use zeroize::Zeroize;

use crate::error::{Result, VaultError};

/// Куда сообщать о новом состоянии базы после commit (внешний checkpoint):
/// ревизия и SHA-256 файла.
pub type RevisionSink = Box<dyn Fn(u64, [u8; 32]) -> Result<()> + Send + Sync>;

/// SHA-256 файла базы. Вместе с ревизией — подтверждаемое состояние: ревизия
/// ловит замену файла целиком, дайджест — подмену отдельных страниц.
pub fn file_digest(path: &Path) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    Ok(Sha256::digest(std::fs::read(path)?).into())
}

/// Ревизия базы для защиты от отката.
///
/// Каждое изменение данных увеличивает `db_state.revision` триггером в той же
/// транзакции, поэтому ревизия растёт при любом durable commit — каким бы
/// путём код ни менял базу. После commit ревизия подтверждается во внешнем
/// checkpoint'е (`RevisionSink`). Сбой между commit и подтверждением
/// оставляет базу на ревизию впереди checkpoint'а — это продолжение вперёд,
/// а не откат: при следующем входе checkpoint догоняется. База с ревизией
/// ниже подтверждённой — подложенная старая копия.
pub struct RecordsDb {
    conn: Mutex<Connection>,
    path: PathBuf,
    /// Последняя ревизия, переданная в `sink`.
    confirmed: AtomicU64,
    sink: Mutex<Option<RevisionSink>>,
}

impl RecordsDb {
    /// Validate every encrypted page of a staged backup without migrations or
    /// writes. Checking just sqlite_master misses corruption in data pages.
    pub fn verify_snapshot(path: &Path, key: &[u8; 32]) -> Result<()> {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let key_hex = zeroize::Zeroizing::new(hex::encode(key));
        let pragma = zeroize::Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", key_hex.as_str()));
        conn.execute_batch(&pragma)?;
        conn.execute_batch("PRAGMA cipher_compatibility = 4;")?;
        let count: i64 = conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))?;
        if count == 0 {
            return Err(VaultError::MetaTampered);
        }
        let mut cipher_check = conn.prepare("PRAGMA cipher_integrity_check")?;
        if cipher_check.query([])?.next()?.is_some() {
            return Err(VaultError::MetaTampered);
        }
        let mut check = conn.prepare("PRAGMA integrity_check")?;
        let mut rows = check.query([])?;
        let result: String = rows.next()?.ok_or(VaultError::MetaTampered)?.get(0)?;
        if result != "ok" || rows.next()?.is_some() {
            return Err(VaultError::MetaTampered);
        }
        Ok(())
    }

    /// Открыть SQLCipher-БД. Если файл новый — будет создан и зашифрован
    /// переданным ключом. Если существующий — ключ должен совпадать с тем,
    /// которым БД была создана/перешифрована, иначе любой запрос упадёт
    /// с "file is not a database".
    pub fn open(path: &Path, sqlcipher_key: &[u8; 32]) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if !path.exists() {
            crate::failpoint::hit("records.create_file")?;
        }
        let conn = Connection::open(path)?;
        // КРИТИЧНО: PRAGMA key должна быть ПЕРВОЙ операцией над connection.
        // SQLCipher хранит ключ в hex-форме (raw 256-bit) с префиксом x' …'.
        let mut key_hex = hex::encode(sqlcipher_key);
        let pragma = zeroize::Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", key_hex));
        key_hex.zeroize();
        conn.execute_batch(&pragma)?;
        conn.execute_batch("PRAGMA cipher_compatibility = 4;")?;

        // Проверка корректности ключа. ВАЖНО: `PRAGMA cipher_version` возвращает
        // версию БИБЛИОТЕКИ и НЕ трогает страницы БД — на неверном ключе он НЕ
        // падает. Реальная проверка — чтение sqlite_master: это заставляет
        // SQLCipher расшифровать и HMAC-проверить первую страницу. На новой БД
        // вернёт 0, на существующей с неверным ключом — ошибку "file is not a
        // database".
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        })
        .map_err(|_| {
            VaultError::Crypto("Не удалось открыть SQLCipher-БД (неверный ключ?)".into())
        })?;

        // Стандартные настройки.
        // journal_mode = DELETE (не WAL) — для portable-сценария надёжнее:
        // данные пишутся атомарно в основной файл, без зависимости от
        // *.db-wal и *.db-shm spillover-файлов, которые могли потеряться
        // при некорректном закрытии или копировании папки.
        conn.execute_batch(
            r#"
            PRAGMA busy_timeout = 5000;
            PRAGMA journal_mode = DELETE;
            PRAGMA synchronous = FULL;
            PRAGMA foreign_keys = ON;
            PRAGMA temp_store = MEMORY;
            PRAGMA secure_delete = ON;
            "#,
        )?;
        apply_records_migrations(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            path: path.to_path_buf(),
            confirmed: AtomicU64::new(0),
            sink: Mutex::new(None),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Доступ к соединению. Если за вызов что-то было закоммичено, новая
    /// ревизия подтверждается во внешнем checkpoint'е до возврата: команда
    /// не сообщает об успехе раньше, чем откат этого изменения станет
    /// обнаружимым.
    pub(crate) fn with_conn<R>(&self, f: impl FnOnce(&Connection) -> Result<R>) -> Result<R> {
        let g = self.conn.lock();
        let before = g.total_changes();
        let result = f(&g);
        if g.is_autocommit() && g.total_changes() != before {
            let confirmed = self.confirm_revision(&g);
            let value = result?;
            confirmed?;
            return Ok(value);
        }
        result
    }

    fn confirm_revision(&self, conn: &Connection) -> Result<()> {
        let revision = read_revision(conn)?;
        if revision <= self.confirmed.load(Ordering::SeqCst) {
            return Ok(());
        }
        if let Some(sink) = &*self.sink.lock() {
            // Commit с synchronous = FULL уже на диске: дайджест берётся с
            // того файла, который увидит следующий вход.
            sink(revision, file_digest(&self.path)?)?;
        }
        self.confirmed.store(revision, Ordering::SeqCst);
        Ok(())
    }

    /// Текущая ревизия базы.
    pub fn revision(&self) -> Result<u64> {
        let g = self.conn.lock();
        read_revision(&g)
    }

    /// Ревизия и SHA-256 файла. Пока соединение открыто, файл нельзя
    /// заменить другим (Windows не даёт переименовать открытый файл), поэтому
    /// дайджест относится к той базе, с которой работает сессия.
    pub fn state(&self) -> Result<(u64, [u8; 32])> {
        let g = self.conn.lock();
        Ok((read_revision(&g)?, file_digest(&self.path)?))
    }

    /// Задать ревизию — только для снимка, который станет живой базой
    /// (restore): новая ревизия обязана быть выше подтверждённой.
    pub fn set_revision(&self, revision: u64) -> Result<()> {
        let g = self.conn.lock();
        g.execute(
            "UPDATE db_state SET revision = ?1 WHERE id = 1",
            [revision as i64],
        )?;
        Ok(())
    }

    /// Подключить подтверждение ревизий. `confirmed` — уже подтверждённая.
    pub(crate) fn attach_revision_sink(&self, confirmed: u64, sink: RevisionSink) {
        self.confirmed.store(confirmed, Ordering::SeqCst);
        *self.sink.lock() = Some(sink);
    }

    /// Take a transaction-consistent SQLCipher online backup.  The destination
    /// is opened with the same key before SQLite copies pages, so the produced
    /// file remains encrypted and can be shipped in a backup bundle.
    pub fn backup_to(&self, destination: &Path, key: &[u8; 32]) -> Result<()> {
        self.with_conn(|source| {
            let mut destination_conn = Connection::open(destination)?;
            let mut key_hex = hex::encode(key);
            let pragma = zeroize::Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", key_hex));
            key_hex.zeroize();
            destination_conn.execute_batch(&pragma)?;
            destination_conn.execute_batch("PRAGMA cipher_compatibility = 4;")?;
            {
                let backup = rusqlite::backup::Backup::new(source, &mut destination_conn)?;
                backup.run_to_completion(256, std::time::Duration::from_millis(5), None)?;
            }
            destination_conn.execute_batch("PRAGMA synchronous = FULL;")?;
            Ok(())
        })
    }
}

/// Схема БД записей. Версия одна: продукт не выпущен, миграций нет.
const RECORDS_SCHEMA_VERSION: i32 = 1;

fn apply_records_migrations(conn: &Connection) -> Result<()> {
    let current: i32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if current >= RECORDS_SCHEMA_VERSION {
        return Ok(());
    }

    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result: Result<()> = (|| {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS records (
                id TEXT PRIMARY KEY,
                -- Идентификатор запроса, создавшего запись: повтор того же
                -- запроса после потерянного ответа не создаёт дубликат.
                request_id TEXT UNIQUE,
                name TEXT NOT NULL,
                project TEXT,
                icon TEXT,
                color TEXT,
                category TEXT CHECK (category IN ('personal','work')) DEFAULT 'personal',
                sort_order INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS fields (
                id TEXT PRIMARY KEY,
                record_id TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
                field_type TEXT NOT NULL CHECK (field_type IN ('secret','api','key','id','comment','custom')),
                label TEXT NOT NULL,
                value_blob BLOB NOT NULL,
                is_secret INTEGER NOT NULL DEFAULT 1,
                sort_order INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS record_password_history (
                id TEXT PRIMARY KEY,
                record_id TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
                field_id TEXT NOT NULL,
                field_label TEXT NOT NULL,
                encrypted_value BLOB NOT NULL,
                created_at TEXT NOT NULL
            );

            -- Выдачи генератора. Живут отдельно от записей: это черновик,
            -- а не именованный секрет, и удаляются по возрасту.
            CREATE TABLE IF NOT EXISTS generated_secrets (
                id TEXT PRIMARY KEY,
                -- Без CHECK на список значений: набор типов расширяется, а
                -- ограничение в схеме превращало бы каждый новый тип в
                -- несовместимое изменение БД. Значение проверяет GeneratedKind
                -- при записи и при чтении, и делает это строже.
                kind TEXT NOT NULL,
                length INTEGER NOT NULL,
                value_blob BLOB NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_generated_created ON generated_secrets(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_records_name ON records(name COLLATE NOCASE);
            CREATE INDEX IF NOT EXISTS idx_records_project ON records(project COLLATE NOCASE);
            CREATE INDEX IF NOT EXISTS idx_records_sort ON records(sort_order);
            CREATE INDEX IF NOT EXISTS idx_fields_record ON fields(record_id, sort_order);
            CREATE INDEX IF NOT EXISTS idx_history_record ON record_password_history(record_id, created_at DESC);

            -- Ревизия базы: растёт с каждым изменением данных (см. RecordsDb).
            CREATE TABLE IF NOT EXISTS db_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                revision INTEGER NOT NULL CHECK (revision >= 0)
            );
            INSERT OR IGNORE INTO db_state (id, revision) VALUES (1, 0);
            "#,
        )?;
        for table in [
            "records",
            "fields",
            "record_password_history",
            "generated_secrets",
        ] {
            for event in ["INSERT", "UPDATE", "DELETE"] {
                conn.execute_batch(&format!(
                    "CREATE TRIGGER IF NOT EXISTS revision_{table}_{event} \
                     AFTER {event} ON {table} \
                     BEGIN UPDATE db_state SET revision = revision + 1 WHERE id = 1; END;",
                    event = event.to_lowercase(),
                ))?;
            }
        }
        conn.execute_batch(&format!("PRAGMA user_version = {RECORDS_SCHEMA_VERSION}"))?;
        Ok(())
    })();

    match result {
        Ok(()) => {
            if let Err(error) = crate::failpoint::hit("records.migrate") {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(error);
            }
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

fn read_revision(conn: &Connection) -> Result<u64> {
    let revision: i64 = conn.query_row("SELECT revision FROM db_state WHERE id = 1", [], |r| {
        r.get(0)
    })?;
    u64::try_from(revision).map_err(|_| VaultError::MetaTampered)
}

/// Проверить, что данный SQLCipher-ключ реально открывает
/// СУЩЕСТВУЮЩУЮ records-БД (расшифровка + HMAC первой страницы). Read-only,
/// без миграций и записи. Используется в recovery ДО деструктивных операций,
/// чтобы неверные Shamir-доли (например от другого экземпляра хранилища) не
/// «окирпичили» базу молча. Возвращает false на любой ошибке.
pub fn records_key_opens(path: &Path, sqlcipher_key: &[u8; 32]) -> bool {
    if !path.exists() {
        return false;
    }
    let conn = match Connection::open(path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let mut key_hex = hex::encode(sqlcipher_key);
    let pragma = zeroize::Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", key_hex));
    key_hex.zeroize();
    let applied = conn.execute_batch(&pragma).is_ok();
    if !applied {
        return false;
    }
    if conn
        .execute_batch("PRAGMA cipher_compatibility = 4;")
        .is_err()
    {
        return false;
    }
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    })
    .is_ok()
}

/// HKDF-derive SQLCipher-ключа из master_key. Стабильная функция —
/// одинаковый master даёт одинаковый sqlcipher_key.
pub fn derive_sqlcipher_key(master_key: &[u8; 32]) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    use crate::crypto::kdf::hkdf_derive;
    let derived = hkdf_derive(
        master_key,
        b"vaultisor:sqlcipher-salt:v1",
        b"vaultisor:sqlcipher-records:v1",
        32,
    )?;
    let mut out = zeroize::Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&derived);
    Ok(out)
}

/// HKDF-derive SQLCipher-ключа для базы паролей сайтов.
pub fn derive_web_sqlcipher_key(master_key: &[u8; 32]) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    use crate::crypto::kdf::hkdf_derive;
    let derived = hkdf_derive(
        master_key,
        b"vaultisor:sqlcipher-salt:v1",
        b"vaultisor:sqlcipher-web:v1",
        32,
    )?;
    let mut out = zeroize::Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&derived);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_validation_rejects_wrong_key_and_corrupted_data_page() {
        use std::io::{Read, Seek, SeekFrom, Write};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snapshot.db");
        let key = [0x41; 32];
        let db = RecordsDb::open(&path, &key).unwrap();
        db.with_conn(|c| {
            c.execute_batch("CREATE TABLE snapshot_probe (value BLOB); INSERT INTO snapshot_probe VALUES (zeroblob(20000));")?;
            Ok(())
        }).unwrap();
        drop(db);
        RecordsDb::verify_snapshot(&path, &key).unwrap();
        assert!(RecordsDb::verify_snapshot(&path, &[0x42; 32]).is_err());
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::End(-100)).unwrap();
        let mut byte = [0];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0x80;
        file.seek(SeekFrom::End(-100)).unwrap();
        file.write_all(&byte).unwrap();
        drop(file);
        assert!(RecordsDb::verify_snapshot(&path, &key).is_err());
    }

    // SQLCipher-открытие ДОЛЖНО отвергать неверный ключ.
    // Раньше «проверка ключа» была фиктивной (PRAGMA cipher_version не падал);
    // теперь пробник читает sqlite_master. Плюс проверяем records_key_opens,
    // на котором держится проверка ключа при восстановлении.
    #[test]
    fn wrong_sqlcipher_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.records.db");
        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];

        // Создаём БД ключом A и закрываем.
        {
            let db = RecordsDb::open(&path, &key_a).unwrap();
            drop(db);
        }

        // Неверный ключ B — open обязан упасть.
        assert!(
            RecordsDb::open(&path, &key_b).is_err(),
            "неверный ключ не должен открывать БД"
        );
        // Верный ключ A — открывается.
        assert!(RecordsDb::open(&path, &key_a).is_ok());

        // records_key_opens согласован с open (на нём держится восстановление).
        assert!(!records_key_opens(&path, &key_b));
        assert!(records_key_opens(&path, &key_a));
    }
}
