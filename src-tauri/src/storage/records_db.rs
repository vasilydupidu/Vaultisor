// RecordsDb — SQLCipher-зашифрованная база с записями и полями.
//
// Использует SQLCipher (форк SQLite + AES-256-CBC + HMAC-SHA512 на каждую
// страницу). Ключ деривируется из master_key через HKDF-SHA256:
//
//     sqlcipher_key = HKDF(master_key, "vaultisor:sqlcipher-records:v1", 32)
//
// Это означает: кто имеет master_key, тот имеет доступ к records.db.
// Master_key получается одним из путей:
//   - cascade unlock через PIN (DPAPI + Argon2id);
//   - cascade unlock через Hello+TPM;
//   - Shamir-восстановление (любые 2 из 3 долей).
//
// На чужой машине: cascade fail (DPAPI) → frontend открывает Recovery →
// Shamir B+C → master_key → derive sqlcipher_key → open records.db. Записи
// читаются без потерь.
//
// Защита: даже на той же машине файл records.db без master_key — это AES-CBC
// шифротекст. Атакующий, имеющий только vault.records.db, не сможет
// прочитать ни имена записей, ни их содержимое.

use std::path::{Path, PathBuf};

use parking_lot::Mutex;
use rusqlite::Connection;
use zeroize::Zeroize;

use crate::error::{Result, VaultError};

pub struct RecordsDb {
    conn: Mutex<Connection>,
    path: PathBuf,
}

impl RecordsDb {
    /// Открыть SQLCipher-БД. Если файл новый — будет создан и зашифрован
    /// переданным ключом. Если существующий — ключ должен совпадать с тем,
    /// которым БД была создана/перешифрована, иначе любой запрос упадёт
    /// с "file is not a database".
    pub fn open(path: &Path, sqlcipher_key: &[u8; 32]) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        // КРИТИЧНО: PRAGMA key должна быть ПЕРВОЙ операцией над connection.
        // SQLCipher хранит ключ в hex-форме (raw 256-bit) с префиксом x' …'.
        let mut key_hex = hex::encode(sqlcipher_key);
        let pragma = format!("PRAGMA key = \"x'{}'\";", key_hex);
        key_hex.zeroize();
        conn.execute_batch(&pragma)?;
        // CRIT-02: pragma string contained raw hex key — drop it promptly.
        drop(pragma);
        conn.execute_batch("PRAGMA cipher_compatibility = 4;")?;

        // Проверка корректности ключа. ВАЖНО: `PRAGMA cipher_version` возвращает
        // версию БИБЛИОТЕКИ и НЕ трогает страницы БД — на неверном ключе он НЕ
        // падает. Реальная проверка — чтение sqlite_master: это заставляет
        // SQLCipher расшифровать и HMAC-проверить первую страницу. На новой БД
        // вернёт 0, на существующей с неверным ключом — ошибку "file is not a
        // database".
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
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
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn with_conn<R>(&self, f: impl FnOnce(&Connection) -> Result<R>) -> Result<R> {
        let g = self.conn.lock();
        f(&*g)
    }
}

/// Миграция records.db. Версионирование локальное (отдельно от meta.db).
fn apply_records_migrations(conn: &Connection) -> Result<()> {
    let mut current: i32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if current < 1 {
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let res: Result<()> = (|| {
            conn.execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS records (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    project TEXT,
                    icon TEXT,
                    color TEXT,
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

                CREATE INDEX IF NOT EXISTS idx_records_name ON records(name COLLATE NOCASE);
                CREATE INDEX IF NOT EXISTS idx_records_project ON records(project COLLATE NOCASE);
                CREATE INDEX IF NOT EXISTS idx_fields_record ON fields(record_id, sort_order);
                "#,
            )?;
            Ok(())
        })();
        match res {
            Ok(()) => {
                conn.execute_batch("PRAGMA user_version = 1")?;
                conn.execute_batch("COMMIT")?;
                current = 1;
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        }
    }

    if current < 2 {
        let has_category = {
            let mut stmt = conn.prepare("PRAGMA table_info(records)")?;
            let mut rows = stmt.query([])?;
            let mut found = false;
            while let Some(row) = rows.next()? {
                let name: String = row.get(1)?;
                if name == "category" {
                    found = true;
                    break;
                }
            }
            found
        };

        if !has_category {
            conn.execute_batch("BEGIN IMMEDIATE")?;
            let res: Result<()> = (|| {
                conn.execute_batch(
                    "ALTER TABLE records ADD COLUMN category TEXT CHECK (category IN ('personal','work')) DEFAULT 'personal';"
                )?;
                Ok(())
            })();
            match res {
                Ok(()) => {
                    conn.execute_batch("PRAGMA user_version = 2")?;
                    conn.execute_batch("COMMIT")?;
                }
                Err(e) => {
                    let _ = conn.execute_batch("ROLLBACK");
                    return Err(e);
                }
            }
        } else {
            conn.execute_batch("PRAGMA user_version = 2")?;
        }
    }

    // R-03: колонка пользовательского порядка. Гейтим по НАЛИЧИЮ КОЛОНКИ, а не по
    // user_version — иначе легаси-БД с user_version>=3 (интерим крипто-маркер,
    // см. N-02) пропустили бы этот аддитивный шаг. user_version здесь НЕ трогаем.
    if !column_exists(conn, "records", "sort_order")? {
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let res: Result<()> = (|| {
            conn.execute_batch(
                "ALTER TABLE records ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0;\n\
                 CREATE INDEX IF NOT EXISTS idx_records_sort ON records(sort_order);",
            )?;
            Ok(())
        })();
        match res {
            Ok(()) => {
                conn.execute_batch("COMMIT")?;
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        }
    }

    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS record_password_history (
            id TEXT PRIMARY KEY,
            record_id TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
            field_id TEXT NOT NULL,
            field_label TEXT NOT NULL,
            encrypted_value BLOB NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_history_record ON record_password_history(record_id, created_at DESC);
        "#
    )?;
    Ok(())
}

/// Есть ли колонка `col` в таблице `table`? `table` — только внутренние литералы
/// (не пользовательский ввод), поэтому интерполяция в PRAGMA безопасна.
fn column_exists(conn: &Connection, table: &str, col: &str) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == col {
            return Ok(true);
        }
    }
    Ok(false)
}

/// AUDIT H5: проверить, что данный SQLCipher-ключ реально открывает
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
    let pragma = format!("PRAGMA key = \"x'{}'\";", key_hex);
    key_hex.zeroize();
    let applied = conn.execute_batch(&pragma).is_ok();
    drop(pragma);
    if !applied {
        return false;
    }
    if conn.execute_batch("PRAGMA cipher_compatibility = 4;").is_err() {
        return false;
    }
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
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

    // AUDIT (test-coverage): SQLCipher-открытие ДОЛЖНО отвергать неверный ключ.
    // Раньше «проверка ключа» была фиктивной (PRAGMA cipher_version не падал);
    // теперь пробник читает sqlite_master. Плюс проверяем records_key_opens,
    // на котором держится верификация восстановления (H5).
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

        // records_key_opens согласован с open (используется в recovery H5).
        assert!(!records_key_opens(&path, &key_b));
        assert!(records_key_opens(&path, &key_a));
    }
}
