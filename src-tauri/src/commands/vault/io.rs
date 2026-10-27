use serde::Deserialize;
use tauri::State;

use crate::error::{Result, VaultError};
use crate::state::{AppState, SessionState};
use crate::storage::meta_db::MetaDb;
use crate::storage::records_db::{derive_sqlcipher_key, RecordsDb};

use crate::commands::file_grants::{session_stamp, FileOperation};
use crate::storage::create_staging::CreateStaging;
use crate::storage::osjournal::{OsJournal, Resource};

/// Импорт резервной копии на чистую установку: доступен, только пока
/// локального хранилища нет (онбординг).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportInput {
    pub capability: String,
}

/// Команда читает и записывает файлы хранилища целиком. Синхронная
/// Tauri-команда делала бы это в главном потоке и подвешивала интерфейс.
#[tauri::command]
pub async fn vault_import(input: ImportInput, state: State<'_, AppState>) -> Result<()> {
    let state = state.inner().clone();
    crate::blocking::run(move || vault_import_blocking(input, &state)).await
}

pub(crate) fn vault_import_blocking(input: ImportInput, state: &AppState) -> Result<()> {
    let present = [state.meta_path(), state.records_path(), state.web_path()]
        .iter()
        .any(|path| path.exists());
    if present {
        return Err(VaultError::BadInput(
            "Хранилище уже существует. Импорт возможен только на чистую установку.".into(),
        ));
    }
    let source = {
        let session = state.session.lock();
        state.file_grants.lock().consume(
            &input.capability,
            FileOperation::Import,
            session_stamp(&session),
        )?
    };
    let bundle = std::fs::read(source)?;
    let (meta, records, web) = parse_bundle(&bundle)?;
    std::fs::create_dir_all(&state.data_dir)?;

    let mut journal = OsJournal::begin(&state.data_dir, &state.os)?;
    let result = stage_import(state, &mut journal, [&meta, &records, &web]);
    if result.is_err() {
        // Незавершённая сборка откатывается сейчас или при следующем старте.
        if let Err(cleanup) = crate::storage::create_staging::recover(&state.data_dir) {
            log::warn!("vault_import: staging cleanup deferred: {cleanup}");
        }
    }
    journal.finish(&state.os, &state.data_dir);
    match &result {
        Ok(Bootstrap::SameDevice) => log::info!("vault_import: published on the source device"),
        Ok(Bootstrap::RecoveryRequired) => {
            log::warn!("vault_import: published; this device can open it only via recovery")
        }
        Err(error) => log::error!("vault_import FAILED: {error}"),
    }
    result.map(|_| ())
}

/// Как импортированное хранилище будет открываться на этом устройстве.
enum Bootstrap {
    /// Integrity-ключ разворачивается, и копия не ослабляет защиту: вход по PIN
    /// (если цел TPM-ключ).
    SameDevice,
    /// Другой компьютер или учётная запись Windows, либо копия ослабила бы
    /// защиту этого устройства: вход только по долям B и C.
    RecoveryRequired,
}

/// Собрать импорт в каталоге сборки и опубликовать одним переносом.
///
/// Бандл — недоверенный файл. Если его integrity-ключ разворачивается на
/// этом устройстве, подпись обязана сойтись, а метаданные перепечатываются
/// поверх checkpoint'а этого ключа так, что импорт не ослабляет ни эпоху, ни
/// задержки PIN (`MetaDb::reseal_import`). Иначе хранилище публикуется как
/// есть: без integrity-ключа ни вход по PIN, ни проверка подписи невозможны,
/// и открыть его можно только восстановлением по долям, которое заново
/// создаёт все ключи устройства.
fn stage_import(
    state: &AppState,
    journal: &mut OsJournal,
    databases: [&[u8]; 3],
) -> Result<Bootstrap> {
    let staging = CreateStaging::begin(&state.data_dir)?;
    let [meta, records, web] = databases;
    crate::storage::fsio::write(&staging.meta_path(), meta)?;
    crate::storage::fsio::write(&staging.records_path(), records)?;
    crate::storage::fsio::write(&staging.web_path(), web)?;
    // Сначала структурная проверка без записи: MetaDb::open применил бы
    // миграции к недоверенному файлу.
    validate_untrusted_sqlite(&staging.meta_path())?;

    let bootstrap = {
        let db = MetaDb::open_staged(&staging.meta_path(), &state.data_dir)?;
        let row = db.vault_load()?.ok_or_else(|| {
            VaultError::BadInput("Бандл не содержит инициализированного хранилища".into())
        })?;
        let integrity_key = db
            .get_integrity_key_dpapi()?
            .ok_or(VaultError::MetaTampered)
            .and_then(|blob| {
                crate::commands::vault::unwrap_integrity_key(&blob, &row.dpapi_entropy)
            });
        // Копия запечатывается на этом устройстве, только если не ослабляет
        // защиту относительно checkpoint'а (Hello, подтверждение копирования,
        // обёртка под текущим PIN). Иначе — как на чужом устройстве: вход лишь
        // по частям B и C.
        let sealable = match &integrity_key {
            Ok(key) => db.import_keeps_policy(key)?,
            Err(_) => false,
        };
        match integrity_key {
            Ok(integrity_key) if sealable => {
                let id = crate::storage::meta_db::crud::checkpoint_id(&integrity_key);
                // Существующий checkpoint этого ключа — монотонное состояние
                // прежнего хранилища: при неудаче импорта его удалять нельзя.
                if !crate::storage::machine_checkpoint::exists(&state.data_dir, &id)? {
                    journal.will_create(Resource::Checkpoint { id })?;
                }
                let digest = |bytes: &[u8]| -> [u8; 32] {
                    use sha2::{Digest, Sha256};
                    Sha256::digest(bytes).into()
                };
                db.reseal_import(
                    &integrity_key,
                    journal.op_id(),
                    (digest(records), digest(web)),
                )?;
                Bootstrap::SameDevice
            }
            _ => {
                db.mark_unsealed_import(journal.op_id())?;
                Bootstrap::RecoveryRequired
            }
        }
    };
    staging.commit(journal.op_id())?;
    Ok(bootstrap)
}

/// Структурная проверка недоверенного файла SQLite БЕЗ применения миграций.
///
/// Открываем строго read-only, прогоняем `quick_check` и убеждаемся, что это
/// действительно метаданные Vaultisor. Это не подтверждает подлинность (её
/// проверит MAC при разблокировке), но не даёт скормить парсеру SQLite
/// произвольный файл в режиме записи.
fn validate_untrusted_sqlite(path: &std::path::Path) -> Result<()> {
    use rusqlite::{Connection, OpenFlags};

    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|_| VaultError::BadInput("Бандл не является базой Vaultisor".into()))?;
    let integrity: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|_| VaultError::BadInput("Повреждённая база в бандле".into()))?;
    if integrity != "ok" {
        return Err(VaultError::BadInput("Повреждённая база в бандле".into()));
    }
    let has_meta: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'vault_meta'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| VaultError::BadInput("Бандл не является базой Vaultisor".into()))?;
    if has_meta == 0 {
        return Err(VaultError::BadInput(
            "Бандл не содержит метаданных Vaultisor".into(),
        ));
    }
    Ok(())
}

/// Разобрать .vault-бандл VLT2: три базы подряд (meta, records, web).
/// Возвращает (meta, records, web).
pub(crate) type ParsedBundle = (Vec<u8>, Vec<u8>, Vec<u8>);
pub(crate) fn parse_bundle(b: &[u8]) -> Result<ParsedBundle> {
    fn corrupt() -> VaultError {
        VaultError::BadInput("Повреждённый бандл".into())
    }
    if b.len() < 8 {
        return Err(corrupt());
    }

    fn read_chunk(b: &[u8], off: usize) -> Result<(Vec<u8>, usize)> {
        let len_end = off.checked_add(4).ok_or_else(corrupt)?;
        if b.len() < len_end {
            return Err(corrupt());
        }
        let len = u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]) as usize;
        let data_end = len_end.checked_add(len).ok_or_else(corrupt)?;
        if b.len() < data_end {
            return Err(corrupt());
        }
        Ok((b[len_end..data_end].to_vec(), data_end))
    }

    if &b[0..4] != b"VLT2" {
        return Err(VaultError::BadInput(
            "Файл не является бандлом Vaultisor".into(),
        ));
    }
    let (meta, off) = read_chunk(b, 4)?;
    let (records, off) = read_chunk(b, off)?;
    let (web, off) = read_chunk(b, off)?;
    if off != b.len() {
        return Err(corrupt());
    }
    Ok((meta, records, web))
}

/// Восстановить пользовательские данные из резервной копии в открытое
/// хранилище (см. `storage::restore`). Метаданные безопасности не меняются.
/// Команда читает и записывает файлы хранилища целиком, поэтому выполняется
/// вне главного потока.
#[tauri::command]
pub async fn vault_restore(input: ImportInput, state: State<'_, AppState>) -> Result<()> {
    let state = state.inner().clone();
    crate::blocking::run(move || vault_restore_blocking(input, &state)).await
}

pub(crate) fn vault_restore_blocking(input: ImportInput, state: &AppState) -> Result<()> {
    use crate::storage::restore::RestoreTransaction;

    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    crate::commands::security::consume(
        state,
        crate::commands::security::SecurityAction::RestoreBackup,
    )?;
    let (master, integrity_key, session_started, live) = {
        let session = state.session.lock();
        match &*session {
            SessionState::Unlocked {
                master_key,
                integrity_key,
                unlocked_at,
                records_db,
                web_db,
                ..
            } => (
                master_key.clone(),
                integrity_key.clone(),
                *unlocked_at,
                (records_db.revision()?, web_db.revision()?),
            ),
            SessionState::Locked => return Err(VaultError::Locked),
        }
    };
    let source = state.file_grants.lock().consume(
        &input.capability,
        FileOperation::Restore,
        Some(session_started),
    )?;
    let bundle = std::fs::read(source)?;
    // Метаданные копии не используются: факторы входа, восстановление и
    // задержки PIN остаются текущими.
    let (_, records, web) = parse_bundle(&bundle)?;

    let records_key = master.with_decrypted(derive_sqlcipher_key)?;
    let web_key = master.with_decrypted(crate::storage::records_db::derive_web_sqlcipher_key)?;
    let (records_confirmed, web_confirmed) = state.open_meta()?.data_state(&integrity_key)?;

    let tx = RestoreTransaction::prepare(&state.data_dir, [&records, &web])?;
    // Снимок принадлежит этому хранилищу, если его базы открываются ключами
    // текущего мастер-ключа. Затем их ревизии поднимаются выше живых и
    // подтверждённых: восстановленная база — новое состояние, а не откат.
    let staged = (|| -> Result<(u64, u64)> {
        RecordsDb::verify_snapshot(&tx.records_path(), &records_key)?;
        RecordsDb::verify_snapshot(&tx.web_path(), &web_key)?;
        let records_revision = live.0.max(records_confirmed.revision) + 1;
        let web_revision = live.1.max(web_confirmed.revision) + 1;
        RecordsDb::open(&tx.records_path(), &records_key)?.set_revision(records_revision)?;
        RecordsDb::open(&tx.web_path(), &web_key)?.set_revision(web_revision)?;
        Ok((records_revision, web_revision))
    })();
    let (records_revision, web_revision) = match staged {
        Ok(revisions) => revisions,
        Err(error) => {
            RestoreTransaction::recover(&state.data_dir)?;
            return Err(match error {
                VaultError::MetaTampered | VaultError::DbFailure(_) => VaultError::BadInput(
                    "Резервная копия принадлежит другому хранилищу или повреждена".into(),
                ),
                other => other,
            });
        }
    };

    // Сессия закрывается до замены: соединения с живыми базами держат файлы.
    {
        let mut session = state.session.lock();
        match &*session {
            SessionState::Unlocked { unlocked_at, .. } if *unlocked_at == session_started => {}
            _ => {
                drop(session);
                RestoreTransaction::recover(&state.data_dir)?;
                return Err(VaultError::Locked);
            }
        }
        *session = SessionState::Locked;
    }
    state.file_grants.lock().clear();
    state.pending_import_deletions.lock().clear();
    state.pending_recovery_saves.lock().clear();

    if let Err(error) = tx.swap() {
        RestoreTransaction::recover(&state.data_dir)?;
        return Err(error);
    }
    tx.commit()?;
    // После commit: сбой здесь оставит базы на ревизию впереди checkpoint'а,
    // и первый вход его догонит.
    let records_digest = crate::storage::records_db::file_digest(&state.records_path())?;
    let web_digest = crate::storage::records_db::file_digest(&state.web_path())?;
    state.open_meta()?.advance_data_state(
        &integrity_key,
        Some(super::helpers::data_state((
            records_revision,
            records_digest,
        ))),
        Some(super::helpers::data_state((web_revision, web_digest))),
    )?;
    log::warn!("vault_restore: user data restored from backup (security event)");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_authority_is_not_an_ipc_input() {
        assert!(serde_json::from_value::<ImportInput>(
            serde_json::json!({"source_path":"C:\\victim"})
        )
        .is_err());
        assert!(serde_json::from_value::<ImportInput>(
            serde_json::json!({"capability":"token", "source_path":"C:\\victim"})
        )
        .is_err());
    }

    fn build_vlt2(meta: &[u8], records: &[u8], web: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"VLT2");
        b.extend_from_slice(&(meta.len() as u32).to_le_bytes());
        b.extend_from_slice(meta);
        b.extend_from_slice(&(records.len() as u32).to_le_bytes());
        b.extend_from_slice(records);
        b.extend_from_slice(&(web.len() as u32).to_le_bytes());
        b.extend_from_slice(web);
        b
    }

    #[test]
    fn untrusted_file_validation_rejects_non_sqlite_and_foreign_databases() {
        let dir = tempfile::tempdir().unwrap();

        let garbage = dir.path().join("garbage.db");
        std::fs::write(&garbage, b"not a database at all").unwrap();
        assert!(validate_untrusted_sqlite(&garbage).is_err());

        // Валидная SQLite-база, но без метаданных Vaultisor.
        let foreign = dir.path().join("foreign.db");
        {
            let c = rusqlite::Connection::open(&foreign).unwrap();
            c.execute_batch(
                "CREATE TABLE unrelated (x INTEGER); INSERT INTO unrelated VALUES (1);",
            )
            .unwrap();
        }
        assert!(validate_untrusted_sqlite(&foreign).is_err());

        // Настоящая meta-БД проходит проверку.
        let good = dir.path().join("vault.meta.db");
        {
            let db = MetaDb::open(&good).unwrap();
            db.vault_create(b"wrapped", 300, 10, b"dpapi", &[9u8; 32], b"entropy", None)
                .unwrap();
        }
        validate_untrusted_sqlite(&good).unwrap();
    }

    #[test]
    fn parse_bundle_vlt2_roundtrip() {
        let bundle = build_vlt2(b"META-BYTES", b"RECORDS-BYTES", b"WEB-BYTES");
        let (m, r, w) = parse_bundle(&bundle).unwrap();
        assert_eq!(m, b"META-BYTES");
        assert_eq!(r, b"RECORDS-BYTES");
        assert_eq!(w, b"WEB-BYTES");
    }

    #[test]
    fn parse_bundle_rejects_bad_magic() {
        let mut b = build_vlt2(b"M", b"R", b"W");
        b[0] = b'X';
        assert!(parse_bundle(&b).is_err());
    }

    #[test]
    fn parse_bundle_rejects_truncated() {
        let bundle = build_vlt2(b"META", b"RECORDS", b"WEB");
        let truncated = &bundle[..bundle.len() - 5];
        assert!(parse_bundle(truncated).is_err());
    }

    #[test]
    fn parse_bundle_rejects_oversized_length() {
        // Заявленная meta_len = u32::MAX выходит за буфер → должно отвергнуться,
        // а не паниковать на срезе: границы проверяются до среза.
        let mut b = build_vlt2(b"META", b"RECORDS", b"WEB");
        b[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_bundle(&b).is_err());
    }

    #[test]
    fn parse_bundle_rejects_too_short() {
        assert!(parse_bundle(b"VLT").is_err());
        assert!(parse_bundle(&[]).is_err());
    }
}
