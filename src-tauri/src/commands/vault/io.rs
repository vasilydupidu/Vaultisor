use serde::Deserialize;
use tauri::State;

use crate::error::{Result, VaultError};
use crate::state::{AppState, SessionState};
use crate::storage::meta_db::MetaDb;
use crate::storage::records_db::{derive_sqlcipher_key, RecordsDb};

use crate::commands::file_grants::{session_stamp, FileOperation};
use crate::storage::create_staging::CreateStaging;
use crate::storage::osjournal::{OsJournal, Resource};

/// Экспорт хранилища: копирует ОБА файла (meta + records) в .vault-bundle.
/// Формат бандла: tar-архив с двумя файлами внутри (или просто два рядом
/// расположенных файла с расширением .meta и .records). Для простоты —
/// один tar-файл, без сжатия.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportInput {
    pub capability: String,
    pub password: Option<String>,
}

/// AUDIT 3.1.1: команда выполняет Argon2id (512 МиБ) и потоковую работу с
/// файлами хранилища. Синхронная Tauri-команда делала бы это в главном потоке
/// и подвешивала интерфейс на несколько секунд.
#[tauri::command]
pub async fn vault_export(input: ExportInput, state: State<'_, AppState>) -> Result<()> {
    let state = state.inner().clone();
    crate::blocking::run(move || vault_export_blocking(input, &state)).await
}

pub(crate) fn vault_export_blocking(input: ExportInput, state: &AppState) -> Result<()> {
    // HIGH-RES-01: требуем разблокированную сессию.
    // Без проверки злонамеренный JS мог экспортировать БД без ввода PIN —
    // и хотя файл бесполезен без master_key (DPAPI-защита), при компрометации
    // Shamir-долей атакующий получит доступ к содержимому.
    // AUDIT M5: сначала авто-блокировка по простою.
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    // Разрешение изымается до полномочия на файл: без PIN выбранный файл
    // остаётся за пользователем и годится для повтора после подтверждения.
    crate::commands::security::consume(
        state,
        crate::commands::security::SecurityAction::ExportVault,
    )?;
    let session = state.session.lock();
    if !session.is_unlocked() {
        return Err(VaultError::Locked);
    }
    let initial = session_stamp(&session);
    let target =
        state
            .file_grants
            .lock()
            .consume(&input.capability, FileOperation::Export, initial)?;
    drop(session);
    let meta_src = state.meta_path();
    let records_src = state.records_path();
    let web_src = state.web_path();
    if !meta_src.exists() || !records_src.exists() || !web_src.exists() {
        return Err(VaultError::NotInitialized);
    }
    // VULN-05 / VULN-11 FIX: санитизируем meta.db перед экспортом (обнуляем pin_hash, удаляем recovery_local).
    let (meta_bytes, records_bytes, web_bytes) =
        crate::commands::backup::snapshot_bundle_parts(state)?;
    let mut out =
        Vec::with_capacity(12 + meta_bytes.len() + records_bytes.len() + web_bytes.len() + 12);
    out.extend_from_slice(b"VLT2");
    out.extend_from_slice(&(meta_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&meta_bytes);
    out.extend_from_slice(&(records_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&records_bytes);
    out.extend_from_slice(&(web_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&web_bytes);

    let final_bytes = if let Some(pwd) = input.password.as_deref().filter(|p| !p.trim().is_empty())
    {
        seal_password_bundle(&out, pwd, crate::crypto::kdf::Argon2Params::default())?
    } else {
        out
    };

    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    let session = state.session.lock();
    if session_stamp(&session) != initial {
        return Err(VaultError::Locked);
    }
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)?;
    file.write_all(&final_bytes)?;
    file.sync_all()?;
    log::info!(
        "vault_export: succeeded ({} + {} + {} bytes)",
        meta_bytes.len(),
        records_bytes.len(),
        web_bytes.len()
    );
    Ok(())
}

/// Импорт ранее экспортированной БД. Доступен только если локальной БД
/// ещё нет (т.е. на чистой инсталляции после онбординга или до него).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportInput {
    pub capability: String,
    pub password: Option<String>,
}

/// AUDIT 3.1.1: команда выполняет Argon2id (512 МиБ) и потоковую работу с
/// файлами хранилища. Синхронная Tauri-команда делала бы это в главном потоке
/// и подвешивала интерфейс на несколько секунд.
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
    let (meta, records, web) = parse_bundle(&bundle, input.password.as_deref())?;
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
    /// Integrity-ключ разворачивается: вход по PIN (если цел TPM-ключ).
    SameDevice,
    /// Другой компьютер или учётная запись Windows: только по долям B и C.
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
        match integrity_key {
            Ok(integrity_key) => {
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
            Err(_) => {
                db.mark_unsealed_import(journal.op_id())?;
                Bootstrap::RecoveryRequired
            }
        }
    };
    staging.commit(journal.op_id())?;
    Ok(bootstrap)
}

/// Заголовок VLT4: магия, параметры Argon2id и соль.
///
/// Параметры KDF лежат в самом файле: иначе изменение констант сборки сделало
/// бы ранее созданные защищённые паролем копии нечитаемыми.
const BUNDLE_SALT_LEN: usize = 16;
const VLT4_HEADER_LEN: usize = 4 + 4 * 3 + BUNDLE_SALT_LEN;
const BUNDLE_AAD: &[u8] = b"vaultisor:backup-v3";

pub(crate) fn seal_password_bundle(
    payload: &[u8],
    password: &str,
    params: crate::crypto::kdf::Argon2Params,
) -> Result<Vec<u8>> {
    let salt: [u8; BUNDLE_SALT_LEN] = crate::crypto::rng::random_array();
    let kek = crate::crypto::kdf::argon2id_derive_key_with(password.as_bytes(), &salt, params)?;
    let blob = crate::crypto::aead::encrypt(&kek, payload, BUNDLE_AAD)?;
    let body = blob.to_bytes();
    let mut out = Vec::with_capacity(VLT4_HEADER_LEN + body.len());
    out.extend_from_slice(b"VLT4");
    out.extend_from_slice(&params.m_cost.to_le_bytes());
    out.extend_from_slice(&params.t_cost.to_le_bytes());
    out.extend_from_slice(&params.p_cost.to_le_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&body);
    Ok(out)
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

/// Разобрать .vault-бандл: VLT4 — защищённый паролем контейнер вокруг VLT2,
/// VLT2 — три базы подряд (meta, records, web).
/// Возвращает (meta, records, web).
pub(crate) type ParsedBundle = (Vec<u8>, Vec<u8>, Vec<u8>);
pub(crate) fn parse_bundle(bundle: &[u8], password: Option<&str>) -> Result<ParsedBundle> {
    fn corrupt() -> VaultError {
        VaultError::BadInput("Повреждённый бандл".into())
    }
    if bundle.len() < 8 {
        return Err(corrupt());
    }

    let payload: std::borrow::Cow<'_, [u8]> = if &bundle[0..4] == b"VLT4" {
        let pwd = password.filter(|p| !p.trim().is_empty()).ok_or_else(|| {
            VaultError::BadInput(
                "Этот файл резервной копии зашифрован паролем. Пожалуйста, укажите пароль.".into(),
            )
        })?;
        if bundle.len() < VLT4_HEADER_LEN + 12 + 16 {
            return Err(VaultError::BadInput(
                "Повреждённый зашифрованный бандл".into(),
            ));
        }
        let read_u32 = |offset: usize| {
            u32::from_le_bytes([
                bundle[offset],
                bundle[offset + 1],
                bundle[offset + 2],
                bundle[offset + 3],
            ])
        };
        let params =
            crate::crypto::kdf::Argon2Params::from_stored(read_u32(4), read_u32(8), read_u32(12))
                .map_err(|_| {
                VaultError::BadInput(
                    "Параметры защиты в заголовке резервной копии недопустимы".into(),
                )
            })?;
        let mut salt = [0u8; BUNDLE_SALT_LEN];
        salt.copy_from_slice(&bundle[16..VLT4_HEADER_LEN]);
        let blob_bytes = &bundle[VLT4_HEADER_LEN..];
        let kek = crate::crypto::kdf::argon2id_derive_key_with(pwd.as_bytes(), &salt, params)?;
        let blob = crate::crypto::aead::EncryptedBlob::from_bytes(blob_bytes)?;
        let pt = crate::crypto::aead::decrypt(&kek, &blob, BUNDLE_AAD)
            .map_err(|_| VaultError::BadInput("Неверный пароль к резервной копии".into()))?;
        std::borrow::Cow::Owned(pt)
    } else {
        std::borrow::Cow::Borrowed(bundle)
    };

    let b = payload.as_ref();
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
/// AUDIT 3.1.1: команда выполняет Argon2id (512 МиБ) и потоковую работу с
/// файлами хранилища. Синхронная Tauri-команда делала бы это в главном потоке
/// и подвешивала интерфейс на несколько секунд.
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
    let (_, records, web) = parse_bundle(&bundle, input.password.as_deref())?;

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
        assert!(serde_json::from_value::<ExportInput>(
            serde_json::json!({"target_path":"C:\\victim", "password":null})
        )
        .is_err());
        assert!(serde_json::from_value::<ImportInput>(
            serde_json::json!({"source_path":"C:\\victim", "password":null})
        )
        .is_err());
        assert!(serde_json::from_value::<ImportInput>(
            serde_json::json!({"capability":"token", "source_path":"C:\\victim", "password":null})
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
        let (m, r, w) = parse_bundle(&bundle, None).unwrap();
        assert_eq!(m, b"META-BYTES");
        assert_eq!(r, b"RECORDS-BYTES");
        assert_eq!(w, b"WEB-BYTES");
    }

    #[test]
    fn parse_bundle_rejects_bad_magic() {
        let mut b = build_vlt2(b"M", b"R", b"W");
        b[0] = b'X';
        assert!(parse_bundle(&b, None).is_err());
    }

    #[test]
    fn parse_bundle_rejects_truncated() {
        let bundle = build_vlt2(b"META", b"RECORDS", b"WEB");
        let truncated = &bundle[..bundle.len() - 5];
        assert!(parse_bundle(truncated, None).is_err());
    }

    #[test]
    fn parse_bundle_rejects_oversized_length() {
        // Заявленная meta_len = u32::MAX выходит за буфер → должно отвергнуться,
        // а не паниковать на срезе (AUDIT: bounds перед slicing).
        let mut b = build_vlt2(b"META", b"RECORDS", b"WEB");
        b[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_bundle(&b, None).is_err());
    }

    #[test]
    fn parse_bundle_rejects_too_short() {
        assert!(parse_bundle(b"VLT", None).is_err());
        assert!(parse_bundle(&[], None).is_err());
    }

    /// Дешёвые параметры Argon2id для тестов: проверяется формат, не стоимость.
    fn fast_params() -> crate::crypto::kdf::Argon2Params {
        crate::crypto::kdf::Argon2Params {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn parse_bundle_vlt4_password_roundtrip() {
        let inner = build_vlt2(b"META", b"RECORDS", b"WEB");
        let vlt4 = seal_password_bundle(&inner, "my-backup-pass", fast_params()).unwrap();
        assert_eq!(&vlt4[0..4], b"VLT4");

        // Correct password
        let (m, r, w) = parse_bundle(&vlt4, Some("my-backup-pass")).unwrap();
        assert_eq!(m, b"META");
        assert_eq!(r, b"RECORDS");
        assert_eq!(w, b"WEB");

        // Wrong password
        assert!(parse_bundle(&vlt4, Some("wrong-pass")).is_err());
        // Missing password
        assert!(parse_bundle(&vlt4, None).is_err());
    }

    /// Заголовок с экстремальными параметрами Argon2 отвергается до деривации:
    /// тест завершается мгновенно, а не через годы вычислений.
    #[test]
    fn vlt4_header_with_extreme_kdf_params_is_rejected_before_derivation() {
        let inner = build_vlt2(b"M", b"R", b"W");
        let sealed = seal_password_bundle(&inner, "pass", fast_params()).unwrap();
        for (offset, value) in [(4, u32::MAX), (8, u32::MAX), (12, u32::MAX), (8, 0)] {
            let mut forged = sealed.clone();
            forged[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            let started = std::time::Instant::now();
            assert!(parse_bundle(&forged, Some("pass")).is_err());
            assert!(started.elapsed() < std::time::Duration::from_secs(2));
        }
    }

    /// AUDIT 3.1.1: параметры KDF теперь лежат в самом файле, поэтому копия,
    /// созданная на других параметрах, продолжает открываться и после смены
    /// констант сборки.
    #[test]
    fn vlt4_carries_its_own_kdf_parameters() {
        let inner = build_vlt2(b"M", b"R", b"W");
        let unusual = crate::crypto::kdf::Argon2Params {
            m_cost: 16 * 1024,
            t_cost: 2,
            p_cost: 1,
        };
        let sealed = seal_password_bundle(&inner, "pass", unusual).unwrap();
        assert_eq!(
            u32::from_le_bytes([sealed[4], sealed[5], sealed[6], sealed[7]]),
            unusual.m_cost
        );
        let (m, _, _) = parse_bundle(&sealed, Some("pass")).unwrap();
        assert_eq!(m, b"M");
    }
}
