// Лёгкая автоматизация резервных копий.
//
// Бэкап = копия ОДНОГО зашифрованного бандла (все три БД, формат VLT2) в
// выбранную пользователем папку. Если папка синхронизируется
// облачным клиентом (Я.Диск/Dropbox/OneDrive) — копия уезжает в облако.
//
// Безопасность: бандл полностью зашифрован и привязан к устройству (TPM+DPAPI);
// восстановление на другом ПК возможно только через Shamir. Поэтому копию
// безопасно держать в стороннем облаке.
//
// Путь назначения является долговременной write-authority. Он хранится в
// backup.json только внутри HMAC envelope, поэтому webview/файловая подмена не
// может перенаправить последующий backup в произвольное место.

use std::path::Path;

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::error::{Result, VaultError};
use crate::state::AppState;
use crate::storage::meta_db::MetaDb;

/// Минимальный ретеншн: храним последние N копий, остальные удаляем.
const KEEP_LAST: usize = 3;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BackupConfig {
    /// Папка назначения (абсолютный путь). None — не настроено.
    pub dir: Option<String>,
    /// "off" | "daily" | "weekly".
    pub frequency: String,
    /// RFC3339-время последнего успешного бэкапа.
    pub last_backup: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupConfigEnvelope {
    version: u32,
    config: BackupConfig,
    mac_hex: String,
}

const BACKUP_CONFIG_DOMAIN: &[u8] = b"vaultisor:backup-config:v1";

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            dir: None,
            frequency: "off".into(),
            last_backup: None,
        }
    }
}

fn config_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("backup.json")
}

fn session_integrity_key(state: &AppState) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    match &*state.session.lock() {
        crate::state::SessionState::Unlocked { integrity_key, .. } => Ok(integrity_key.clone()),
        _ => Err(VaultError::Locked),
    }
}

fn config_mac(key: &[u8; 32], cfg: &BackupConfig) -> Result<[u8; 32]> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let payload = serde_json::to_vec(cfg)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .map_err(|_| VaultError::Internal("backup config HMAC key".into()))?;
    mac.update(BACKUP_CONFIG_DOMAIN);
    mac.update(&payload);
    Ok(mac.finalize().into_bytes().into())
}

/// Прочитать аутентифицированный конфиг по уже извлечённому integrity-ключу.
///
/// Раньше эта функция сама лезла за ключом в
/// `state.session`, а `backup_now`/`backup_set_config` вызывали её, уже держа
/// этот мьютекс. `parking_lot::Mutex` нереентрантный, поэтому команда намертво
/// вешала главный поток Tauri вместе со всем интерфейсом. Теперь функция
/// принимает каталог и ключ и структурно не имеет доступа к сессии.
fn read_config_at(data_dir: &Path, key: &[u8; 32]) -> Result<BackupConfig> {
    let raw = match std::fs::read(config_path(data_dir)) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BackupConfig::default())
        }
        Err(error) => return Err(error.into()),
    };
    let envelope: BackupConfigEnvelope = match serde_json::from_slice(&raw) {
        Ok(envelope) => envelope,
        Err(_) => {
            // Конфиг без аутентифицированного конверта (подложенный или
            // повреждённый) не даёт права на путь: каталог выбирается заново.
            return Ok(BackupConfig::default());
        }
    };
    if envelope.version != 1 {
        return Err(VaultError::CorruptedWrapper);
    }
    let expected = config_mac(key, &envelope.config)?;
    let supplied = hex::decode(&envelope.mac_hex).map_err(|_| VaultError::CorruptedWrapper)?;
    if !bool::from(subtle::ConstantTimeEq::ct_eq(
        expected.as_slice(),
        &supplied,
    )) {
        return Err(VaultError::CorruptedWrapper);
    }
    Ok(envelope.config)
}

/// Удобная обёртка для мест, где мьютекс сессии заведомо не удерживается.
pub(crate) fn read_config(state: &AppState) -> Result<BackupConfig> {
    let key = session_integrity_key(state)?;
    read_config_at(&state.data_dir, &key)
}

fn write_config_at(data_dir: &Path, key: &[u8; 32], cfg: &BackupConfig) -> Result<()> {
    let envelope = BackupConfigEnvelope {
        version: 1,
        config: cfg.clone(),
        mac_hex: hex::encode(config_mac(key, cfg)?),
    };
    let json = serde_json::to_string_pretty(&envelope)
        .map_err(|e| VaultError::System(format!("backup config serialize: {e}")))?;
    // Временный файл с префиксом атомарной записи: след оборванной замены
    // убирается при старте, а не остаётся в каталоге хранилища навсегда.
    crate::storage::fsio::write_atomic(&config_path(data_dir), json.as_bytes())
}

/// Session-bound material captured once, so no config I/O runs while the
/// session mutex is held.
struct BackupSession {
    stamp: std::time::Instant,
    integrity_key: zeroize::Zeroizing<[u8; 32]>,
}

fn capture_session(state: &AppState) -> Result<BackupSession> {
    let session = state.session.lock();
    match &*session {
        crate::state::SessionState::Unlocked {
            integrity_key,
            unlocked_at,
            ..
        } => Ok(BackupSession {
            stamp: *unlocked_at,
            integrity_key: integrity_key.clone(),
        }),
        crate::state::SessionState::Locked => Err(VaultError::Locked),
    }
}

#[tauri::command]
pub fn backup_get_config(state: State<'_, AppState>) -> Result<BackupConfig> {
    if state.check_autolock() || !state.session.lock().is_unlocked() {
        return Err(VaultError::Locked);
    }
    read_config(state.inner())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSetInput {
    pub directory_capability: Option<String>,
    pub frequency: String,
}

#[tauri::command]
pub fn backup_set_config(input: BackupSetInput, state: State<'_, AppState>) -> Result<()> {
    set_backup_config(&state, input)
}

pub(crate) fn set_backup_config(state: &AppState, input: BackupSetInput) -> Result<()> {
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    // Смена каталога решает, куда уходят копии хранилища: это политика
    // безопасности, и она требует свежего подтверждения. Частота — нет.
    if input.directory_capability.is_some() {
        crate::commands::security::consume(
            state,
            crate::commands::security::SecurityAction::ChangeBackupDirectory,
        )?;
    }
    let session = capture_session(state)?;
    let mut cfg = read_config_at(&state.data_dir, &session.integrity_key)?;
    if let Some(token) = input.directory_capability {
        let dir = state.file_grants.lock().consume(
            &token,
            crate::commands::file_grants::FileOperation::BackupDirectory,
            Some(session.stamp),
        )?;
        cfg.dir = Some(dir.to_string_lossy().into_owned());
    }
    cfg.frequency = match input.frequency.as_str() {
        "daily" | "weekly" | "off" => input.frequency,
        _ => "off".into(),
    };
    write_config_at(&state.data_dir, &session.integrity_key, &cfg)
}

#[derive(Debug, Serialize)]
pub struct BackupResult {
    pub path: String,
}

/// Синхронные Tauri-команды выполняются в главном потоке, поэтому
/// сборка бандла (три online-backup SQLite и чтение файлов) подвешивала весь
/// интерфейс. Автобэкап вызывается при входе в хранилище, то есть зависание
/// приходилось ровно на старт. Тяжёлая часть вынесена в blocking-пул.
#[tauri::command]
pub async fn backup_now(request_id: String, state: State<'_, AppState>) -> Result<BackupResult> {
    let state = state.inner().clone();
    crate::blocking::run(move || backup_now_blocking(&state, &request_id)).await
}

/// Создать резервную копию. Начало `request_id` входит в имя файла: повтор
/// того же запроса после потерянного ответа находит уже записанную копию.
pub(crate) fn backup_now_blocking(state: &AppState, request_id: &str) -> Result<BackupResult> {
    let request_id = crate::commands::request::parse(request_id)?;
    // Требуем разблокированную сессию — защита от эксфильтрации
    // фоновым/вредоносным кодом без ведома пользователя.
    // Сначала авто-блокировка по простою.
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    let session = capture_session(state)?;
    let initial = session.stamp;
    let dir = read_config_at(&state.data_dir, &session.integrity_key)?
        .dir
        .ok_or_else(|| VaultError::BadInput("Выберите каталог резервных копий".into()))?;

    let target = validate_dir(&dir)?;
    std::fs::create_dir_all(target)?;
    // Хватает первых 8 hex-символов (32 бита): совпасть они могут только
    // у разных запросов в одной папке, где хранятся единицы копий.
    let suffix = format!("-{}.vault", &request_id[..8]);
    let done = std::fs::read_dir(target)?
        .flatten()
        .map(|e| e.path())
        .find(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("Vaultisor-backup-") && n.ends_with(&suffix))
        });
    if let Some(done) = done {
        // Копия уже записана, но ответ или запись конфига могли пропасть:
        // повтор догоняет `last_backup`, иначе автобэкап считал бы, что
        // копии не было, и делал бы новую при каждом входе.
        let written = std::fs::metadata(&done)
            .and_then(|m| m.modified())
            .map(chrono::DateTime::<chrono::Local>::from)
            .unwrap_or_else(|_| chrono::Local::now());
        record_backup(state, &session, &dir, written)?;
        log::info!("backup_now: request already completed");
        return Ok(BackupResult {
            path: done.to_string_lossy().to_string(),
        });
    }

    let bundle = build_bundle(state)?;
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    // Revalidate the session, then release the mutex immediately: holding it
    // across filesystem writes and config I/O is what previously deadlocked
    // this command against `session_integrity_key`.
    if crate::commands::file_grants::session_stamp(&state.session.lock()) != Some(initial) {
        return Err(VaultError::Locked);
    }

    // Имя с временной меткой (локальное время). Лексикографически = хронологически.
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let full = target.join(format!("Vaultisor-backup-{ts}{suffix}"));
    // Копия появляется под своим именем только целиком: временный файл,
    // fsync, атомарная замена. Иначе сбой оставил бы усечённую копию, которую
    // ретеншн считал бы полноценной и удалял бы ради неё целые. Следы прошлых
    // оборванных записей убираются перед новой.
    crate::storage::fsio::remove_stale_temporaries(target)?;
    crate::storage::fsio::write_atomic(&full, &bundle)?;

    apply_retention(target);

    // Ошибка записи конфига не скрывается: ответ «успешно» при несохранённом
    // `last_backup` заставил бы автобэкап повторяться. Копия уже на диске,
    // и повтор того же запроса найдёт её и допишет конфиг.
    record_backup(state, &session, &dir, chrono::Local::now())?;

    log::info!("backup_now: wrote backup ({} bytes)", bundle.len());
    Ok(BackupResult {
        path: full.to_string_lossy().to_string(),
    })
}

/// Записать в конфиг каталог и время последней копии.
fn record_backup(
    state: &AppState,
    session: &BackupSession,
    dir: &str,
    at: chrono::DateTime<chrono::Local>,
) -> Result<()> {
    let mut cfg = read_config_at(&state.data_dir, &session.integrity_key)?;
    cfg.dir = Some(dir.to_owned());
    cfg.last_backup = Some(at.to_rfc3339());
    write_config_at(&state.data_dir, &session.integrity_key, &cfg)
}

/// Собрать VLT2-бандл из трёх зашифрованных БД (meta + records + web).
/// `meta.db` санитизируется перед включением: обёртки FIDO2 и credential
/// Windows Hello из копии убираются (`sanitize_meta_for_export_with_key`).
pub(crate) fn build_bundle(state: &AppState) -> Result<Vec<u8>> {
    let (meta, records, web) = snapshot_bundle_parts(state)?;
    let mut out = Vec::with_capacity(16 + meta.len() + records.len() + web.len());
    out.extend_from_slice(b"VLT2");
    out.extend_from_slice(&(meta.len() as u32).to_le_bytes());
    out.extend_from_slice(&meta);
    out.extend_from_slice(&(records.len() as u32).to_le_bytes());
    out.extend_from_slice(&records);
    out.extend_from_slice(&(web.len() as u32).to_le_bytes());
    out.extend_from_slice(&web);
    Ok(out)
}

/// Snapshot all live SQLite databases through the online backup API.  A raw
/// filesystem copy can miss pages while a connection has an active journal;
/// this helper gives export and scheduled backup the same transaction-safe
/// snapshot semantics.
pub(crate) fn snapshot_bundle_parts(state: &AppState) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let (master, integrity_key) = {
        let session = state.session.lock();
        match &*session {
            crate::state::SessionState::Unlocked {
                master_key,
                integrity_key,
                ..
            } => (master_key.clone(), integrity_key.clone()),
            crate::state::SessionState::Locked => return Err(VaultError::Locked),
        }
    };
    let records_key = master.with_decrypted(crate::storage::records_db::derive_sqlcipher_key)?;
    let web_key = master.with_decrypted(crate::storage::records_db::derive_web_sqlcipher_key)?;

    let meta_tmp = tempfile::NamedTempFile::new()?;
    let records_tmp = tempfile::NamedTempFile::new()?;
    let web_tmp = tempfile::NamedTempFile::new()?;
    state.open_meta()?.backup_to(meta_tmp.path())?;
    {
        let session = state.session.lock();
        let (records_db, web_db) = match &*session {
            crate::state::SessionState::Unlocked {
                records_db, web_db, ..
            } => (records_db, web_db),
            crate::state::SessionState::Locked => return Err(VaultError::Locked),
        };
        records_db.backup_to(records_tmp.path(), &records_key)?;
        web_db.backup_to(web_tmp.path(), &web_key)?;
    }

    let meta_raw = std::fs::read(meta_tmp.path())?;
    let meta = sanitize_meta_for_export_with_key(&meta_raw, Some(&integrity_key))?;
    Ok((
        meta,
        std::fs::read(records_tmp.path())?,
        std::fs::read(web_tmp.path())?,
    ))
}

/// Санитизированная копия meta.db для бэкапа.
///
/// Из снимка убирается всё, что привязано к конкретной машине и при этом
/// является фактором доступа: обёртки FIDO2 и платформенный credential
/// Windows Hello. Бэкап — это recovery-путь: он разворачивается по частям
/// B и C и по PIN, а не по железу исходного ПК.
///
/// Обёртки, бесполезные вне машины (`device_secret_tpm_blob`,
/// `integrity_key_dpapi`), остаются: без TPM/DPAPI того же ПК они не
/// расшифровываются, а на том же ПК позволяют восстановиться без recovery.
pub(crate) fn sanitize_meta_for_export_with_key(
    raw: &[u8],
    integrity_key: Option<&[u8; 32]>,
) -> Result<Vec<u8>> {
    use rusqlite::{Connection, OpenFlags};

    let tmp =
        tempfile::NamedTempFile::new().map_err(|e| VaultError::System(format!("tempfile: {e}")))?;
    let tmp_path = tmp.path().to_path_buf();
    std::fs::write(&tmp_path, raw)?;

    {
        let conn = Connection::open_with_flags(
            &tmp_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| VaultError::System(format!("sanitize open: {e}")))?;

        // Схема одна и та же во всём продукте, поэтому ошибка здесь — это баг,
        // а не старый файл: молча проглотить её значило бы выпустить секреты.
        conn.execute_batch(
            r#"
            DELETE FROM fido2_keys;
            UPDATE vault_meta SET
                use_windows_hello = 0,
                require_auth_for_copy = 0,
                hello_key_credential_name = NULL,
                hello_key_credential_public_key = NULL
            WHERE id = 1;
            "#,
        )
        .map_err(|e| VaultError::System(format!("sanitize meta: {e}")))?;

        // VACUUM убирает освободившиеся страницы вместе с их содержимым.
        conn.execute_batch("VACUUM")
            .map_err(|e| VaultError::System(format!("sanitize vacuum: {e}")))?;
    }

    if let Some(key) = integrity_key {
        MetaDb::open(&tmp_path)?.reseal_snapshot(key)?;
    }
    let sanitized = std::fs::read(&tmp_path)?;
    // tmp удалится автоматически при drop NamedTempFile
    Ok(sanitized)
}

/// Оставить последние KEEP_LAST копий, старые удалить.
///
/// Порядок — по времени изменения файла, при равенстве по имени. Имя несёт
/// ЛОКАЛЬНОЕ время создания: после перевода часов или смены часового пояса
/// более новая копия получила бы «меньшее» имя и была бы удалена вместо старой.
fn apply_retention(dir: &Path) {
    let mut backups: Vec<(std::time::SystemTime, std::path::PathBuf)> = match std::fs::read_dir(dir)
    {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.starts_with("Vaultisor-backup-") && n.ends_with(".vault"))
                    .unwrap_or(false)
            })
            .map(|e| {
                let modified = e
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::UNIX_EPOCH);
                (modified, e.path())
            })
            .collect(),
        Err(_) => return,
    };
    backups.sort();
    if backups.len() > KEEP_LAST {
        for (_, old) in &backups[..backups.len() - KEEP_LAST] {
            let _ = std::fs::remove_file(old);
        }
    }
}

/// Валидация папки назначения: абсолютный путь, без `..`, не сетевой.
///
/// Сетевой путь проверяется и по каноническому виду: диск, подключённый как
/// `Z:`, после `canonicalize` оказывается `\\?\UNC\server\share`, а по
/// строке из конфига этого не видно. Бэкап не должен уходить на SMB
/// атакующего. Локальная папка облачного клиента (Я.Диск/OneDrive) — обычный
/// путь с буквой диска, под ограничение не попадает.
fn validate_dir(p: &str) -> Result<&Path> {
    let path = Path::new(p);
    if !path.is_absolute() {
        return Err(VaultError::BadInput("Путь должен быть абсолютным".into()));
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(VaultError::BadInput(
            "Путь содержит запрещённые сегменты ..".into(),
        ));
    }
    crate::commands::file_grants::reject_network_path(path)?;
    if path.exists() {
        crate::commands::file_grants::canonical_local_path(path)?;
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Конфиг резервных копий обязан
    /// читаться и писаться без обращения к состоянию сессии. Раньше это
    /// обращение было, и команды, уже державшие мьютекс сессии, вешали
    /// приложение намертво. Тест работает без Tauri именно потому, что
    /// зависимость от AppState устранена структурно.
    #[test]
    fn config_roundtrip_needs_only_directory_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x5Au8; 32];
        let cfg = BackupConfig {
            dir: Some(r"C:\backups".into()),
            frequency: "daily".into(),
            last_backup: Some("2026-09-13T10:00:00+03:00".into()),
        };
        write_config_at(dir.path(), &key, &cfg).unwrap();
        let restored = read_config_at(dir.path(), &key).unwrap();
        assert_eq!(restored.dir, cfg.dir);
        assert_eq!(restored.frequency, "daily");
        assert_eq!(restored.last_backup, cfg.last_backup);
    }

    #[test]
    fn missing_config_is_default_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = read_config_at(dir.path(), &[0x11u8; 32]).unwrap();
        assert!(cfg.dir.is_none());
        assert_eq!(cfg.frequency, "off");
    }

    #[test]
    fn redirected_destination_is_rejected_by_mac() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x33u8; 32];
        write_config_at(
            dir.path(),
            &key,
            &BackupConfig {
                dir: Some(r"C:\backup-a".into()),
                frequency: "daily".into(),
                last_backup: None,
            },
        )
        .unwrap();

        // Подмена каталога назначения мимо приложения должна быть замечена.
        let path = config_path(dir.path());
        let raw = std::fs::read_to_string(&path).unwrap();
        let tampered = raw.replace(r"C:\\backup-a", r"C:\\attacker");
        assert_ne!(raw, tampered, "подстановка должна была сработать");
        std::fs::write(&path, tampered).unwrap();

        assert!(matches!(
            read_config_at(dir.path(), &key),
            Err(VaultError::CorruptedWrapper)
        ));
    }

    #[test]
    fn config_written_under_another_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        write_config_at(
            dir.path(),
            &[0x01u8; 32],
            &BackupConfig {
                dir: Some(r"C:\backups".into()),
                frequency: "weekly".into(),
                last_backup: None,
            },
        )
        .unwrap();
        assert!(matches!(
            read_config_at(dir.path(), &[0x02u8; 32]),
            Err(VaultError::CorruptedWrapper)
        ));
    }

    #[test]
    fn unauthenticated_config_grants_no_path_authority() {
        let dir = tempfile::tempdir().unwrap();
        // Голый BackupConfig без конверта и MAC.
        std::fs::write(
            config_path(dir.path()),
            br#"{"dir":"C:\\attacker","frequency":"daily","last_backup":null}"#,
        )
        .unwrap();
        let cfg = read_config_at(dir.path(), &[0x44u8; 32]).unwrap();
        assert!(
            cfg.dir.is_none(),
            "старый формат не должен давать право на запись в произвольный каталог"
        );
    }

    #[test]
    fn unknown_envelope_version_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            config_path(dir.path()),
            br#"{"version":2,"config":{"dir":null,"frequency":"off","last_backup":null},"mac_hex":"00"}"#,
        )
        .unwrap();
        assert!(matches!(
            read_config_at(dir.path(), &[0x55u8; 32]),
            Err(VaultError::CorruptedWrapper)
        ));
    }

    #[test]
    fn retention_keeps_last_n_and_ignores_others() {
        let dir = tempfile::tempdir().unwrap();
        // 5 бэкапов; имена с таймстампом → лексикографически = хронологически.
        for i in 1..=5 {
            let name = format!("Vaultisor-backup-2026010{i}-000000.vault");
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        // Посторонний файл не должен считаться или удаляться.
        std::fs::write(dir.path().join("notes.txt"), b"y").unwrap();

        apply_retention(dir.path());

        let backups: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.starts_with("Vaultisor-backup-") && n.ends_with(".vault"))
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(
            backups.len(),
            KEEP_LAST,
            "должно остаться ровно KEEP_LAST копий"
        );
        // Удалены самые старые (…01, …02), остались новейшие (…03,04,05).
        assert!(!dir
            .path()
            .join("Vaultisor-backup-20260101-000000.vault")
            .exists());
        assert!(dir
            .path()
            .join("Vaultisor-backup-20260105-000000.vault")
            .exists());
        assert!(
            dir.path().join("notes.txt").exists(),
            "посторонний файл не трогаем"
        );
    }

    fn set_mtime(path: &Path, at: std::time::SystemTime) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(at)
            .unwrap();
    }

    fn backups_left(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("Vaultisor-backup-"))
            .collect();
        names.sort();
        names
    }

    /// Имя несёт локальное время: после перевода часов самая новая копия
    /// может иметь «меньшее» имя. Удаляться должна самая старая по времени.
    #[test]
    fn retention_orders_by_modified_time_not_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let base = std::time::SystemTime::now() - std::time::Duration::from_secs(86_400);
        for i in 1..=5u64 {
            let name = format!("Vaultisor-backup-2026010{i}-000000-aaaaaaaa.vault");
            let path = dir.path().join(&name);
            std::fs::write(&path, b"x").unwrap();
            // Чем больше число в имени, тем СТАРШЕ файл.
            set_mtime(&path, base + std::time::Duration::from_secs((6 - i) * 60));
        }
        apply_retention(dir.path());
        assert_eq!(
            backups_left(dir.path()),
            [
                "Vaultisor-backup-20260101-000000-aaaaaaaa.vault",
                "Vaultisor-backup-20260102-000000-aaaaaaaa.vault",
                "Vaultisor-backup-20260103-000000-aaaaaaaa.vault",
            ],
            "остались три самые новые по времени, а не по имени"
        );
    }

    #[test]
    fn retention_breaks_modified_time_ties_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let same = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        for i in 1..=5 {
            let path = dir
                .path()
                .join(format!("Vaultisor-backup-2026010{i}-000000-bbbbbbbb.vault"));
            std::fs::write(&path, b"x").unwrap();
            set_mtime(&path, same);
        }
        apply_retention(dir.path());
        assert_eq!(
            backups_left(dir.path()),
            [
                "Vaultisor-backup-20260103-000000-bbbbbbbb.vault",
                "Vaultisor-backup-20260104-000000-bbbbbbbb.vault",
                "Vaultisor-backup-20260105-000000-bbbbbbbb.vault",
            ]
        );
    }

    #[test]
    fn network_destinations_are_rejected_in_any_spelling() {
        for bad in [
            r"\\server\share\backups",
            r"\\?\UNC\server\share\backups",
            r"//server/share/backups",
            r"\\.\PhysicalDrive0",
        ] {
            assert!(
                matches!(validate_dir(bad), Err(VaultError::BadInput(_))),
                "{bad}"
            );
        }
        assert!(validate_dir(r"relative\dir").is_err());
        assert!(validate_dir(r"C:\backups\..\other").is_err());
        assert!(validate_dir(r"C:\backups").is_ok());
        assert!(validate_dir(r"\\?\C:\backups").is_ok());
        // Существующий локальный каталог проходит и по каноническому виду.
        let dir = tempfile::tempdir().unwrap();
        assert!(validate_dir(dir.path().to_str().unwrap()).is_ok());
    }

    #[test]
    fn backup_destination_is_covered_by_config_mac() {
        let key = [0x42; 32];
        let first = BackupConfig {
            dir: Some(r"C:\backup-a".into()),
            frequency: "daily".into(),
            last_backup: None,
        };
        let mut redirected = first.clone();
        redirected.dir = Some(r"C:\redirected".into());
        assert_ne!(
            config_mac(&key, &first).unwrap(),
            config_mac(&key, &redirected).unwrap()
        );
    }

    #[test]
    fn sanitized_backup_is_self_consistent_after_fido_removal() {
        std::env::set_var("VAULTISOR_TEST_CHECKPOINTS", "1");
        let dir = tempfile::tempdir().unwrap();
        let source = crate::storage::meta_db::MetaDb::open(&dir.path().join("source.db")).unwrap();
        let key = [0x77u8; 32];
        source
            .vault_create(b"wrapped", 300, 10, b"dpapi", &key, b"entropy", None)
            .unwrap();
        source
            .add_fido2_key(
                &key,
                "fido",
                b"credential",
                b"public",
                b"wrapped",
                None,
                true,
                None,
            )
            .unwrap();
        let sanitized =
            sanitize_meta_for_export_with_key(&std::fs::read(source.path()).unwrap(), Some(&key))
                .unwrap();
        let exported = dir.path().join("sanitized.db");
        std::fs::write(&exported, sanitized).unwrap();
        let restored = crate::storage::meta_db::MetaDb::open(&exported).unwrap();
        restored.verify_meta_mac_only(&key).unwrap();
        // A sanitized snapshot has different metadata at the same epoch; it
        // may become live only through authorized restore/checkpoint install.
        assert!(restored.verify_meta_integrity(&key).is_err());
        source.verify_meta_integrity(&key).unwrap();
        assert!(restored.get_fido2_keys().unwrap().is_empty());
    }
}
