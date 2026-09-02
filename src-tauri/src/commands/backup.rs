// Лёгкая автоматизация резервных копий.
//
// Бэкап = копия ОДНОГО зашифрованного бандла (все три БД, формат VLT2 — как
// vault_export) в выбранную пользователем папку. Если папка синхронизируется
// облачным клиентом (Я.Диск/Dropbox/OneDrive) — копия уезжает в облако.
//
// Безопасность: бандл полностью зашифрован и привязан к устройству (TPM+DPAPI);
// восстановление на другом ПК возможно только через Shamir. Поэтому копию
// безопасно держать в стороннем облаке.
//
// Конфиг (папка/частота/время последнего бэкапа) хранится в vault/backup.json —
// это несекретные значения (путь + расписание), под master-key их класть не
// нужно. Бэкап требует разблокированную сессию (как и экспорт) — анти-эксфильтрация.

use std::path::Path;

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::error::{Result, VaultError};
use crate::state::AppState;

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

impl Default for BackupConfig {
    fn default() -> Self {
        Self { dir: None, frequency: "off".into(), last_backup: None }
    }
}

fn config_path(state: &AppState) -> std::path::PathBuf {
    state.data_dir.join("backup.json")
}

fn read_config(state: &AppState) -> BackupConfig {
    std::fs::read_to_string(config_path(state))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn write_config(state: &AppState, cfg: &BackupConfig) -> Result<()> {
    let json = serde_json::to_string_pretty(cfg)
        .map_err(|e| VaultError::System(format!("backup config serialize: {e}")))?;
    std::fs::write(config_path(state), json)?;
    Ok(())
}

#[tauri::command]
pub fn backup_get_config(state: State<'_, AppState>) -> Result<BackupConfig> {
    Ok(read_config(state.inner()))
}

#[derive(Debug, Deserialize)]
pub struct BackupSetInput {
    pub dir: Option<String>,
    pub frequency: String,
}

#[tauri::command]
pub fn backup_set_config(input: BackupSetInput, state: State<'_, AppState>) -> Result<()> {
    let mut cfg = read_config(state.inner());
    cfg.dir = input.dir;
    cfg.frequency = match input.frequency.as_str() {
        "daily" | "weekly" | "off" => input.frequency,
        _ => "off".into(),
    };
    write_config(state.inner(), &cfg)
}

#[derive(Debug, Serialize)]
pub struct BackupResult {
    pub path: String,
}

#[tauri::command]
pub fn backup_now(state: State<'_, AppState>, dir: String) -> Result<BackupResult> {
    // Требуем разблокированную сессию (как и экспорт) — защита от эксфильтрации
    // фоновым/вредоносным кодом без ведома пользователя.
    // AUDIT M5: сначала авто-блокировка по простою.
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    if !state.session.lock().is_unlocked() {
        return Err(VaultError::Locked);
    }
    state.touch();

    let target = validate_dir(&dir)?;
    std::fs::create_dir_all(target)?;

    let bundle = build_bundle(state.inner())?;

    // Имя с временной меткой (локальное время). Лексикографически = хронологически.
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let full = target.join(format!("Vaultisor-backup-{ts}.vault"));
    std::fs::write(&full, &bundle)?;

    apply_retention(target);

    let mut cfg = read_config(state.inner());
    cfg.dir = Some(dir.clone());
    cfg.last_backup = Some(chrono::Local::now().to_rfc3339());
    let _ = write_config(state.inner(), &cfg);

    log::info!("backup_now: wrote backup ({} bytes)", bundle.len());
    Ok(BackupResult { path: full.to_string_lossy().to_string() })
}

/// Собрать VLT2-бандл из трёх зашифрованных БД (meta + records + web).
/// VULN-05 FIX: meta.db санитизируется перед включением — pin_hash обнуляется.
fn build_bundle(state: &AppState) -> Result<Vec<u8>> {
    let meta_raw = std::fs::read(state.meta_path())?;
    let meta = sanitize_meta_for_export(&meta_raw)?;
    let records = std::fs::read(state.records_path())?;
    let web = std::fs::read(state.web_path())?;
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

/// VULN-05 FIX: создать санитизированную копию meta.db для экспорта/бэкапа.
/// Обнуляет pin_hash — он не нужен для unlock (AEAD tag проверяет PIN),
/// но при экспозиции позволяет офлайн-перебор.
pub(crate) fn sanitize_meta_for_export(raw: &[u8]) -> Result<Vec<u8>> {
    use rusqlite::{Connection, OpenFlags};

    let tmp = tempfile::NamedTempFile::new()
        .map_err(|e| VaultError::System(format!("tempfile: {e}")))?;
    let tmp_path = tmp.path().to_path_buf();
    std::fs::write(&tmp_path, raw)?;

    {
        let conn = Connection::open_with_flags(
            &tmp_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| VaultError::System(format!("sanitize open: {e}")))?;

        // Обнуляем pin_hash (safety net для старых vault'ов).
        conn.execute("UPDATE vault_meta SET pin_hash = '' WHERE id = 1", [])
            .map_err(|e| VaultError::System(format!("sanitize pin_hash: {e}")))?;

        // VACUUM для компактности и удаления wal/journal с несанитизированными данными.
        let _ = conn.execute_batch("VACUUM");
    }

    let sanitized = std::fs::read(&tmp_path)?;
    // tmp удалится автоматически при drop NamedTempFile
    Ok(sanitized)
}

/// Оставить последние KEEP_LAST копий, старые удалить.
fn apply_retention(dir: &Path) {
    let mut backups: Vec<std::path::PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("Vaultisor-backup-") && n.ends_with(".vault"))
                    .unwrap_or(false)
            })
            .collect(),
        Err(_) => return,
    };
    backups.sort();
    if backups.len() > KEEP_LAST {
        for old in &backups[..backups.len() - KEEP_LAST] {
            let _ = std::fs::remove_file(old);
        }
    }
}

/// Валидация папки назначения: абсолютный путь, без `..`.
fn validate_dir(p: &str) -> Result<&Path> {
    let path = Path::new(p);
    if !path.is_absolute() {
        return Err(VaultError::BadInput("Путь должен быть абсолютным".into()));
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(VaultError::BadInput("Путь содержит запрещённые сегменты ..".into()));
    }
    // AUDIT M8: отклоняем UNC/сетевые пути — бэкап не должен уходить на SMB
    // атакующего по инъектированному пути. Локальная папка облачного клиента
    // (Я.Диск/OneDrive) — обычный путь с буквой диска, под ограничение не попадает.
    #[cfg(windows)]
    {
        if p.starts_with(r"\\") {
            return Err(VaultError::BadInput(
                "Сетевые и UNC-пути не поддерживаются".into(),
            ));
        }
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(backups.len(), KEEP_LAST, "должно остаться ровно KEEP_LAST копий");
        // Удалены самые старые (…01, …02), остались новейшие (…03,04,05).
        assert!(!dir.path().join("Vaultisor-backup-20260101-000000.vault").exists());
        assert!(dir.path().join("Vaultisor-backup-20260105-000000.vault").exists());
        assert!(dir.path().join("notes.txt").exists(), "посторонний файл не трогаем");
    }
}
