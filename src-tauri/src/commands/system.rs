// Системные команды.

use serde::Serialize;
use tauri::State;

use crate::error::Result;
use crate::state::AppState;

#[derive(Debug, Clone, Serialize)]
pub struct SystemCheck {
    pub dpapi_available: bool,
    pub windows_hello_available: bool,
    pub vbs_enclave_available: bool,
    pub tpm_available: bool,
    pub windows_version: String,
}

#[tauri::command]
pub fn system_check() -> SystemCheck {
    let c = crate::windows_api::capabilities();
    SystemCheck {
        dpapi_available: c.dpapi_available,
        windows_hello_available: c.windows_hello_available,
        vbs_enclave_available: c.vbs_enclave_available,
        tpm_available: c.tpm_available,
        windows_version: c.windows_version,
    }
}

/// Проверка существования инициализированного хранилища на диске.
/// Используется фронтом, чтобы решить — показывать онбординг или экран разблокировки.
#[tauri::command]
pub fn vault_exists(state: State<'_, AppState>) -> Result<bool> {
    let meta_path = state.meta_path();
    let records_path = state.records_path();
    log::info!(
        "vault_exists: meta={} (exists={}), records={} (exists={})",
        meta_path.display(),
        meta_path.exists(),
        records_path.display(),
        records_path.exists(),
    );
    if !meta_path.exists() || !records_path.exists() {
        log::warn!("vault_exists → false (один из файлов отсутствует)");
        return Ok(false);
    }
    let db = state.open_meta()?;
    let initialized = db.vault_initialized()?;
    log::info!("vault_exists → vault_initialized()={}", initialized);
    Ok(initialized)
}


#[tauri::command]
pub fn idle_seconds() -> Result<u64> {
    crate::windows_api::idle::idle_seconds()
}

/// Heartbeat сессии из фронтенда для корректного авто-лока.
///
/// `active` = была ли активность пользователя В ОКНЕ приложения с прошлого
/// вызова (движение мыши / клавиатура, включая набор в формах — где обычных
/// команд нет). Если активна — продлеваем сессию (touch). Затем проверяем
/// autolock (залочит при превышении простоя) и возвращаем, разблокирована ли
/// сессия ещё. Фронт при `false` уходит на lock-экран.
///
/// Это чинит рассинхрон: раньше фронт мерил СИСТЕМНЫЙ простой (ввод по всему
/// ПК), а бэкенд — активность в приложении; работа в других окнах приводила к
/// тому, что бэкенд лочил сессию, а UI оставался «разблокированным».
#[tauri::command]
pub fn session_heartbeat(state: State<AppState>, active: bool) -> Result<bool> {
    if active {
        state.touch();
    }
    state.check_autolock();
    Ok(state.session.lock().is_unlocked())
}
