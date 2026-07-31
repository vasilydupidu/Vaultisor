// Чтение и запись настроек хранилища.
//
// Все изменения требуют unlocked-сессии. Для изменения vault_meta нужен
// integrity_key, иначе следующий unlock получит META_TAMPERED.

use crate::error::{Result, VaultError};
use crate::state::{AppState, SessionState, VaultSettings};
use serde::{Deserialize, Serialize};
use tauri::State;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsDto {
    pub autolock_seconds: u32,
    pub clipboard_clear_seconds: u32,
    pub require_auth_for_copy: bool,
    pub use_windows_hello: bool,
    pub max_pin_attempts: u32,
}

impl From<&VaultSettings> for SettingsDto {
    fn from(s: &VaultSettings) -> Self {
        Self {
            autolock_seconds: s.autolock_seconds,
            clipboard_clear_seconds: s.clipboard_clear_seconds,
            require_auth_for_copy: s.require_auth_for_copy,
            use_windows_hello: s.use_windows_hello,
            max_pin_attempts: s.max_pin_attempts,
        }
    }
}

#[tauri::command]
pub fn settings_get(state: State<'_, AppState>) -> SettingsDto {
    let s = state.settings.lock();
    SettingsDto::from(&*s)
}

#[tauri::command]
pub async fn settings_update(
    input: SettingsDto,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<()> {
    // AUDIT M5: авто-блокировка по простою до изменения настроек.
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    state.touch();
    let new_autolock = input.autolock_seconds.min(60 * 60);
    let new_clipboard = input.clipboard_clear_seconds.min(120);
    let new_require_auth = input.require_auth_for_copy;
    let new_hello = input.use_windows_hello;
    let new_max_pin_attempts = input.max_pin_attempts.clamp(3, 10);

    // M-01: «Подтверждение для копирования» опирается на Windows Hello как второй
    // фактор. Без Hello подтверждать нечем — не даём включить «пустую» настройку,
    // иначе это был бы декоративный (нефункциональный) контрол.
    if new_require_auth && !new_hello {
        return Err(VaultError::BadInput(
            "«Подтверждение для копирования» требует включённого Windows Hello".into(),
        ));
    }

    let prev_hello = state.settings.lock().use_windows_hello;

    let (master_key, integrity_key) = {
        let session = state.session.lock();
        match &*session {
            SessionState::Locked => return Err(VaultError::Locked),
            SessionState::Unlocked {
                master_key,
                integrity_key,
                ..
            } => (master_key.clone(), integrity_key.clone()),
        }
    };

    if new_hello != prev_hello {
        if new_hello {
            if !crate::windows_api::cng_hello::is_supported() {
                return Err(VaultError::System(
                    "Windows Hello недоступен: аппаратный Microsoft Platform Crypto Provider не готов или не подтверждает TPM.".into(),
                ));
            }

            let mut cred_name = String::new();
            let attempt = async {
                log::info!("settings: starting CNG TPM key create+sign");
                let credential =
                    crate::windows_api::cng_hello::create_and_sign(
                        &app,
                        crate::commands::vault::TPM_KEK_CHALLENGE,
                    )
                    .await?;
                cred_name = credential.stored_id;
                let (ek, ct, dk_encrypted, tpm_wrapped_key) =
                    crate::commands::vault::wrap_hello_v2(&master_key, &credential.signature)?;
                let db = state.open_meta()?;
                db.save_tpm_wrap(&*integrity_key, &cred_name, &tpm_wrapped_key)?;
                db.save_pq_hello(&*integrity_key, &ek, &ct, &dk_encrypted)?;
                Ok::<(), VaultError>(())
            }
            .await;

            if let Err(e) = attempt {
                log::warn!("settings: TPM Hello failed ({}), Hello not enabled", e);
                let _ = crate::windows_api::cng_hello::delete(&cred_name);
                return Err(VaultError::System(format!(
                    "Windows Hello hardware unwrap не работает на этой системе ({}).",
                    e
                )));
            }

            log::info!("settings: TPM Hello enabled");
        } else {
            let db = state.open_meta()?;
            db.clear_hello_wrapped(&*integrity_key)?;
            if let Some(meta) = db.vault_load()? {
                if let Some(cred_name) = meta.tpm_credential_name {
                    let _ = crate::windows_api::cng_hello::delete(&cred_name);
                }
            }
            db.clear_tpm_wrap(&*integrity_key)?;
        }
    }

    let db = state.open_meta()?;
    db.update_settings(
        &*integrity_key,
        new_autolock,
        new_clipboard,
        new_require_auth,
        new_hello,
        new_max_pin_attempts,
    )?;

    let mut s = state.settings.lock();
    *s = VaultSettings {
        autolock_seconds: new_autolock,
        clipboard_clear_seconds: new_clipboard,
        require_auth_for_copy: new_require_auth,
        use_windows_hello: new_hello,
        max_pin_attempts: new_max_pin_attempts,
    };

    log::info!("settings_update: applied");
    Ok(())
}

#[tauri::command]
pub async fn get_ui_language(state: State<'_, AppState>) -> Result<String> {
    let session = state.session.lock();
    match &*session {
        SessionState::Unlocked { .. } => {
            let db = state.open_meta()?;
            db.get_ui_language()
        },
        _ => Ok("ru".to_string()), // fallback before unlock
    }
}

#[tauri::command]
pub async fn set_ui_language(lang: String, state: State<'_, AppState>) -> Result<()> {
    let session = state.session.lock();
    match &*session {
        SessionState::Unlocked { .. } => {
            let db = state.open_meta()?;
            db.set_ui_language(&lang)
        },
        _ => Err(VaultError::Locked),
    }
}
