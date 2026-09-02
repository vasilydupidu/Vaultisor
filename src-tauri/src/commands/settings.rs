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
                let db = state.open_meta()?;
                let meta = db.vault_load()?.ok_or(VaultError::NotInitialized)?;
                let (ek, ct, dk_encrypted, tpm_wrapped_key) =
                    crate::commands::vault::wrap_hello_v2(&master_key, &credential.signature, meta.dpapi_entropy.as_deref())?;
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

#[tauri::command]
pub async fn get_enable_health_check(state: State<'_, AppState>) -> Result<bool> {
    let db = state.open_meta()?;
    db.get_enable_health_check()
}

#[tauri::command]
pub async fn set_enable_health_check(enabled: bool, state: State<'_, AppState>) -> Result<()> {
    let session = state.session.lock();
    match &*session {
        SessionState::Unlocked { .. } => {
            let db = state.open_meta()?;
            db.set_enable_health_check(enabled)
        }
        _ => Err(VaultError::Locked),
    }
}

#[tauri::command]
pub async fn get_enable_password_history(state: State<'_, AppState>) -> Result<bool> {
    let db = state.open_meta()?;
    db.get_enable_password_history()
}

#[tauri::command]
pub async fn set_enable_password_history(enabled: bool, state: State<'_, AppState>) -> Result<()> {
    let session = state.session.lock();
    match &*session {
        SessionState::Unlocked { .. } => {
            let db = state.open_meta()?;
            db.set_enable_password_history(enabled)
        }
        _ => Err(VaultError::Locked),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2KeyItem {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub credential_id_preview: String,
    /// Название модели ключа, определённое по AAGUID ("Рутокен MFA", "YubiKey 5 NFC" и т.д.)
    pub model_name: String,
    /// Режим привязки: true = ПИН+Touch, false = Touch-only
    pub require_pin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2StatusDto {
    pub enabled: bool,
    pub available: bool,
    pub keys: Vec<Fido2KeyItem>,
}

#[tauri::command]
pub async fn get_fido2_status(state: State<'_, AppState>) -> Result<Fido2StatusDto> {
    let db = state.open_meta()?;
    let keys_rows = db.get_fido2_keys().unwrap_or_default();
    let (enabled_meta, _, _) = db.get_fido2_status().unwrap_or((false, None, None));
    let available = crate::auth::fido2::is_fido2_supported();

    let keys = keys_rows
        .into_iter()
        .map(|k| {
            let hex_id = hex::encode(&k.credential_id);
            let preview = if !hex_id.is_empty() {
                if hex_id.len() > 12 {
                    format!("{}...{}", &hex_id[..6], &hex_id[hex_id.len() - 6..])
                } else {
                    hex_id
                }
            } else {
                format!("id-{}", &k.id[..6.min(k.id.len())])
            };
            // Определяем модель ключа по AAGUID
            let model_name = if let Some(ref aaguid_hex) = k.aaguid {
                if aaguid_hex.len() == 32 {
                    let mut buf = [0u8; 16];
                    if hex::decode_to_slice(aaguid_hex, &mut buf).is_ok() {
                        crate::auth::fido2::aaguid_model_name(&buf).to_string()
                    } else {
                        "FIDO2 Security Key".to_string()
                    }
                } else {
                    "FIDO2 Security Key".to_string()
                }
            } else {
                "FIDO2 Security Key".to_string()
            };
            Fido2KeyItem {
                id: k.id,
                name: k.name,
                created_at: k.created_at,
                credential_id_preview: preview,
                model_name,
                require_pin: k.require_pin,
            }
        })
        .collect::<Vec<_>>();

    let enabled = enabled_meta || !keys.is_empty();
    Ok(Fido2StatusDto { enabled, available, keys })
}

#[tauri::command]
pub async fn register_fido2_key(name: Option<String>, require_pin: Option<bool>, state: State<'_, AppState>) -> Result<Fido2KeyItem> {
    let (master_key, _integrity_key) = {
        let session = state.session.lock();
        match &*session {
            SessionState::Unlocked { master_key, integrity_key, .. } => (master_key.clone(), integrity_key.clone()),
            _ => return Err(VaultError::Locked),
        }
    };

    let pin_mode = require_pin.unwrap_or(true);
    let key_name = name.filter(|n| !n.trim().is_empty()).unwrap_or_else(|| "FIDO2 Ключ".to_string());
    let name_for_prompt = key_name.clone();

    let reg = tokio::task::spawn_blocking(move || {
        crate::auth::fido2::register_fido2_key_prompt(&name_for_prompt, pin_mode)
    })
    .await
    .map_err(|e| VaultError::BadInput(format!("ошибка вызова FIDO2: {e}")))?;

    let reg = reg?;

    // VULN-01 FIX: проверяем поддержку PRF (hmac-secret).
    // Если аутентификатор не поддерживает PRF, привязка не обеспечивает
    // аппаратную защиту KEK → отказываем в регистрации.
    if !reg.prf_supported {
        return Err(VaultError::BadInput(
            "Ваш FIDO2-ключ не поддерживает расширение PRF (hmac-secret). \
             Привязка невозможна — KEK не может быть аппаратно защищён. \
             Используйте ключ с поддержкой CTAP2 hmac-secret (Рутокен MFA, YubiKey 5+)."
            .into(),
        ));
    }

    // VULN-01 FIX: немедленно выполняем assertion с PRF salt, чтобы получить
    // hardware-bound secret для вывода KEK.
    let cred_ids = vec![reg.credential_id.clone()];
    let assertion = tokio::task::spawn_blocking(move || {
        crate::auth::fido2::assert_fido2_key_prompt(&cred_ids, pin_mode)
    })
    .await
    .map_err(|e| VaultError::BadInput(format!("ошибка PRF assertion: {e}")))?;

    let assertion = assertion?;

    let prf_output = assertion.prf_output.ok_or_else(|| VaultError::BadInput(
        "FIDO2-ключ поддерживает PRF, но не вернул PRF-output при assertion. \
         Возможно, требуется обновление ОС (Windows 11 21H2+).".into(),
    ))?;

    // VULN-01 FIX: KEK выводится из PRF-output (hardware-bound secret),
    // а НЕ из публичного credential_id.
    let fido2_kek = crate::crypto::kdf::hkdf_derive(
        &prf_output, b"vaultisor:fido2-prf-kek-salt:v1", b"vaultisor:fido2-prf-kek:v1", 32)?;
    let mut kek_arr = [0u8; 32];
    kek_arr.copy_from_slice(&fido2_kek);

    let fido2_blob = master_key.with_decrypted(|dec| {
        crate::crypto::aead::encrypt(&kek_arr, dec, b"vaultisor:fido2-wrap:v2")
    })?;
    zeroize::Zeroize::zeroize(&mut kek_arr);
    let fido2_wrapped_bytes = fido2_blob.to_bytes();

    let aaguid_hex = hex::encode(&reg.aaguid);
    let model_name = crate::auth::fido2::aaguid_model_name(&reg.aaguid).to_string();

    // Если пользователь не задал имя — используем модель ключа как имя
    let final_name = if key_name == "FIDO2 Ключ" {
        model_name.clone()
    } else {
        key_name
    };

    let db = state.open_meta()?;
    let added = db.add_fido2_key(&final_name, &reg.credential_id, &reg.public_key, &fido2_wrapped_bytes, Some(&aaguid_hex), pin_mode)?;

    let hex_id = hex::encode(&added.credential_id);
    let preview = if !hex_id.is_empty() {
        if hex_id.len() > 12 {
            format!("{}...{}", &hex_id[..6], &hex_id[hex_id.len() - 6..])
        } else {
            hex_id
        }
    } else {
        format!("id-{}", &added.id[..6.min(added.id.len())])
    };

    Ok(Fido2KeyItem {
        id: added.id,
        name: added.name,
        created_at: added.created_at,
        credential_id_preview: preview,
        model_name,
        require_pin: pin_mode,
    })
}

#[tauri::command]
pub async fn unbind_fido2_key(id: Option<String>, state: State<'_, AppState>) -> Result<()> {
    let session = state.session.lock();
    match &*session {
        SessionState::Unlocked { .. } => {
            let db = state.open_meta()?;
            if let Some(key_id) = id {
                db.delete_fido2_key(&key_id)
            } else {
                db.delete_all_fido2_keys()
            }
        }
        _ => Err(VaultError::Locked),
    }
}
