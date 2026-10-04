//! Блокировка, вход по FIDO2-ключу и смена PIN.

use serde::Deserialize;
use tauri::State;

use crate::auth::backoff::BackoffState;
use crate::auth::webauthn_rp::{self, Ceremony, ClientData};
use crate::commands::security::{self, SecurityAction};
use crate::error::{Result, VaultError};
use crate::state::{AppState, SessionState};
use crate::storage::db::wrap_dpapi_layer;

use crate::commands::vault::helpers::{load_device_secret, open_session, wrap_master_off_thread};
use crate::commands::vault::unlock::verified_meta;

#[tauri::command]
pub fn vault_lock(state: State<'_, AppState>) -> Result<()> {
    state.lock();
    Ok(())
}

/// Что показать на экране блокировки. Не требует разблокированной сессии.
#[derive(Debug, serde::Serialize)]
pub struct LockInfo {
    /// Windows Hello настроен как второй фактор после PIN.
    pub use_windows_hello: bool,
    /// Привязан хотя бы один аппаратный FIDO2-ключ.
    pub fido2_enabled: bool,
}

#[tauri::command]
pub fn vault_lock_info(state: State<'_, AppState>) -> Result<LockInfo> {
    let path = state.meta_path();
    if !path.exists() {
        return Ok(LockInfo {
            use_windows_hello: false,
            fido2_enabled: false,
        });
    }
    let db = state.open_meta()?;
    let Some(meta) = db.vault_load()? else {
        return Ok(LockInfo {
            use_windows_hello: false,
            fido2_enabled: false,
        });
    };
    let (fido2_enabled, _, _) = db.get_fido2_status().unwrap_or((false, None, None));
    Ok(LockInfo {
        use_windows_hello: meta.use_windows_hello && meta.hello_key_credential_name.is_some(),
        fido2_enabled,
    })
}

#[tauri::command]
pub async fn vault_unlock_with_fido2(state: State<'_, AppState>) -> Result<()> {
    unlock_with_fido2(&state).await
}

/// Вход по FIDO2-ключу без PIN Vaultisor.
///
/// Порядок — как у RP: свежий challenge → assertion → credential id из списка
/// привязанных → rpIdHash, UP, UV по режиму этого ключа, ES256-подпись
/// сохранённым при привязке ключом → и только затем PRF-выход идёт в KEK.
/// KEK зависит ещё и от Device Secret этого ПК (см. `crypto::fido`), поэтому
/// токен с копией файлов на другом компьютере хранилище не открывает.
pub(crate) async fn unlock_with_fido2(state: &AppState) -> Result<()> {
    let _auth_flow = state.auth_flow.lock().await;
    let db = state.open_meta()?;
    let (integrity_key, meta) = verified_meta(&db)?;
    let keys = db.get_fido2_keys()?;
    if keys.is_empty() {
        return Err(VaultError::BadInput(
            "Физический FIDO2-ключ не привязан".into(),
        ));
    }
    let (_, device_secret) = load_device_secret(&state.os, &db).await?;

    let all_ids: Vec<Vec<u8>> = keys.iter().map(|k| k.credential_id.clone()).collect();
    // Что попросить у аутентификатора, известно только для однородного набора:
    // заранее неизвестно, какой ключ поднесут. Настоящая проверка — ниже, по
    // флагу UV в подписанных данных откликнувшегося ключа.
    let require_pin = keys.iter().all(|k| k.require_pin);
    let client = ClientData::new(Ceremony::Get);
    let (os, json) = (state.os.clone(), client.json.clone());
    let assertion =
        crate::blocking::run(move || os.fido_assert(&all_ids, require_pin, &json)).await?;

    let key = keys
        .iter()
        .find(|k| k.credential_id == assertion.credential_id)
        .ok_or_else(|| VaultError::FidoFailed("ответил непривязанный ключ".into()))?;
    webauthn_rp::verify_client_data(&client.json, Ceremony::Get, &client.challenge)?;
    let verified = webauthn_rp::verify_assertion(
        &key.public_key,
        &assertion.authenticator_data,
        &client.json,
        &assertion.signature,
        key.require_pin,
    )?;

    let prf = assertion
        .prf_output
        .ok_or_else(|| VaultError::FidoFailed("токен не вернул PRF-секрет (hmac-secret)".into()))?;
    let master = crate::crypto::fido::unwrap_master(
        &key.fido2_wrapped_key,
        &prf,
        &device_secret,
        &key.credential_id,
        &meta.dpapi_entropy,
    )?;

    // Доказанное владение фактором снимает задержку после неверных PIN.
    if meta.backoff != BackoffState::default() {
        db.set_backoff(&integrity_key, BackoffState::default())?;
    }
    open_session(state, master, integrity_key)?;
    super::unlock::after_unlock(state, &meta);
    log::info!(
        "vault_unlock_with_fido2: unlocked via '{}' (mode={}, uv={})",
        key.name,
        if key.require_pin {
            "pin+touch"
        } else {
            "touch-only"
        },
        verified.user_verified
    );
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePinInput {
    pub new_pin: String,
    /// Один на намерение пользователя: повтор после потерянного ответа
    /// распознаётся и не требует подтверждения уже сменённым PIN.
    pub request_id: String,
}

#[tauri::command]
pub async fn vault_change_pin(input: ChangePinInput, state: State<'_, AppState>) -> Result<()> {
    change_pin(&state, input).await
}

/// Сменить PIN в открытой сессии.
///
/// Требует свежего подтверждения (`SecurityAction::ChangePin`): оно и есть
/// проверка текущего PIN (и Hello). Сессию команда не открывает и не
/// переоткрывает — это не путь входа. Новая обёртка, её соль и параметры
/// Argon2 записываются одной транзакцией.
pub(crate) async fn change_pin(state: &AppState, input: ChangePinInput) -> Result<()> {
    let _auth_flow = state.auth_flow.lock().await;
    let (master, integrity_key, stamp) = {
        let session = state.session.lock();
        match &*session {
            SessionState::Unlocked {
                master_key,
                integrity_key,
                unlocked_at,
                ..
            } => (master_key.clone(), integrity_key.clone(), *unlocked_at),
            SessionState::Locked => return Err(VaultError::Locked),
        }
    };
    let request_id = crate::commands::request::parse(&input.request_id)?;
    let db = state.open_meta()?;
    let (_, meta) = verified_meta(&db)?;
    if meta.pin_change_request_id.as_deref() == Some(request_id.as_str()) {
        // Повтор распознаётся, только если это тот же новый PIN: он обязан
        // открывать уже записанную обёртку. Иначе пользователь думал бы, что
        // задал второй PIN, а действовал бы первый.
        let wrapped =
            super::helpers::unwrap_master_blob(&meta.wrapped_master_dpapi, &meta.dpapi_entropy)?;
        let params = crate::crypto::kdf::Argon2Params::from_stored(
            meta.argon2_m_cost,
            meta.argon2_t_cost,
            meta.argon2_p_cost,
        )?;
        let device_secret = if meta.crypto_version >= 2 {
            Some(load_device_secret(&state.os, &db).await?.1)
        } else {
            None
        };
        return match super::helpers::unwrap_master_off_thread(
            wrapped,
            input.new_pin.as_bytes(),
            device_secret,
            params,
        )
        .await
        {
            Ok(_) => {
                log::info!("vault_change_pin: request already applied");
                Ok(())
            }
            Err(_) => Err(VaultError::BadInput(
                "Этот запрос смены PIN уже выполнен с другим значением".into(),
            )),
        };
    }
    security::consume(state, SecurityAction::ChangePin)?;

    crate::auth::pin::validate_secret_format(&input.new_pin, meta.crypto_version >= 2)?;
    let device_secret = if meta.crypto_version >= 2 {
        Some(load_device_secret(&state.os, &db).await?.1)
    } else {
        None
    };
    let (_, wrapped, params) =
        wrap_master_off_thread(master, input.new_pin.as_bytes(), device_secret).await?;
    let stored = wrap_dpapi_layer(&wrapped, &meta.dpapi_entropy)?;

    if crate::commands::file_grants::session_stamp(&state.session.lock()) != Some(stamp) {
        return Err(VaultError::Locked);
    }
    db.replace_pin_wrapper(&integrity_key, &stored, params, &request_id)?;
    log::info!("vault_change_pin: PIN replaced");
    Ok(())
}
