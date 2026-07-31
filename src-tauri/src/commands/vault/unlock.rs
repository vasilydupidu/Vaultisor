use serde::Deserialize;
use tauri::State;

use crate::crypto::master::unwrap_master_with_pin;
use crate::error::{Result, VaultError};
use crate::state::AppState;

use super::*;
use crate::commands::vault::helpers::{
    apply_settings, load_device_secret_and_unwrap, open_session, unwrap_master_blob,
};

#[derive(Debug, Deserialize)]
pub struct VaultUnlockInput {
    pub pin: String,
}

#[tauri::command]
pub async fn vault_unlock(
    input: VaultUnlockInput,
    state: State<'_, AppState>,
    _app: tauri::AppHandle,
) -> Result<()> {
    let db = state.open_meta()?;
    let meta = db.vault_load()?.ok_or(VaultError::NotInitialized)?;

    // Шаг 1 — DPAPI-unwrap integrity_key (раньше всех остальных проверок).
    // Если integrity_key_dpapi отсутствует или unprotect провалился — это
    // указывает на перенос БД на другую машину или legacy-БД без интегрити.
    let integrity_key_dpapi = db
        .get_integrity_key_dpapi()?
        .ok_or(VaultError::DeviceMismatch)?;
    let integrity_key = unwrap_integrity_key(&integrity_key_dpapi)?;

    // Шаг 2 — Проверка целостности vault_meta. Если кто-то отредактировал
    // БД (обнулил failed_pin_attempts, поднял max_pin_attempts и т.п.),
    // MAC не совпадёт → блокируемся до восстановления через Shamir.
    db.verify_meta_integrity(&*integrity_key)?;

    // Шаг 3 — Лимит попыток. Persistent в БД, защищён HMAC.
    if meta.failed_pin_attempts >= meta.max_pin_attempts {
        log::warn!("vault_unlock blocked: failed attempts limit reached");
        return Err(VaultError::TooManyAttempts);
    }

    // Шаг 4 — PIN проверяется КРИПТОГРАФИЧЕСКИ ниже: неверный PIN → неверный
    // KEK → AEAD-разворот мастера падает (InvalidPin). Отдельный pin_hash НЕ
    // используется (и больше не хранится — pentest P0: был оффлайн-оракул).
    // Шаг 5 — DPAPI-снятие master-обёртки.
    let wrapped = unwrap_master_blob(&meta.wrapped_master_dpapi)?;

    // Шаг 6 — AES-GCM unwrap с Device Secret (или v1 legacy).
    let master = if meta.crypto_version >= 2 {
        log::info!("vault_unlock: v2 path — loading Device Secret from TPM");
        match load_device_secret_and_unwrap(&db, &wrapped, input.pin.as_bytes()).await {
            Ok(master) => master,
            Err(_) => {
                log::warn!(
                    "vault_unlock: invalid PIN (v2), attempts={}/{}",
                    meta.failed_pin_attempts + 1,
                    meta.max_pin_attempts
                );
                db.set_failed_attempts(&*integrity_key, meta.failed_pin_attempts + 1)?;
                return Err(VaultError::InvalidPin);
            }
        }
    } else {
        match unwrap_master_with_pin(&wrapped, input.pin.as_bytes()) {
            Ok(master) => master,
            Err(_) => {
                log::warn!(
                    "vault_unlock: invalid PIN (v1), attempts={}/{}",
                    meta.failed_pin_attempts + 1,
                    meta.max_pin_attempts
                );
                db.set_failed_attempts(&*integrity_key, meta.failed_pin_attempts + 1)?;
                return Err(VaultError::InvalidPin);
            }
        }
    };

    // Шаг 7 — Сброс счётчика, открытие records-БД, установка сессии.
    db.set_failed_attempts(&*integrity_key, 0)?;
    apply_settings(&state, &meta);
    log::info!("vault_unlock: success");
    open_session(&state, master, integrity_key)?;

    Ok(())
}

/// Стабильный challenge для TPM-подписи. Детерминированный (RSASSA-PKCS#1-v1.5
/// без random salt) → одинаковая подпись при одинаковом challenge → стабильный KEK.
pub(crate) const TPM_KEK_CHALLENGE: &[u8] = b"vaultisor:tpm-master-kek-challenge:v1";

/// Деривируем 32-байтовый KEK из подписи TPM через HKDF-SHA256.
/// MED-NEW-01: возвращаем Zeroizing<[u8;32]>, derived (Vec) явно zeroize.
/// pub(crate): используется также в settings.rs при включении Hello.
pub(crate) fn derive_tpm_kek(signature: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    use crate::crypto::kdf::hkdf_derive;
    let derived = hkdf_derive(
        signature,
        b"vaultisor:tpm-kek-salt:v1",
        b"vaultisor:tpm-kek:v1",
        32,
    )?;
    let mut kek = zeroize::Zeroizing::new([0u8; 32]);
    kek.copy_from_slice(&derived);
    // derived is Zeroizing<Vec<u8>> — auto-zeroizes on drop.
    Ok(kek)
}
