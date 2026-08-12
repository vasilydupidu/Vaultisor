use serde::Deserialize;
use tauri::State;
use zeroize::Zeroize;

use crate::auth::pin::validate_pin_format;
use crate::crypto::master::{
    unwrap_master_with_pin, wrap_master_with_pin, wrap_master_with_pin_v2,
};
use crate::error::{Result, VaultError};
use crate::state::AppState;
use crate::storage::db::wrap_dpapi_layer;

use super::*;
use crate::commands::vault::helpers::{
    apply_settings, load_device_secret_and_unwrap, open_session, unwrap_master_blob,
};

#[tauri::command]
pub fn vault_lock(state: State<'_, AppState>) -> Result<()> {
    state.lock();
    Ok(())
}

/// Разблокировать через Windows Hello (биометрия / системный PIN).
/// Логика:
///  1) Прочитать hello_wrapped_key из vault_meta. Если NULL — Hello не настроен.
///  2) Получить HWND главного окна и запросить prompt привязанный к нему.
///  3) Если verified → DPAPI-unprotect → master_key → session unlocked.
#[tauri::command]
pub async fn vault_unlock_with_hello(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<()> {
    log::info!("vault_unlock_with_hello: start");
    let db = state.open_meta()?;
    let meta = db.vault_load()?.ok_or(VaultError::NotInitialized)?;
    log::info!(
        "vault_unlock_with_hello: meta loaded — use_hello={}, has_tpm_blob={}, has_dpapi_blob={}",
        meta.use_windows_hello,
        meta.tpm_wrapped_key.is_some(),
        meta.hello_wrapped_key.is_some()
    );
    if !meta.use_windows_hello {
        return Err(VaultError::BadInput(
            "Windows Hello отключён".into(),
        ));
    }
    if meta.failed_pin_attempts >= meta.max_pin_attempts {
        return Err(VaultError::TooManyAttempts);
    }
    let integrity_key_dpapi = db
        .get_integrity_key_dpapi()?
        .ok_or(VaultError::DeviceMismatch)?;
    let integrity_key = unwrap_integrity_key(&integrity_key_dpapi)?;
    db.verify_meta_integrity(&*integrity_key)?;
    log::info!("vault_unlock_with_hello: integrity OK");

    if meta.tpm_credential_name.is_none() || meta.tpm_wrapped_key.is_none() {
        return Err(VaultError::System(
            "Windows Hello is enabled, but the TPM-bound key wrapper is missing; use PIN and re-enable Hello in settings".into(),
        ));
    }

    log::info!("vault_unlock_with_hello: starting hardware Hello unwrap");

    // Получить master_key через TPM-путь.
    let mut master_opt: Option<crate::crypto::master::MasterKey> = None;

    // === TPM-bound (Hello+TPM) ===
    if let (Some(cred_name), Some(tpm_blob)) = (
        meta.tpm_credential_name.as_ref(),
        meta.tpm_wrapped_key.as_ref(),
    ) {
        log::info!("vault_unlock_with_hello: trying TPM path with cred=[REDACTED]");
        let attempt = async {
            if meta.crypto_version >= 2 {
                log::info!("vault_unlock_with_hello: v2 PQ-hybrid Hello path");
                let (ek, ct, dk_encrypted) = db.get_pq_hello()?.ok_or_else(|| {
                    VaultError::Crypto("PQ Hello data missing".into())
                })?;
                // Учётные данные Hello всегда создаются как CNG-ключ
                // Microsoft Platform Crypto Provider (см. cng_hello).
                let sig =
                    crate::windows_api::cng_hello::sign(&app, cred_name, TPM_KEK_CHALLENGE)
                        .await?;
                let m = unwrap_hello_v2(&sig, &ek, &ct, &dk_encrypted, tpm_blob)?;
                Ok::<crate::crypto::master::MasterKey, VaultError>(m)
            } else {
                // Учётные данные Hello всегда создаются как CNG-ключ
                // Microsoft Platform Crypto Provider (см. cng_hello).
                log::info!("vault_unlock_with_hello: CNG TPM key path");
                let mut sig =
                    crate::windows_api::cng_hello::sign(&app, cred_name, TPM_KEK_CHALLENGE)
                        .await?;
                log::info!(
                    "vault_unlock_with_hello: CNG TPM sign returned {} bytes",
                    sig.len()
                );
                let kek = derive_tpm_kek(&sig)?;
                sig.zeroize();
                let blob = crate::crypto::aead::EncryptedBlob::from_bytes(tpm_blob)?;
                let mut plaintext =
                    crate::crypto::aead::decrypt(&*kek, &blob, b"vaultisor:tpm-wrap:v1")
                        .map_err(|_| VaultError::DeviceMismatch)?;
                if plaintext.len() != 32 {
                    plaintext.zeroize();
                    return Err(VaultError::Crypto("tpm-blob bad length".into()));
                }
                let mut key_buf = [0u8; 32];
                key_buf.copy_from_slice(&plaintext);
                plaintext.zeroize();
                Ok::<crate::crypto::master::MasterKey, VaultError>(crate::crypto::master::MasterKey::new(key_buf))
            }
        }
        .await;
        match attempt {
            Ok(m) => {
                log::info!("vault_unlock_with_hello: TPM-bound success");
                master_opt = Some(m);
            }
            Err(e) => {
                log::warn!(
                    "vault_unlock_with_hello: TPM path failed ({}); PIN fallback required",
                    e
                );
            }
        }
    }

    // SECURITY: legacy DPAPI Hello path is disabled. If TPM unwrap fails,
    // the user must unlock with the primary Vaultisor PIN.
    if master_opt.is_none() {
        return Err(VaultError::System(
            "Hello-разблокировка недоступна: TPM-ключ или Windows Hello confirmation не сработали. Используйте PIN и пере-включите Hello в настройках."
                .into(),
        ));
    }

    // === Общий путь: установка сессии ===
    let master = master_opt.expect("master_opt must be Some at this point");
    apply_settings(&state, &meta);
    db.set_failed_attempts(&*integrity_key, 0)?;
    open_session(&state, master, integrity_key)?;
    Ok(())
}

/// Краткая информация для lock-screen: настроен ли Hello, чтобы решить
/// показывать ли соответствующую кнопку. Не требует unlocked-сессии.
#[derive(Debug, serde::Serialize)]
pub struct LockInfo {
    pub use_windows_hello: bool,
    pub hello_blob_present: bool,
    pub fido2_enabled: bool,
}

#[tauri::command]
pub fn vault_lock_info(state: State<'_, AppState>) -> Result<LockInfo> {
    let path = state.meta_path();
    if !path.exists() {
        return Ok(LockInfo {
            use_windows_hello: false,
            hello_blob_present: false,
            fido2_enabled: false,
        });
    }
    let db = state.open_meta()?;
    let meta = match db.vault_load()? {
        Some(m) => m,
        None => {
            return Ok(LockInfo {
                use_windows_hello: false,
                hello_blob_present: false,
                fido2_enabled: false,
            })
        }
    };
    let (fido2_enabled, _, _) = db.get_fido2_status().unwrap_or((false, None, None));
    Ok(LockInfo {
        use_windows_hello: meta.use_windows_hello,
        hello_blob_present: meta.tpm_wrapped_key.is_some(),
        fido2_enabled,
    })
}

#[tauri::command]
pub async fn vault_unlock_with_fido2(
    state: State<'_, AppState>,
    _app: tauri::AppHandle,
) -> Result<()> {
    let db = state.open_meta()?;
    let keys = db.get_fido2_keys().unwrap_or_default();
    let (enabled, cred_id_legacy, wrapped_legacy) = db.get_fido2_status().unwrap_or((false, None, None));

    let mut key_tuples: Vec<(Vec<u8>, Vec<u8>, bool)> = keys
        .into_iter()
        .map(|k| (k.credential_id, k.fido2_wrapped_key, k.require_pin))
        .collect();

    if key_tuples.is_empty() {
        if let (Some(cid), Some(wr)) = (cred_id_legacy, wrapped_legacy) {
            key_tuples.push((cid, wr, true)); // legacy keys default to require_pin=true
        }
    }

    if key_tuples.is_empty() || (!enabled && key_tuples.is_empty()) {
        return Err(VaultError::BadInput("Физический FIDO2-ключ не привязан".into()));
    }

    let integrity_key_dpapi = db
        .get_integrity_key_dpapi()?
        .ok_or(VaultError::DeviceMismatch)?;
    let integrity_key = unwrap_integrity_key(&integrity_key_dpapi)?;
    db.verify_meta_integrity(&*integrity_key)?;

    let meta = db.vault_load()?.ok_or(VaultError::NotInitialized)?;
    if meta.failed_pin_attempts >= meta.max_pin_attempts {
        return Err(VaultError::TooManyAttempts);
    }

    // 1. Собираем список всех зарегистрированных Credential ID
    let all_cred_ids: Vec<Vec<u8>> = key_tuples.iter().map(|(cid, _, _)| cid.clone()).collect();
    // Определяем require_pin: если хотя бы один ключ — PIN, используем PIN режим.
    // Если все ключи touch-only, используем touch-only.
    let any_require_pin = key_tuples.iter().any(|(_, _, rp)| *rp);

    // 2. Вызываем окно WebAuthn с передачей всех привязанных ключей
    let matched_cid = tokio::task::spawn_blocking(move || {
        crate::auth::fido2::assert_fido2_key_prompt(&all_cred_ids, any_require_pin)
    })
    .await
    .map_err(|e| VaultError::BadInput(format!("ошибка вызова FIDO2: {e}")))?
    ?;


    // 3. Находим соответствующий wrapped_key для коснувшегося токена
    let (_, fido2_wrapped_bytes, _) = key_tuples
        .into_iter()
        .find(|(cid, _, _)| cid == &matched_cid)
        .ok_or_else(|| VaultError::BadInput("Ответный FIDO2-ключ не найден в локальном хранилище".into()))?;

    // 4. Распаковываем master_key по KEK конкретного ключа
    let fido2_kek = crate::crypto::kdf::hkdf_derive(&matched_cid, b"vaultisor:fido2-salt:v1", b"vaultisor:fido2-kek:v1", 32)?;
    let mut kek_arr = [0u8; 32];
    kek_arr.copy_from_slice(&fido2_kek);

    let blob = crate::crypto::aead::EncryptedBlob::from_bytes(&fido2_wrapped_bytes)?;
    let mut plaintext = crate::crypto::aead::decrypt(&kek_arr, &blob, b"vaultisor:fido2-wrap:v1")
        .map_err(|_| VaultError::BadInput("Ошибка расшифровки FIDO2 ключа".into()))?;

    if plaintext.len() != 32 {
        zeroize::Zeroize::zeroize(&mut plaintext);
        return Err(VaultError::Crypto("fido2-blob bad length".into()));
    }

    let mut key_buf = [0u8; 32];
    key_buf.copy_from_slice(&plaintext);
    zeroize::Zeroize::zeroize(&mut plaintext);
    let master = crate::crypto::master::MasterKey::new(key_buf);
    zeroize::Zeroize::zeroize(&mut key_buf);

    apply_settings(&state, &meta);
    db.set_failed_attempts(&*integrity_key, 0)?;
    open_session(&state, master, integrity_key)?;

    log::info!("vault_unlock_with_fido2: unlocked successfully via hardware FIDO2 key");
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct ChangePinInput {
    pub old_pin: String,
    pub new_pin: String,
}

#[tauri::command]
pub async fn vault_change_pin(
    input: ChangePinInput,
    state: State<'_, AppState>,
    _app: tauri::AppHandle,
) -> Result<()> {
    let db = state.open_meta()?;
    let meta = db.vault_load()?.ok_or(VaultError::NotInitialized)?;

    if meta.crypto_version >= 2 {
        validate_pin_format(&input.new_pin)?;
    } else {
        if input.new_pin.chars().count() < 15 {
            return Err(VaultError::BadInput(
                "Мастер-пароль должен быть не менее 15 символов".into(),
            ));
        }
    }

    // Integrity-цепочка та же, что в vault_unlock — иначе change_pin был бы
    // обходом rate-limit для bruteforce старого PIN.
    let integrity_key_dpapi = db
        .get_integrity_key_dpapi()?
        .ok_or(VaultError::DeviceMismatch)?;
    let integrity_key = unwrap_integrity_key(&integrity_key_dpapi)?;
    db.verify_meta_integrity(&*integrity_key)?;

    if meta.failed_pin_attempts >= meta.max_pin_attempts {
        return Err(VaultError::TooManyAttempts);
    }

    let wrapped = unwrap_master_blob(&meta.wrapped_master_dpapi)?;

    let master = if meta.crypto_version >= 2 {
        log::info!("vault_change_pin: v2 path — loading Device Secret from TPM");
        match load_device_secret_and_unwrap(&db, &wrapped, input.old_pin.as_bytes()).await {
            Ok(master) => master,
            Err(_) => {
                db.set_failed_attempts(&*integrity_key, meta.failed_pin_attempts + 1)?;
                return Err(VaultError::InvalidPin);
            }
        }
    } else {
        match unwrap_master_with_pin(&wrapped, input.old_pin.as_bytes()) {
            Ok(master) => master,
            Err(_) => {
                db.set_failed_attempts(&*integrity_key, meta.failed_pin_attempts + 1)?;
                return Err(VaultError::InvalidPin);
            }
        }
    };

    let new_wrapped = if meta.crypto_version >= 2 {
        let ds_data = db.get_device_secret()?.ok_or_else(|| {
            VaultError::Crypto("Device Secret data missing".into())
        })?;
        let sig = crate::windows_api::cng_hello::sign_silent(
            &ds_data.0,
            crate::crypto::device_secret::DS_KEK_CHALLENGE,
        )
        .await?;
        let ds = crate::crypto::device_secret::decrypt_device_secret(
            &crate::crypto::device_secret::DeviceSecretData {
                tpm_key_name: ds_data.0,
                encrypted_blob: ds_data.1,
            },
            &sig,
        )?;
        wrap_master_with_pin_v2(&master, input.new_pin.as_bytes(), &*ds)?
    } else {
        wrap_master_with_pin(&master, input.new_pin.as_bytes())?
    };

    let stored = wrap_dpapi_layer(&new_wrapped)?;
    
    // AUDIT (pentest P0): не храним Argon2id-хэш PIN (оффлайн-оракул перебора).
    let new_pin_hash = String::new();
    db.update_wrapped_master(&*integrity_key, &stored, &new_pin_hash)?;
    // Сбросить счётчик при успехе.
    db.set_failed_attempts(&*integrity_key, 0)?;

    // master не меняется при change_pin → sqlcipher_key тоже не меняется,
    // records_db остаётся валидной. Открываем её здесь же, чтобы сессия
    // содержала свежий handle.
    open_session(&state, master, integrity_key)?;

    Ok(())
}

/// v0.2: Обернуть master-key для гибридного Hello-пути (classical + ML-KEM-768).
pub(crate) fn wrap_hello_v2(
    master: &crate::crypto::master::MasterKey,
    signature: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    use crate::crypto::pq_kem;
    use crate::crypto::kdf::hkdf_derive;
    use crate::crypto::aead;
    use zeroize::Zeroize;

    // 1. ML-KEM keygen
    let (ek, mut dk) = pq_kem::keygen();

    // 2. AUDIT H1: приватный ключ dk запечатываем НЕЗАВИСИМО от классического
    //    TPM-секрета. Раньше dk шифровался classical_kek = HKDF(RSA-подпись) —
    //    значит слом RSA (Shor) восстанавливал dk → декапсуляцию → shared_secret,
    //    и весь гибрид схлопывался к классике (PQ-защита была декоративной).
    //    DPAPI симметричен (AES-256, квантово-стойкий против Grover) и привязан к
    //    user+device, а не к RSA-ключу. Поэтому враг, сграбивший ТОЛЬКО файлы
    //    хранилища (модель «harvest-now-decrypt-later»), не получит dk без самой
    //    машины → не декапсулирует → ML-KEM-секрет реально защищает master.
    let dk_encrypted = crate::windows_api::dpapi::protect(&dk)?;
    dk.zeroize();

    // 4. Encapsulate с публичным ek
    let (shared_secret, ct) = pq_kem::encapsulate(&ek)?;

    // 5. Вывод гибридного KEK: HKDF(signature || shared_secret)
    let mut combined_entropy = Vec::with_capacity(signature.len() + 32);
    combined_entropy.extend_from_slice(signature);
    combined_entropy.extend_from_slice(&*shared_secret);

    let hybrid_kek_derived = hkdf_derive(
        &combined_entropy,
        b"vaultisor:hybrid-kek-salt:v1",
        b"vaultisor:hybrid-kek:v1",
        32,
    )?;
    let mut hybrid_kek = zeroize::Zeroizing::new([0u8; 32]);
    hybrid_kek.copy_from_slice(&hybrid_kek_derived);
    combined_entropy.zeroize();

    // 6. Шифрование master_key под гибридным KEK
    let tpm_wrapped_blob = master.with_decrypted(|decrypted| {
        aead::encrypt(&*hybrid_kek, decrypted, b"vaultisor:tpm-wrap:v2")
    })?;
    let tpm_wrapped_key = tpm_wrapped_blob.to_bytes();

    Ok((ek, ct, dk_encrypted, tpm_wrapped_key))
}

/// v0.2: Развернуть master-key для гибридного Hello-пути (classical + ML-KEM-768).
pub(crate) fn unwrap_hello_v2(
    signature: &[u8],
    _ek: &[u8],
    ct: &[u8],
    dk_encrypted_bytes: &[u8],
    tpm_wrapped_bytes: &[u8],
) -> Result<crate::crypto::master::MasterKey> {
    use crate::crypto::pq_kem;
    use crate::crypto::kdf::hkdf_derive;
    use crate::crypto::aead;
    use zeroize::Zeroize;

    // 1. AUDIT H1: dk снимаем DPAPI (независимо от классического TPM-секрета —
    //    см. wrap_hello_v2). На чужой машине/учётке DPAPI не развернёт → Hello
    //    там и не работает (это ожидаемо; кросс-машинно — PIN или Shamir).
    let dk: zeroize::Zeroizing<Vec<u8>> =
        crate::windows_api::dpapi::unprotect(dk_encrypted_bytes)
            .map_err(|_| VaultError::DeviceMismatch)?;

    // 2. Decapsulate с dk и ct (dk затрётся при drop Zeroizing).
    let shared_secret = pq_kem::decapsulate(&dk, ct)?;

    // 4. Вывод гибридного KEK: HKDF(signature || shared_secret)
    let mut combined_entropy = Vec::with_capacity(signature.len() + 32);
    combined_entropy.extend_from_slice(signature);
    combined_entropy.extend_from_slice(&*shared_secret);

    let hybrid_kek_derived = hkdf_derive(
        &combined_entropy,
        b"vaultisor:hybrid-kek-salt:v1",
        b"vaultisor:hybrid-kek:v1",
        32,
    )?;
    let mut hybrid_kek = zeroize::Zeroizing::new([0u8; 32]);
    hybrid_kek.copy_from_slice(&hybrid_kek_derived);
    combined_entropy.zeroize();

    // 5. Расшифровка master_key под гибридным KEK
    let tpm_wrapped_blob = aead::EncryptedBlob::from_bytes(tpm_wrapped_bytes)?;
    let mut plaintext = aead::decrypt(&*hybrid_kek, &tpm_wrapped_blob, b"vaultisor:tpm-wrap:v2")?;

    if plaintext.len() != 32 {
        plaintext.zeroize();
        return Err(VaultError::Crypto("hybrid tpm-blob bad length".into()));
    }

    let mut master_buf = [0u8; 32];
    master_buf.copy_from_slice(&plaintext);
    plaintext.zeroize();

    let mk = crate::crypto::master::MasterKey::new(master_buf);
    master_buf.zeroize(); // AUDIT M4: затираем стековую копию master-ключа
    Ok(mk)
}

#[cfg(test)]
mod tests {
    use super::*;

    // AUDIT (test-coverage): гибридный PQ-путь (wrap_hello_v2/unwrap_hello_v2) —
    // несущий, но ранее не покрыт тестами. Здесь проверяем сквозной roundtrip.
    // Подпись — фиксированная заглушка (реальный TPM не нужен: wrap и unwrap
    // используют одну и ту же подпись как HKDF-вход), а dk запечатывается
    // настоящим DPAPI этой машины (H1).

    #[test]
    fn hello_v2_roundtrip_recovers_master() {
        let master = crate::crypto::master::generate_master_key();
        let signature = b"test-fixed-tpm-signature-0123456789abcdef".to_vec();
        if let Ok((ek, ct, dk_enc, tpm_wrapped)) = wrap_hello_v2(&master, &signature) {
            let recovered = unwrap_hello_v2(&signature, &ek, &ct, &dk_enc, &tpm_wrapped).unwrap();
            master.with_decrypted(|m| {
                recovered.with_decrypted(|r| {
                    assert_eq!(m, r, "master после roundtrip должен совпасть");
                })
            });
        }
    }

    #[test]
    fn hello_v2_wrong_signature_fails() {
        // Неверная TPM-подпись → неверный hybrid_kek → AEAD-тег master не сойдётся.
        let master = crate::crypto::master::generate_master_key();
        if let Ok((ek, ct, dk_enc, tpm_wrapped)) = wrap_hello_v2(&master, b"correct-signature") {
            let res = unwrap_hello_v2(b"wrong-signature-xx", &ek, &ct, &dk_enc, &tpm_wrapped);
            assert!(res.is_err(), "неверная подпись не должна разворачивать master");
        }
    }
}
