use serde::Deserialize;
use tauri::State;

use crate::auth::pin::validate_pin_format;
use crate::crypto::kdf;
use crate::crypto::master::{generate_master_key, wrap_master_with_pin, wrap_master_with_pin_v2};
use crate::crypto::shamir::split_secret;
use crate::error::{Result, VaultError};
use crate::state::{AppState, SessionState, VaultSettings};
use crate::storage::db::wrap_dpapi_layer;

use super::*;
use crate::commands::vault::helpers::open_session;

#[derive(Debug, Deserialize)]
pub struct VaultCreateInput {
    pub pin: String,
    /// Если задан — поверх PIN-обёртки добавляется ещё DPAPI-слой
    /// (рекомендуется на Windows).
    pub use_dpapi: bool,
    /// Сразу включить Hello (флаг сохранится в settings).
    pub use_windows_hello: bool,
    pub autolock_seconds: Option<u32>,
    pub clipboard_clear_seconds: Option<u32>,
}

/// Результат создания хранилища: возвращаются 3 Shamir-доли в hex,
/// чтобы фронт мог показать пользователю QR/копию для ручного бэкапа.
/// Доля A сразу сохранена локально (DPAPI), В возвращается фронту
/// для записи на USB по выбору пользователя, С — для бумажного бэкапа.
#[derive(Debug, serde::Serialize)]
pub struct VaultCreateOutput {
    pub recovery_share_b_hex: String, // для USB
    pub recovery_share_c_hex: String, // для пользователя (бумага/QR)
}

#[tauri::command]
pub async fn vault_create(
    input: VaultCreateInput,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<VaultCreateOutput> {
    log::info!(
        "vault_create: start (use_dpapi={}, use_hello={})",
        input.use_dpapi,
        input.use_windows_hello
    );
    let res = vault_create_inner(input, &state, &app).await;
    if let Err(ref e) = res {
        log::error!("vault_create FAILED: {}", e);
        // Откат: удаляем созданные файлы, чтобы при следующем запуске
        // онбординг показался заново и пользователь мог попробовать снова.
        let meta = state.meta_path();
        let records = state.records_path();
        if meta.exists() {
            log::warn!("vault_create rollback: removing {}", meta.display());
            let _ = std::fs::remove_file(&meta);
            let _ = std::fs::remove_file(meta.with_extension("db-wal"));
            let _ = std::fs::remove_file(meta.with_extension("db-shm"));
        }
        if records.exists() {
            log::warn!("vault_create rollback: removing {}", records.display());
            let _ = std::fs::remove_file(&records);
            let _ = std::fs::remove_file(records.with_extension("db-wal"));
            let _ = std::fs::remove_file(records.with_extension("db-shm"));
        }
        // Сессия не должна быть в Unlocked при ошибке.
        let mut s = state.session.lock();
        *s = SessionState::Locked;
    } else {
        log::info!("vault_create: success");
    }
    res
}

async fn vault_create_inner(
    input: VaultCreateInput,
    state: &State<'_, AppState>,
    app: &tauri::AppHandle,
) -> Result<VaultCreateOutput> {
    let tpm_supported = crate::windows_api::cng_hello::is_supported();

    if tpm_supported {
        validate_pin_format(&input.pin)?;
    } else {
        if input.pin.chars().count() < 15 {
            return Err(VaultError::BadInput(
                "Мастер-пароль должен быть не менее 15 символов".into(),
            ));
        }
    }

    log::info!("vault_create step 1: opening meta_db");
    let db = state.open_meta()?;
    if db.vault_initialized()? {
        return Err(VaultError::BadInput(
            "Хранилище уже создано. Используйте разблокировку.".into(),
        ));
    }

    log::info!("vault_create step 2: generating master_key");
    let master = generate_master_key();

    let wrapped_res = if tpm_supported {
        // v0.2: создать Device Secret через TPM.
        log::info!("vault_create step 3: creating Device Secret (TPM-only)");
        let device_secret: zeroize::Zeroizing<[u8; 32]>;
        let ds_data: crate::crypto::device_secret::DeviceSecretData;
        
        // Создать TPM-ключ и подписать challenge для Device Secret KEK.
        let ds_cred = crate::windows_api::cng_hello::create_and_sign_silent(
            crate::crypto::device_secret::DS_KEK_CHALLENGE,
        )
        .await?;
        let (ds, data) = crate::crypto::device_secret::generate_and_encrypt(
            &ds_cred.stored_id,
            &ds_cred.signature,
        )?;
        device_secret = ds;
        ds_data = data;

        log::info!(
            "vault_create step 4: wrap with PIN + Device Secret (Argon2id 512MB, ~2-3 сек)"
        );
        let wrapped = wrap_master_with_pin_v2(&master, input.pin.as_bytes(), &*device_secret)?;
        Ok::<(crate::crypto::master::WrappedKey, Option<crate::crypto::device_secret::DeviceSecretData>), VaultError>((wrapped, Some(ds_data)))
    } else {
        log::info!(
            "vault_create step 4: Soft-Sealing wrap with passphrase (no TPM)"
        );
        let wrapped = wrap_master_with_pin(&master, input.pin.as_bytes())?;
        Ok((wrapped, None))
    }?;
    let (wrapped, ds_data) = wrapped_res;

    // v0.2: сохраняем DPAPI-обёртку поверх (integrity, не криптозащита —
    // реальная защита = Device Secret в TPM).
    let stored = if input.use_dpapi {
        wrap_dpapi_layer(&wrapped)?
    } else {
        wrapped.to_bytes()
    };

    // AUDIT (pentest P0): НЕ храним Argon2id-хэш PIN. Он лежал в открытой meta.db
    // (и в каждом бэкапе), но НИГДЕ не проверялся (argon2id_verify не вызывается) —
    // PIN проверяется криптографически через AEAD-разворот мастера. Это был
    // чистый ОФФЛАЙН-оракул перебора числового PIN из украденного бэкапа.
    let pin_hash = String::new();

    log::info!("vault_create step 6: integrity_key + DPAPI");
    let mut integrity_key = zeroize::Zeroizing::new([0u8; 32]);
    crate::crypto::rng::fill(integrity_key.as_mut_slice());
    let integrity_key_dpapi = crate::windows_api::dpapi::protect(&integrity_key[..])?;

    log::info!("vault_create step 7: insert vault_meta with HMAC");
    let autolock = input.autolock_seconds.unwrap_or(300);
    let clipboard_clear = input.clipboard_clear_seconds.unwrap_or(10);
    db.vault_create(
        &stored,
        &pin_hash,
        autolock,
        clipboard_clear,
        false,
        input.use_windows_hello && tpm_supported,
        10,
        &integrity_key_dpapi,
        &*integrity_key,
    )?;

    if let Some(ds) = ds_data {
        // v0.2: сохранить Device Secret в БД (имя TPM-ключа + зашифрованный blob).
        db.save_device_secret(
            &*integrity_key,
            &ds.tpm_key_name,
            &ds.encrypted_blob,
        )?;
    }
    // v0.2: сохранить параметры Argon2id.
    db.save_argon2_params(
        &*integrity_key,
        kdf::ARGON2_M_COST,
        kdf::ARGON2_T_COST,
        kdf::ARGON2_P_COST,
    )?;
    log::info!("vault_create: Device Secret + Argon2id params saved to DB");

    // Локальный флаг — реально ли Hello получился. Если TPM Sign упал,
    // мы сбрасываем use_windows_hello в БД, чтобы фронт не показывал
    // "лишнюю" кнопку Hello, которую нечем разблокировать.
    let mut hello_actually_enabled = input.use_windows_hello;
    log::info!(
        "vault_create step 8: Hello wrap (if enabled, use_hello={})",
        input.use_windows_hello
    );
    // SECURITY: DPAPI Hello fallback УДАЛЁН.
    //
    // Прошлый DPAPI fallback был уязвим к локальному stealer-malware:
    // DPAPI(CurrentUser) с константной entropy = ACL, а не криптография.
    // Любой код в той же сессии Windows мог вызвать CryptUnprotectData с
    // известной entropy "vaultisor:dpapi:v1" и получить master_key напрямую.
    //
    // Теперь Hello доступен ТОЛЬКО когда TPM Sign успешен (т.е. в Windows
    // настроен PIN/Fingerprint + Hello). На face-only Hello-машинах
    // RequestSign падает с 0x80098044 → Hello становится недоступен и
    // пользователь использует PIN. Это правильный trade-off:
    // неудобство UX < silent compromise.
    
    if input.use_windows_hello {
        if !tpm_supported {
            log::warn!(
                "vault_create: TPM не поддерживается → Hello будет недоступен. PIN-разблокировка работает как обычно."
            );
            hello_actually_enabled = false;
        } else {
            let mut cred_name = String::new();
            let tpm_attempt = async {
                log::info!("vault_create: starting CNG TPM key create+sign");

                // Combined Create+Sign в одном STA-thread'е —
                // обходим возможный per-apartment state issue.
                let credential =
                    crate::windows_api::cng_hello::create_and_sign(app, TPM_KEK_CHALLENGE)
                        .await?;
                cred_name = credential.stored_id;
                let (ek, ct, dk_encrypted, tpm_wrapped_key) =
                    wrap_hello_v2(&master, &credential.signature)?;
                db.save_tpm_wrap(&*integrity_key, &cred_name, &tpm_wrapped_key)?;
                db.save_pq_hello(&*integrity_key, &ek, &ct, &dk_encrypted)?;
                Ok::<(), VaultError>(())
            }
            .await;
            match tpm_attempt {
                Ok(()) => {
                    log::info!("vault_create: TPM-bound Hello wrap saved");
                }
                Err(e) => {
                    log::warn!(
                        "vault_create: TPM Hello path failed ({}). Hello will be disabled; use PIN. \
                            The Microsoft Platform Crypto Provider or Windows Hello confirmation failed.",
                        e
                    );
                    let _ = crate::windows_api::cng_hello::delete(&cred_name);
                    hello_actually_enabled = false;
                    // Сбрасываем флаг в БД, чтобы lock-screen не показывал
                    // несуществующую кнопку Hello.
                    let _ = db.update_settings(
                        &*integrity_key,
                        autolock,
                        clipboard_clear,
                        false,
                        false,
                        10,
                    );
                }
            }
        }
    }

    log::info!("vault_create step 9: Shamir 2-of-3 split");
    let shares = master.with_decrypted(|decrypted| {
        split_secret(decrypted, 2, 3)
    })?;
    let share_a = &shares[0];
    let share_b = &shares[1];
    let share_c = &shares[2];

    log::info!("vault_create step 10: saving recovery_local A");
    let y_dpapi = crate::windows_api::dpapi::protect(&share_a.y)?;
    db.save_recovery_local(share_a.x, &y_dpapi)?;

    // 9) Обновляем in-memory settings (использовать реальный флаг Hello).
    {
        let mut s = state.settings.lock();
        *s = VaultSettings {
            autolock_seconds: autolock,
            clipboard_clear_seconds: clipboard_clear,
            require_auth_for_copy: false,
            use_windows_hello: hello_actually_enabled,
            max_pin_attempts: 10,
        };
    }

    // 10) Сразу разблокируем сессию (счётчик попыток в свежей БД уже 0).
    open_session(&state, master, integrity_key)?;

    Ok(VaultCreateOutput {
        recovery_share_b_hex: format!("{}|{}", share_b.x, hex::encode(&share_b.y)),
        recovery_share_c_hex: format!("{}|{}", share_c.x, hex::encode(&share_c.y)),
    })
}
