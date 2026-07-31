use crate::error::{Result, VaultError};
use crate::state::AppState;
use crate::storage::meta_db::MetaDb;

pub(crate) async fn load_device_secret_and_unwrap(
    db: &MetaDb,
    wrapped: &crate::crypto::master::WrappedKey,
    pin: &[u8],
) -> Result<crate::crypto::master::MasterKey> {
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
    crate::crypto::master::unwrap_master_with_pin_v2(wrapped, pin, &*ds)
}

pub(crate) fn unwrap_master_blob(
    wrapped_master_dpapi: &[u8],
) -> Result<crate::crypto::master::WrappedKey> {
    match crate::storage::db::unwrap_dpapi_layer(wrapped_master_dpapi) {
        Ok(w) => Ok(w),
        Err(_) => crate::crypto::master::WrappedKey::from_bytes(wrapped_master_dpapi)
            .map_err(|_| VaultError::DeviceMismatch),
    }
}

pub(crate) fn open_session(
    state: &AppState,
    master: crate::crypto::master::MasterKey,
    integrity_key: zeroize::Zeroizing<[u8; 32]>,
) -> Result<()> {
    let sqlcipher_key = master.with_decrypted(|decrypted| crate::storage::records_db::derive_sqlcipher_key(decrypted))?;
    let records_db = crate::storage::records_db::RecordsDb::open(&state.records_path(), &sqlcipher_key)?;
    let web_sqlcipher_key = master.with_decrypted(|decrypted| crate::storage::records_db::derive_web_sqlcipher_key(decrypted))?;
    let web_db = crate::storage::records_db::RecordsDb::open(&state.web_path(), &web_sqlcipher_key)?;

    crate::storage::records::migrate_field_encryption(&records_db, &master)?;
    crate::storage::records::migrate_field_encryption(&web_db, &master)?;

    let mut s = state.session.lock();
    *s = crate::state::SessionState::Unlocked {
        master_key: master,
        integrity_key,
        records_db,
        web_db,
        unlocked_at: std::time::Instant::now(),
        last_activity: std::time::Instant::now(),
        auth_verified_at: None,
    };
    Ok(())
}

pub(crate) fn apply_settings(
    state: &AppState,
    meta: &crate::storage::meta_db::VaultMetaRow,
) {
    let mut s = state.settings.lock();
    *s = crate::state::VaultSettings {
        autolock_seconds: meta.autolock_seconds,
        clipboard_clear_seconds: meta.clipboard_clear_seconds,
        require_auth_for_copy: meta.require_auth_for_copy,
        use_windows_hello: meta.use_windows_hello,
        max_pin_attempts: meta.max_pin_attempts,
    };
}
