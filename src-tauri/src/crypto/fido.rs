//! Конверт мастер-ключа под FIDO2-ключом, привязанный к устройству.
//!
//! Гарантия: вход без PIN по FIDO2 работает только при одновременном наличии
//!
//! ```text
//! этого аутентификатора (PRF/hmac-secret)
//! + этой учётной записи Windows (DPAPI)
//! + этого ПК (Device Secret из TPM)
//! ```
//!
//! KEK = HKDF-SHA256(PRF ‖ DeviceSecret, соль домена, info ‖ credential id).
//! Device Secret — главный машинный фактор: он получается только подписью
//! неэкспортируемого TPM-ключа этого ПК. Поверх AES-GCM-конверта — DPAPI
//! (CurrentUser) с энтропией хранилища: привязка к учётной записи.
//!
//! Скопированные на другой ПК файлы хранилища вместе с тем же токеном
//! мастер-ключ не дают: без TPM исходного ПК нет Device Secret. PIN Vaultisor
//! при этом не нужен — Device Secret получается автоматически.

use zeroize::{Zeroize, Zeroizing};

use crate::crypto::aead::{self, EncryptedBlob};
use crate::crypto::master::MasterKey;
use crate::error::{Result, VaultError};

const KEK_SALT: &[u8] = b"vaultisor:fido2-kek-salt:v3";
const KEK_INFO: &[u8] = b"vaultisor:fido2-kek:v3:";
const WRAP_AAD: &[u8] = b"vaultisor:fido2-wrap:v3";

fn kek(prf: &[u8], device_secret: &[u8; 32], credential_id: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if prf.len() != 32 {
        return Err(VaultError::FidoFailed("PRF-выход неверной длины".into()));
    }
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(prf);
    ikm.extend_from_slice(device_secret);
    let mut info = Vec::with_capacity(KEK_INFO.len() + credential_id.len());
    info.extend_from_slice(KEK_INFO);
    info.extend_from_slice(credential_id);
    let derived = crate::crypto::kdf::hkdf_derive(&ikm, KEK_SALT, &info, 32)?;
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&derived);
    Ok(key)
}

/// Запечатать мастер-ключ под FIDO2-ключом этого устройства.
pub fn wrap_master(
    master: &MasterKey,
    prf: &[u8],
    device_secret: &[u8; 32],
    credential_id: &[u8],
    dpapi_entropy: &[u8],
) -> Result<Vec<u8>> {
    let key = kek(prf, device_secret, credential_id)?;
    let blob = master.with_decrypted(|plain| aead::encrypt(&key, plain, WRAP_AAD))?;
    crate::windows_api::dpapi::protect_with_entropy(&blob.to_bytes(), dpapi_entropy)
}

/// Развернуть мастер-ключ. Неверный PRF, чужой Device Secret, чужой
/// credential id или чужая учётная запись Windows — отказ.
pub fn unwrap_master(
    stored: &[u8],
    prf: &[u8],
    device_secret: &[u8; 32],
    credential_id: &[u8],
    dpapi_entropy: &[u8],
) -> Result<MasterKey> {
    let sealed = crate::windows_api::dpapi::unprotect_with_entropy(stored, dpapi_entropy)
        .map_err(|_| VaultError::DeviceMismatch)?;
    let blob = EncryptedBlob::from_bytes(&sealed)?;
    let key = kek(prf, device_secret, credential_id)?;
    let mut plain = aead::decrypt(&key, &blob, WRAP_AAD).map_err(|_| {
        VaultError::FidoFailed("ключ FIDO2 не подходит к этому хранилищу на этом устройстве".into())
    })?;
    if plain.len() != 32 {
        plain.zeroize();
        return Err(VaultError::Crypto("fido2 blob has wrong length".into()));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&plain);
    plain.zeroize();
    let master = MasterKey::new(buf);
    buf.zeroize();
    Ok(master)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTROPY: &[u8] = b"per-vault-dpapi-entropy-32-bytes";

    #[test]
    fn only_the_same_token_device_and_credential_unwrap() {
        let master = crate::crypto::master::generate_master_key();
        let prf = [0x11u8; 32];
        let device = [0x22u8; 32];
        let credential = b"credential-1";
        let stored = wrap_master(&master, &prf, &device, credential, ENTROPY).unwrap();

        let opened = unwrap_master(&stored, &prf, &device, credential, ENTROPY).unwrap();
        master.with_decrypted(|a| opened.with_decrypted(|b| assert_eq!(a, b)));

        // Тот же токен на другом ПК: другой Device Secret.
        assert!(unwrap_master(&stored, &prf, &[0x23u8; 32], credential, ENTROPY).is_err());
        // Другой токен.
        assert!(unwrap_master(&stored, &[0x12u8; 32], &device, credential, ENTROPY).is_err());
        // Конверт от другого credential'а.
        assert!(unwrap_master(&stored, &prf, &device, b"credential-2", ENTROPY).is_err());
        // Другая энтропия DPAPI (другое хранилище).
        assert!(unwrap_master(&stored, &prf, &device, credential, b"another-vault").is_err());
    }

    #[test]
    fn stored_wrapper_is_not_a_bare_aead_blob() {
        let master = crate::crypto::master::generate_master_key();
        let stored = wrap_master(&master, &[1; 32], &[2; 32], b"c", ENTROPY).unwrap();
        // Без DPAPI этой учётной записи конверт даже не разбирается.
        let blob = EncryptedBlob::from_bytes(&stored).unwrap();
        let key = kek(&[1; 32], &[2; 32], b"c").unwrap();
        assert!(aead::decrypt(&key, &blob, WRAP_AAD).is_err());
    }
}
