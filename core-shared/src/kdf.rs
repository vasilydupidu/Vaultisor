// KDF: Argon2id для PIN/passphrase, HKDF-SHA256 для производных ключей.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{CoreError, Result};

/// Дефолтные параметры Argon2id для PIN.
pub const ARGON2_M_COST: u32 = 512 * 1024; // 512 МБ
pub const ARGON2_T_COST: u32 = 6;
pub const ARGON2_P_COST: u32 = 2;
pub const ARGON2_OUT_LEN: usize = 32;

/// Хешировать PIN/passphrase через Argon2id.
/// Возвращает PHC-строку.
pub fn argon2id_hash(passphrase: &[u8]) -> Result<String> {
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    let params = Params::new(
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(ARGON2_OUT_LEN),
    )
    .map_err(|e| CoreError::Crypto(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let hash = argon
        .hash_password(passphrase, &salt)
        .map_err(|e| CoreError::Crypto(format!("argon2 hash: {e}")))?;
    Ok(hash.to_string())
}

/// Проверить PIN/passphrase против ранее сохранённого PHC-хеша.
pub fn argon2id_verify(passphrase: &[u8], phc: &str) -> Result<bool> {
    let parsed =
        PasswordHash::new(phc).map_err(|e| CoreError::Crypto(format!("argon2 parse: {e}")))?;
    Ok(Argon2::default()
        .verify_password(passphrase, &parsed)
        .is_ok())
}

/// Произвести 32-байтовый ключ-шифрования-ключа (KEK) из passphrase + salt.
pub fn argon2id_derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| CoreError::Crypto(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase, salt, out.as_mut_slice())
        .map_err(|e| CoreError::Crypto(format!("argon2 derive: {e}")))?;
    Ok(out)
}

/// HKDF-SHA256 (extract-then-expand) — audited RustCrypto implementation.
pub fn hkdf_derive(secret: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Result<Zeroizing<Vec<u8>>> {
    use hkdf::Hkdf;

    let hk = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut out = vec![0u8; out_len];
    hk.expand(info, &mut out)
        .map_err(|_| CoreError::Crypto("hkdf expand: output too long".into()))?;
    Ok(Zeroizing::new(out))
}

/// Произвести KEK из PIN + device_secret через Argon2id.
pub fn argon2id_derive_key_v2(
    pin: &[u8],
    device_secret: &[u8; 32],
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut combined = Vec::with_capacity(pin.len() + 32);
    combined.extend_from_slice(pin);
    combined.extend_from_slice(device_secret);
    let result = argon2id_derive_key(&combined, salt);
    combined.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_hash_and_verify() {
        let pin = b"123456";
        let phc = argon2id_hash(pin).unwrap();
        assert!(argon2id_verify(pin, &phc).unwrap());
        assert!(!argon2id_verify(b"wrong", &phc).unwrap());
    }

    #[test]
    fn argon2_derive_deterministic_with_same_salt() {
        let salt = b"0123456789abcdef";
        let a = argon2id_derive_key(b"pin", salt).unwrap();
        let b = argon2id_derive_key(b"pin", salt).unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn hkdf_basic() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let out = hkdf_derive(&ikm, &salt, &info, 42).unwrap();
        let expected = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();
        assert_eq!(*out, expected);
    }
}
