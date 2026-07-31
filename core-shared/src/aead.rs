// AES-256-GCM на основе RustCrypto/aes-gcm.
//
// Формат blob'а:
//   [12 байт nonce] [N байт ciphertext+tag(16 байт)]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::rng;
use crate::error::{CoreError, Result};

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

/// Зашифрованный blob: nonce + ciphertext (с tag в конце).
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    /// 12-байтовый nonce.
    pub nonce: Vec<u8>,
    /// Шифротекст + GCM-tag в конце.
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for EncryptedBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedBlob")
            .field("nonce_len", &self.nonce.len())
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

impl EncryptedBlob {
    /// Сериализация в плоский байтовый массив.
    /// Layout: [12 nonce][rest ciphertext+tag].
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.nonce.len() + self.ciphertext.len());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < NONCE_LEN + TAG_LEN {
            return Err(CoreError::Crypto("encrypted blob too short".into()));
        }
        let (nonce, ciphertext) = bytes.split_at(NONCE_LEN);
        Ok(Self {
            nonce: nonce.to_vec(),
            ciphertext: ciphertext.to_vec(),
        })
    }
}

/// Шифрование с контекстной привязкой AAD.
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<EncryptedBlob> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CoreError::Crypto("invalid key length".into()))?;

    let nonce_bytes: [u8; NONCE_LEN] = rng::random_array();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(
        nonce,
        Payload {
            msg: plaintext,
            aad,
        },
    )?;

    Ok(EncryptedBlob {
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

/// Дешифрование с контекстной привязкой AAD.
pub fn decrypt(key: &[u8; KEY_LEN], blob: &EncryptedBlob, aad: &[u8]) -> Result<Vec<u8>> {
    if blob.nonce.len() != NONCE_LEN {
        return Err(CoreError::Crypto("bad nonce length".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CoreError::Crypto("invalid key length".into()))?;
    let nonce = Nonce::from_slice(&blob.nonce);
    let pt = cipher.decrypt(
        nonce,
        Payload {
            msg: &blob.ciphertext,
            aad,
        },
    )?;
    Ok(pt)
}

/// Вспомогательная функция: зашифровать UTF-8 строку.
pub fn encrypt_string(key: &[u8; KEY_LEN], plaintext: &str, aad: &[u8]) -> Result<EncryptedBlob> {
    encrypt(key, plaintext.as_bytes(), aad)
}

/// Вспомогательная функция: расшифровать UTF-8 строку.
pub fn decrypt_string(
    key: &[u8; KEY_LEN],
    blob: &EncryptedBlob,
    aad: &[u8],
) -> Result<zeroize::Zeroizing<String>> {
    let bytes = decrypt(key, blob, aad)?;
    match String::from_utf8(bytes) {
        Ok(s) => Ok(zeroize::Zeroizing::new(s)),
        Err(e) => {
            let mut original = e.into_bytes();
            original.zeroize();
            Err(CoreError::Crypto("invalid utf-8 in plaintext".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key32() -> [u8; KEY_LEN] {
        rng::random_array()
    }

    #[test]
    fn roundtrip_basic() {
        let key = key32();
        let pt = b"hello, vaultisor!";
        let blob = encrypt(&key, pt, b"").unwrap();
        let dec = decrypt(&key, &blob, b"").unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn roundtrip_with_aad() {
        let key = key32();
        let pt = b"secret value";
        let aad = b"record:42:field:api_key";
        let blob = encrypt(&key, pt, aad).unwrap();
        let dec = decrypt(&key, &blob, aad).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn aad_mismatch_fails() {
        let key = key32();
        let blob = encrypt(&key, b"x", b"aad-1").unwrap();
        assert!(decrypt(&key, &blob, b"aad-2").is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let blob = encrypt(&key32(), b"x", b"").unwrap();
        assert!(decrypt(&key32(), &blob, b"").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = key32();
        let mut blob = encrypt(&key, b"data", b"").unwrap();
        blob.ciphertext[0] ^= 0x01;
        assert!(decrypt(&key, &blob, b"").is_err());
    }
}
