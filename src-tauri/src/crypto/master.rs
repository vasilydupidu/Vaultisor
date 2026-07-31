// Управление мастер-ключом.
//
// Жизненный цикл:
//  1) Генерация: 32 байта от OsRng при создании vault.
//  2) Обёртка: master_key шифруется AES-256-GCM ключом, выведенным
//     из PIN через Argon2id (см. kdf::argon2id_derive_key). Полученный
//     wrapped_blob хранится в БД.
//  3) Дополнительно wrapped_blob оборачивается DPAPI (см. windows_api::dpapi),
//     что привязывает его к учётной записи Windows + устройству.
//  4) Recovery: master_key разбивается Shamir 2-of-3 на доли;
//     одна локально (DPAPI), одна на USB, одна — пользователю.
//
// Принцип: backend никогда не выдаёт raw master_key наружу.
// Все криптооперации делаются здесь же, наружу выходит только результат.

use super::aead;
use super::kdf;
use super::rng;
use crate::error::Result;

/// Длина мастер-ключа AES-256.
pub const MASTER_KEY_LEN: usize = 32;

/// Тип мастер-ключа.
pub type MasterKey = core_shared::ram_protect::EncryptedMemoryBuffer<MASTER_KEY_LEN>;

/// Сгенерировать новый мастер-ключ.
pub fn generate_master_key() -> MasterKey {
    use zeroize::Zeroize;
    let mut k = [0u8; MASTER_KEY_LEN];
    rng::fill(&mut k);
    let mk = MasterKey::new(k);
    // AUDIT M4: `[u8; N]` — Copy, поэтому MasterKey::new получает КОПИЮ, а
    // локальный `k` остаётся на стеке. Затираем его явно.
    k.zeroize();
    mk
}

/// Длина salt для Argon2id (хранится с wrapped_blob).
pub const SALT_LEN: usize = 16;

/// Wrapped blob: salt + AEAD-зашифрованный master-key.
/// Сериализуется в БД как BLOB.
#[derive(Debug, Clone)]
pub struct WrappedKey {
    pub salt: [u8; SALT_LEN],
    pub blob: aead::EncryptedBlob,
}

impl WrappedKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SALT_LEN + 12 + 32 + 16);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.blob.to_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < SALT_LEN + 12 + 16 {
            return Err(crate::error::VaultError::Crypto(
                "wrapped key blob too short".into(),
            ));
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[..SALT_LEN]);
        let blob = aead::EncryptedBlob::from_bytes(&bytes[SALT_LEN..])?;
        Ok(Self { salt, blob })
    }
}

/// Обернуть master-key с помощью PIN.
pub fn wrap_master_with_pin(master: &MasterKey, pin: &[u8]) -> Result<WrappedKey> {
    let salt: [u8; SALT_LEN] = rng::random_array();
    let kek = kdf::argon2id_derive_key(pin, &salt)?;
    let blob = master.with_decrypted(|decrypted| {
        aead::encrypt(&*kek, decrypted, b"vaultisor:master-wrap")
    })?;
    Ok(WrappedKey { salt, blob })
}

/// Развернуть master-key с помощью PIN.
pub fn unwrap_master_with_pin(wrapped: &WrappedKey, pin: &[u8]) -> Result<MasterKey> {
    use zeroize::Zeroize;
    let kek = kdf::argon2id_derive_key(pin, &wrapped.salt)?;
    let mut plaintext = aead::decrypt(&*kek, &wrapped.blob, b"vaultisor:master-wrap")
        .map_err(|_| crate::error::VaultError::InvalidPin)?;
    if plaintext.len() != MASTER_KEY_LEN {
        plaintext.zeroize();
        return Err(crate::error::VaultError::Crypto(
            "unwrapped key has wrong length".into(),
        ));
    }
    let mut key_buf = [0u8; MASTER_KEY_LEN];
    key_buf.copy_from_slice(&plaintext);
    plaintext.zeroize();
    let mk = MasterKey::new(key_buf);
    key_buf.zeroize(); // AUDIT M4: затираем стековую копию
    Ok(mk)
}

/// Обернуть master-key с помощью PIN + Device Secret (v2).
pub fn wrap_master_with_pin_v2(
    master: &MasterKey,
    pin: &[u8],
    device_secret: &[u8; 32],
) -> Result<WrappedKey> {
    let salt: [u8; SALT_LEN] = rng::random_array();
    let kek = kdf::argon2id_derive_key_v2(pin, device_secret, &salt)?;
    let blob = master.with_decrypted(|decrypted| {
        aead::encrypt(&*kek, decrypted, b"vaultisor:master-wrap:v2")
    })?;
    Ok(WrappedKey { salt, blob })
}

/// Развернуть master-key с помощью PIN + Device Secret (v2).
pub fn unwrap_master_with_pin_v2(
    wrapped: &WrappedKey,
    pin: &[u8],
    device_secret: &[u8; 32],
) -> Result<MasterKey> {
    use zeroize::Zeroize;
    let kek = kdf::argon2id_derive_key_v2(pin, device_secret, &wrapped.salt)?;
    let mut plaintext = aead::decrypt(&*kek, &wrapped.blob, b"vaultisor:master-wrap:v2")
        .map_err(|_| crate::error::VaultError::InvalidPin)?;
    if plaintext.len() != MASTER_KEY_LEN {
        plaintext.zeroize();
        return Err(crate::error::VaultError::Crypto(
            "unwrapped key has wrong length".into(),
        ));
    }
    let mut key_buf = [0u8; MASTER_KEY_LEN];
    key_buf.copy_from_slice(&plaintext);
    plaintext.zeroize();
    let mk = MasterKey::new(key_buf);
    key_buf.zeroize(); // AUDIT M4: затираем стековую копию
    Ok(mk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let master = generate_master_key();
        let wrapped = wrap_master_with_pin(&master, b"123456").unwrap();
        let unwrapped = unwrap_master_with_pin(&wrapped, b"123456").unwrap();
        master.with_decrypted(|m| {
            unwrapped.with_decrypted(|u| {
                assert_eq!(m, u);
            })
        });
    }

    #[test]
    fn wrong_pin_fails() {
        let master = generate_master_key();
        let wrapped = wrap_master_with_pin(&master, b"correct").unwrap();
        let err = match unwrap_master_with_pin(&wrapped, b"wrong") {
            Err(e) => e,
            Ok(_) => panic!("expected Err, got Ok"),
        };
        assert!(matches!(err, crate::error::VaultError::InvalidPin));
    }

    #[test]
    fn wrapped_key_roundtrip_bytes() {
        let master = generate_master_key();
        let wrapped = wrap_master_with_pin(&master, b"pin").unwrap();
        let bytes = wrapped.to_bytes();
        let restored = WrappedKey::from_bytes(&bytes).unwrap();
        let unwrapped = unwrap_master_with_pin(&restored, b"pin").unwrap();
        master.with_decrypted(|m| {
            unwrapped.with_decrypted(|u| {
                assert_eq!(m, u);
            })
        });
    }

    #[test]
    fn wrap_v2_unwrap_v2_roundtrip() {
        let master = generate_master_key();
        let ds = [0xAAu8; 32];
        let wrapped = wrap_master_with_pin_v2(&master, b"123456", &ds).unwrap();
        let unwrapped = unwrap_master_with_pin_v2(&wrapped, b"123456", &ds).unwrap();
        master.with_decrypted(|m| {
            unwrapped.with_decrypted(|u| {
                assert_eq!(m, u);
            })
        });
    }

    #[test]
    fn wrap_v2_wrong_pin_fails() {
        let master = generate_master_key();
        let ds = [0xBBu8; 32];
        let wrapped = wrap_master_with_pin_v2(&master, b"correct", &ds).unwrap();
        let err = match unwrap_master_with_pin_v2(&wrapped, b"wrong", &ds) {
            Err(e) => e,
            Ok(_) => panic!("expected Err, got Ok"),
        };
        assert!(matches!(err, crate::error::VaultError::InvalidPin));
    }

    #[test]
    fn wrap_v2_wrong_device_secret_fails() {
        let master = generate_master_key();
        let ds1 = [0xCCu8; 32];
        let ds2 = [0xDDu8; 32];
        let wrapped = wrap_master_with_pin_v2(&master, b"pin", &ds1).unwrap();
        let err = match unwrap_master_with_pin_v2(&wrapped, b"pin", &ds2) {
            Err(e) => e,
            Ok(_) => panic!("expected Err, got Ok"),
        };
        assert!(matches!(err, crate::error::VaultError::InvalidPin));
    }
}
