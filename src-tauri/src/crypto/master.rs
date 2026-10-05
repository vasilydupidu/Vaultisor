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
    // `[u8; N]` — Copy, поэтому MasterKey::new получает КОПИЮ, а
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

/// Обернуть master-key с помощью PIN и явных параметров Argon2id.
pub fn wrap_master_with_pin_params(
    master: &MasterKey,
    pin: &[u8],
    params: kdf::Argon2Params,
) -> Result<WrappedKey> {
    let salt: [u8; SALT_LEN] = rng::random_array();
    let kek = kdf::argon2id_derive_key_with(pin, &salt, params)?;
    let blob = master
        .with_decrypted(|decrypted| aead::encrypt(&kek, decrypted, b"vaultisor:master-wrap"))?;
    Ok(WrappedKey { salt, blob })
}

/// Развернуть master-key с помощью PIN и параметров, под которыми он запечатан.
pub fn unwrap_master_with_pin_params(
    wrapped: &WrappedKey,
    pin: &[u8],
    params: kdf::Argon2Params,
) -> Result<MasterKey> {
    use zeroize::Zeroize;
    let kek = kdf::argon2id_derive_key_with(pin, &wrapped.salt, params)?;
    let mut plaintext = aead::decrypt(&kek, &wrapped.blob, b"vaultisor:master-wrap")
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
    key_buf.zeroize(); // затираем стековую копию
    Ok(mk)
}

/// Обернуть master-key (v2) с явными параметрами Argon2id.
pub fn wrap_master_with_pin_v2_params(
    master: &MasterKey,
    pin: &[u8],
    device_secret: &[u8; 32],
    params: kdf::Argon2Params,
) -> Result<WrappedKey> {
    let salt: [u8; SALT_LEN] = rng::random_array();
    let kek = kdf::argon2id_derive_key_v2_with(pin, device_secret, &salt, params)?;
    let blob = master
        .with_decrypted(|decrypted| aead::encrypt(&kek, decrypted, b"vaultisor:master-wrap:v2"))?;
    Ok(WrappedKey { salt, blob })
}

/// Развернуть master-key (v2) на параметрах, под которыми он был запечатан.
pub fn unwrap_master_with_pin_v2_params(
    wrapped: &WrappedKey,
    pin: &[u8],
    device_secret: &[u8; 32],
    params: kdf::Argon2Params,
) -> Result<MasterKey> {
    use zeroize::Zeroize;
    let kek = kdf::argon2id_derive_key_v2_with(pin, device_secret, &wrapped.salt, params)?;
    let mut plaintext = aead::decrypt(&kek, &wrapped.blob, b"vaultisor:master-wrap:v2")
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
    key_buf.zeroize(); // затираем стековую копию
    Ok(mk)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Тестовые параметры Argon2id. Продакшн-значения (512 МиБ, t=6) делают
    /// один вызов многосекундным, а весь набор — часовым; криптографическая
    /// логика обёртки от стоимости не зависит, поэтому в тестах она снижена.
    fn fast() -> kdf::Argon2Params {
        kdf::Argon2Params {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let master = generate_master_key();
        let wrapped = wrap_master_with_pin_params(&master, b"123456", fast()).unwrap();
        let unwrapped = unwrap_master_with_pin_params(&wrapped, b"123456", fast()).unwrap();
        master.with_decrypted(|m| {
            unwrapped.with_decrypted(|u| {
                assert_eq!(m, u);
            })
        });
    }

    #[test]
    fn wrong_pin_fails() {
        let master = generate_master_key();
        let wrapped = wrap_master_with_pin_params(&master, b"correct", fast()).unwrap();
        let err = match unwrap_master_with_pin_params(&wrapped, b"wrong", fast()) {
            Err(e) => e,
            Ok(_) => panic!("expected Err, got Ok"),
        };
        assert!(matches!(err, crate::error::VaultError::InvalidPin));
    }

    #[test]
    fn wrapped_key_roundtrip_bytes() {
        let master = generate_master_key();
        let wrapped = wrap_master_with_pin_params(&master, b"pin", fast()).unwrap();
        let bytes = wrapped.to_bytes();
        let restored = WrappedKey::from_bytes(&bytes).unwrap();
        let unwrapped = unwrap_master_with_pin_params(&restored, b"pin", fast()).unwrap();
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
        let wrapped = wrap_master_with_pin_v2_params(&master, b"123456", &ds, fast()).unwrap();
        let unwrapped = unwrap_master_with_pin_v2_params(&wrapped, b"123456", &ds, fast()).unwrap();
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
        let wrapped = wrap_master_with_pin_v2_params(&master, b"correct", &ds, fast()).unwrap();
        let err = match unwrap_master_with_pin_v2_params(&wrapped, b"wrong", &ds, fast()) {
            Err(e) => e,
            Ok(_) => panic!("expected Err, got Ok"),
        };
        assert!(matches!(err, crate::error::VaultError::InvalidPin));
    }

    /// Ключ, запечатанный под сохранёнными параметрами, обязан
    /// открываться именно ими, а не константами текущей сборки.
    #[test]
    fn unwrap_uses_the_params_the_key_was_sealed_with() {
        let weak = kdf::Argon2Params {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        };
        let master = generate_master_key();
        let salt: [u8; SALT_LEN] = rng::random_array();
        let kek = kdf::argon2id_derive_key_with(b"pin-value", &salt, weak).unwrap();
        let blob = master
            .with_decrypted(|decrypted| aead::encrypt(&kek, decrypted, b"vaultisor:master-wrap"))
            .unwrap();
        let wrapped = WrappedKey { salt, blob };

        let unwrapped = unwrap_master_with_pin_params(&wrapped, b"pin-value", weak).unwrap();
        master.with_decrypted(|m| unwrapped.with_decrypted(|u| assert_eq!(m, u)));

        let other = kdf::Argon2Params {
            m_cost: 16 * 1024,
            t_cost: 1,
            p_cost: 1,
        };
        assert!(
            unwrap_master_with_pin_params(&wrapped, b"pin-value", other).is_err(),
            "чужие параметры не должны разворачивать ключ"
        );
    }

    #[test]
    fn wrap_v2_wrong_device_secret_fails() {
        let master = generate_master_key();
        let ds1 = [0xCCu8; 32];
        let ds2 = [0xDDu8; 32];
        let wrapped = wrap_master_with_pin_v2_params(&master, b"pin", &ds1, fast()).unwrap();
        let err = match unwrap_master_with_pin_v2_params(&wrapped, b"pin", &ds2, fast()) {
            Err(e) => e,
            Ok(_) => panic!("expected Err, got Ok"),
        };
        assert!(matches!(err, crate::error::VaultError::InvalidPin));
    }
}
