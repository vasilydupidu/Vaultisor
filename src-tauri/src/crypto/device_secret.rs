// Управление Device Secret (TPM-привязанным секретом устройства).
//
// Жизненный цикл:
//   1) При инициализации vault на устройстве генерируется 256-bit device_secret.
//   2) TPM-ключ (RSA, NCrypt) подписывает детерминированный challenge
//      DS_KEK_CHALLENGE, получая стабильную подпись.
//   3) Из подписи через HKDF выводится KEK (Key Encryption Key).
//   4) device_secret шифруется AES-256-GCM под KEK и сохраняется в БД.
//
// При разблокировке vault:
//   1) TPM повторно подписывает тот же challenge → та же подпись.
//   2) HKDF → тот же KEK → расшифровка device_secret.
//   3) device_secret используется как добавка к PIN в Argon2id,
//      делая офлайн-перебор PIN невозможным без TPM.

use zeroize::Zeroizing;

use super::aead;
use super::kdf;
use super::rng;
use crate::error::{Result, VaultError};

/// Деривационный challenge для KEK устройственного секрета.
/// Отличается от Hello-challenge, чтобы подпись для DS и Hello
/// были криптографически независимы.
pub const DS_KEK_CHALLENGE: &[u8] = b"vaultisor:device-secret-kek-challenge:v1";

/// Данные для хранения Device Secret в БД.
#[derive(Debug, Clone)]
pub struct DeviceSecretData {
    /// Имя TPM-ключа в NCrypt (для UI и повторного доступа).
    pub tpm_key_name: String,
    /// AES-GCM(HKDF(tpm_sign), device_secret_raw) — зашифрованный blob.
    pub encrypted_blob: Vec<u8>,
}

/// Сгенерировать новый 256-bit device secret и зашифровать его TPM-производным KEK.
///
/// `tpm_key_name` — имя CNG-ключа TPM, которым выполняется подпись.
/// `tpm_signature` — RSA-подпись от TPM Sign(DS_KEK_CHALLENGE).
///
/// Возвращает (device_secret_raw, DeviceSecretData).
/// device_secret_raw нужен вызывающему коду для немедленного использования
/// (например, wrap_master_with_pin_v2), после чего зачищается.
pub fn generate_and_encrypt(
    tpm_key_name: &str,
    tpm_signature: &[u8],
) -> Result<(Zeroizing<[u8; 32]>, DeviceSecretData)> {
    // Генерация 256-bit device secret.
    let mut device_secret = Zeroizing::new([0u8; 32]);
    rng::fill(device_secret.as_mut_slice());

    // Вывод KEK из TPM-подписи.
    let kek = derive_ds_kek(tpm_signature)?;

    // Шифрование device_secret под KEK.
    let blob = aead::encrypt(&*kek, &*device_secret, b"vaultisor:device-secret:v1")?;
    let encrypted_blob = blob.to_bytes();

    Ok((
        device_secret,
        DeviceSecretData {
            tpm_key_name: tpm_key_name.to_string(),
            encrypted_blob,
        },
    ))
}

/// Расшифровать device secret с помощью TPM-подписи.
///
/// `data` — ранее сохранённые DeviceSecretData.
/// `tpm_signature` — RSA-подпись от TPM Sign(DS_KEK_CHALLENGE).
pub fn decrypt_device_secret(
    data: &DeviceSecretData,
    tpm_signature: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    use zeroize::Zeroize;

    let kek = derive_ds_kek(tpm_signature)?;

    let blob = aead::EncryptedBlob::from_bytes(&data.encrypted_blob)?;
    let mut plaintext = aead::decrypt(&*kek, &blob, b"vaultisor:device-secret:v1")
        .map_err(|_| VaultError::Crypto("device secret: decryption failed (wrong TPM signature?)".into()))?;

    if plaintext.len() != 32 {
        plaintext.zeroize();
        return Err(VaultError::Crypto(
            "device secret: decrypted blob has wrong length".into(),
        ));
    }

    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(secret)
}

/// Вывести KEK из TPM-подписи через HKDF-SHA256.
///
/// salt и info фиксированы для данного домена, чтобы KEK
/// был детерминированным при одной и той же подписи.
fn derive_ds_kek(tpm_signature: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let derived = kdf::hkdf_derive(
        tpm_signature,
        b"vaultisor:ds-kek-salt:v1",
        b"vaultisor:ds-kek:v1",
        32,
    )?;
    let mut kek = Zeroizing::new([0u8; 32]);
    kek.copy_from_slice(&derived);
    Ok(kek)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Имитация TPM-подписи для тестов (случайные 256 байт).
    fn fake_tpm_signature() -> Vec<u8> {
        rng::random_vec(256)
    }

    #[test]
    fn generate_and_decrypt_roundtrip() {
        let sig = fake_tpm_signature();
        let (secret_raw, data) = generate_and_encrypt("test-tpm-key", &sig).unwrap();

        // Расшифровка с той же подписью должна вернуть тот же секрет.
        let secret_dec = decrypt_device_secret(&data, &sig).unwrap();
        assert_eq!(
            secret_raw.as_slice(),
            secret_dec.as_slice(),
            "расшифрованный device secret должен совпадать с оригиналом"
        );
    }

    #[test]
    fn wrong_signature_fails_decryption() {
        let sig1 = fake_tpm_signature();
        let (_secret, data) = generate_and_encrypt("test-tpm-key", &sig1).unwrap();

        // Другая подпись → другой KEK → расшифровка провалится.
        let sig2 = fake_tpm_signature();
        let result = decrypt_device_secret(&data, &sig2);
        assert!(
            result.is_err(),
            "расшифровка с чужой подписью должна вернуть ошибку"
        );
    }

    #[test]
    fn tpm_key_name_preserved() {
        let sig = fake_tpm_signature();
        let (_secret, data) = generate_and_encrypt("my-ncrypt-key", &sig).unwrap();
        assert_eq!(data.tpm_key_name, "my-ncrypt-key");
    }

    #[test]
    fn device_secret_is_32_bytes() {
        let sig = fake_tpm_signature();
        let (secret, _data) = generate_and_encrypt("test", &sig).unwrap();
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn two_generate_calls_produce_different_secrets() {
        let sig = fake_tpm_signature();
        let (s1, _d1) = generate_and_encrypt("key", &sig).unwrap();
        let (s2, _d2) = generate_and_encrypt("key", &sig).unwrap();
        assert_ne!(
            s1.as_slice(),
            s2.as_slice(),
            "два вызова generate должны дать разные device secret"
        );
    }
}
