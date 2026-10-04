use zeroize::Zeroizing;

use crate::crypto::aead::{self, EncryptedBlob, NONCE_LEN, TAG_LEN};
use crate::crypto::kdf::hkdf_derive;
use crate::crypto::master::MasterKey;
use crate::crypto::rng;
use crate::error::{Result, VaultError};

/// Длина случайной соли per-blob субключа.
pub(crate) const FIELD_SALT_LEN: usize = 16;

/// Формат значения поля: `[16 salt][12 nonce][ciphertext+tag]`.
///
/// Каждое значение шифруется СВОИМ субключом `HKDF(master, salt)`, а не самим
/// мастер-ключом. Это снимает birthday-bound случайных 96-битных nonce:
/// коллизия потребовала бы совпадения и соли (128 бит), и nonce. Плюс мастер-ключ
/// никогда не используется как AES-ключ напрямую.
///
/// AAD (record_id:field_id:field_type) привязывает шифротекст к конкретному
/// полю конкретной записи: перенос blob'а никуда не расшифруется.
pub(crate) fn derive_field_subkey(
    master_key: &[u8; 32],
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let derived = hkdf_derive(master_key, salt, b"vaultisor:field-aead:v2", 32)?;
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&derived);
    Ok(k)
}

/// Зашифровать значение поля в v2-формат (соль + AEAD на субключе).
pub(crate) fn field_encrypt(master: &MasterKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let salt: [u8; FIELD_SALT_LEN] = rng::random_array();
    // Тип возврата замыкания аннотируем явно: внутри смешиваются VaultError
    // (derive_field_subkey) и CoreError (aead::encrypt) — приводим к VaultError.
    let blob = master.with_decrypted(|decrypted| -> Result<EncryptedBlob> {
        let subkey = derive_field_subkey(decrypted, &salt)?;
        Ok(aead::encrypt(&subkey, plaintext, aad)?)
    })?;
    let mut out = Vec::with_capacity(FIELD_SALT_LEN + blob.nonce.len() + blob.ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&blob.to_bytes());
    Ok(out)
}

/// Расшифровать значение поля v2-формата.
pub(crate) fn field_decrypt(
    master: &MasterKey,
    bytes: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<String>> {
    if bytes.len() < FIELD_SALT_LEN + NONCE_LEN + TAG_LEN {
        return Err(VaultError::Crypto("field blob too short".into()));
    }
    let (salt, rest) = bytes.split_at(FIELD_SALT_LEN);
    let blob = EncryptedBlob::from_bytes(rest)?;
    master.with_decrypted(|decrypted| -> Result<Zeroizing<String>> {
        let subkey = derive_field_subkey(decrypted, salt)?;
        Ok(aead::decrypt_string(&subkey, &blob, aad)?)
    })
}
