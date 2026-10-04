//! DPAPI-слой поверх обёртки мастер-ключа.
//!
//! Обёртка мастер-ключа лежит в НЕзашифрованной meta-БД, поэтому поверх неё
//! ставится DPAPI (CurrentUser): файл, скопированный на другую машину или в
//! другую учётную запись Windows, не разворачивается.
//!
//! Энтропия у каждого хранилища своя, случайная, 32 байта. Общего значения по
//! умолчанию нет: константа в бинарнике не добавляла защиты, но заставляла
//! каждый вызов иметь fallback-ветку.

use crate::crypto::master::WrappedKey;
use crate::error::Result;

/// Снять DPAPI-слой и вернуть WrappedKey (salt + AEAD-обёртка мастер-ключа).
pub fn unwrap_dpapi_layer(dpapi_blob: &[u8], dpapi_entropy: &[u8]) -> Result<WrappedKey> {
    let bytes = crate::windows_api::dpapi::unprotect_with_entropy(dpapi_blob, dpapi_entropy)?;
    WrappedKey::from_bytes(&bytes)
}

/// Наложить DPAPI-слой поверх WrappedKey для хранения в открытой meta-БД.
pub fn wrap_dpapi_layer(wrapped: &WrappedKey, dpapi_entropy: &[u8]) -> Result<Vec<u8>> {
    let bytes = wrapped.to_bytes();
    crate::windows_api::dpapi::protect_with_entropy(&bytes, dpapi_entropy)
}
