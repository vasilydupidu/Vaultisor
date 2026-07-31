// DPAPI-слой обёртки master-key.
//
// Историческая заметка: ранее здесь жила структура `Db` со своей копией
// логики vault_meta (создание/чтение/MAC). Она полностью дублировала живую
// `MetaDb` из `meta_db.rs` и не использовалась — удалена. Осталась только
// маленькая, реально используемая часть: обёртка/разворачивание DPAPI-слоя
// над WrappedKey (используется в commands/vault.rs и commands/recovery.rs).

use crate::crypto::master::WrappedKey;
use crate::error::Result;

/// Снять DPAPI-слой и вернуть WrappedKey (salt + AEAD-обёртка master-key).
pub fn unwrap_dpapi_layer(dpapi_blob: &[u8]) -> Result<WrappedKey> {
    let bytes = crate::windows_api::dpapi::unprotect(dpapi_blob)?;
    WrappedKey::from_bytes(&bytes)
}

/// Наложить DPAPI-слой поверх WrappedKey для хранения в открытой meta.db.
pub fn wrap_dpapi_layer(wrapped: &WrappedKey) -> Result<Vec<u8>> {
    let bytes = wrapped.to_bytes();
    crate::windows_api::dpapi::protect(&bytes)
}
