// DPAPI-слой обёртки master-key.
//
// Историческая заметка: ранее здесь жила структура `Db` со своей копией
// логики vault_meta (создание/чтение/MAC). Она полностью дублировала живую
// `MetaDb` из `meta_db.rs` и не использовалась — удалена. Осталась только
// маленькая, реально используемая часть: обёртка/разворачивание DPAPI-слоя
// над WrappedKey (используется в commands/vault.rs и commands/recovery.rs).

use crate::crypto::master::WrappedKey;
use crate::error::Result;

/// Дефолтная DPAPI-энтропия для старых vault'ов без per-vault entropy.
const DEFAULT_DPAPI_ENTROPY: &[u8] = b"vaultisor:dpapi:v1";

/// Получить эффективную DPAPI entropy: per-vault (если есть) или дефолт.
pub fn effective_entropy(dpapi_entropy: Option<&[u8]>) -> &[u8] {
    dpapi_entropy.unwrap_or(DEFAULT_DPAPI_ENTROPY)
}

/// Снять DPAPI-слой и вернуть WrappedKey (salt + AEAD-обёртка master-key).
/// VULN-06 FIX: использует per-vault entropy если задана.
pub fn unwrap_dpapi_layer(dpapi_blob: &[u8], dpapi_entropy: Option<&[u8]>) -> Result<WrappedKey> {
    let entropy = effective_entropy(dpapi_entropy);
    let bytes = crate::windows_api::dpapi::unprotect_with_entropy(dpapi_blob, entropy)?;
    WrappedKey::from_bytes(&bytes)
}

/// Наложить DPAPI-слой поверх WrappedKey для хранения в открытой meta.db.
/// VULN-06 FIX: использует per-vault entropy если задана.
pub fn wrap_dpapi_layer(wrapped: &WrappedKey, dpapi_entropy: Option<&[u8]>) -> Result<Vec<u8>> {
    let entropy = effective_entropy(dpapi_entropy);
    let bytes = wrapped.to_bytes();
    crate::windows_api::dpapi::protect_with_entropy(&bytes, entropy)
}
