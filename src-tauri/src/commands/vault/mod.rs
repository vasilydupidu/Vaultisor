//! Жизненный цикл хранилища: создание, разблокировка, блокировка, смена PIN.
use crate::error::{Result, VaultError};

mod create;
pub(crate) mod helpers;
mod io;
mod lifecycle;
mod unlock;

// Glob-ре-экспорт тянет публичные команды, их input/output-структуры и скрытые
// элементы, которые генерирует #[tauri::command] (__cmd__*), нужные
// generate_handler! в lib.rs.
pub use create::*;
pub use io::*;
pub use lifecycle::*;
pub use unlock::*;

/// Снять DPAPI с integrity-ключа.
///
/// DPAPI работает только в той же учётной записи Windows на том же устройстве,
/// поэтому неудача здесь однозначно означает чужую машину или учётку — это и
/// сообщается пользователю, чтобы он пошёл в восстановление, а не гадал.
pub(crate) fn unwrap_integrity_key(
    blob: &[u8],
    dpapi_entropy: &[u8],
) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    let plain = crate::windows_api::dpapi::unprotect_with_entropy(blob, dpapi_entropy)
        .map_err(|_| VaultError::DeviceMismatch)?;
    if plain.len() != 32 {
        return Err(VaultError::DeviceMismatch);
    }
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&plain);
    Ok(key)
}
