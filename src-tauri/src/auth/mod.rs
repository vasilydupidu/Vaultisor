// Аутентификация: PIN.
// Логика разблокировки/блокировки сессии распределена между этим модулем
// и AppState (state.rs).

/// Таблица моделей FIDO2-ключей, сгенерированная из FIDO MDS.
mod aaguid_table;
pub mod backoff;
pub mod fido2;
pub mod pin;
pub mod webauthn_rp;

pub use pin::validate_secret_format;
