// Аутентификация: PIN.
// Логика разблокировки/блокировки сессии распределена между этим модулем
// и AppState (state.rs).

pub mod pin;

pub use pin::{validate_pin_format, PIN_MAX_LEN, PIN_MIN_LEN};
