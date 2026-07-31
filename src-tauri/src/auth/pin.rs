// Валидация PIN.
//
// Два режима:
//   1) Цифровой PIN: 8–12 цифр (PIN_MIN_LEN..=PIN_MAX_LEN), удобно для мобильной
//      клавиатуры, + отсев тривиальных (повтор/последовательность).
//   2) L-05: Алфавитно-цифровой PIN (буквы+цифры), 8–64 символа — опция для тех,
//      кому нужна повышенная стойкость (больше энтропии на символ). Включается
//      пользователем отдельной кнопкой в онбординге; backend просто принимает
//      такой ввод. Крипто-обёртка master-ключа при этом не меняется (это просто
//      байты на вход Argon2id).

use crate::error::{Result, VaultError};

pub const PIN_MIN_LEN: usize = 8;
pub const PIN_MAX_LEN: usize = 12;
/// Границы для алфавитно-цифрового PIN (L-05).
pub const PIN_ALNUM_MIN_LEN: usize = 8;
pub const PIN_ALNUM_MAX_LEN: usize = 64;

pub fn validate_pin_format(pin: &str) -> Result<()> {
    let len = pin.chars().count();

    // Режим 3 (S-07): Passphrase mode (>= 15 символов, любые символы).
    // Позволяет использовать парольные фразы (с пробелами и спецсимволами)
    // на устройствах без TPM 2.0.
    if len >= 15 {
        return Ok(());
    }

    let all_digits = !pin.is_empty() && pin.chars().all(|c| c.is_ascii_digit());

    if all_digits {
        // Режим 1: цифровой PIN.
        if len < PIN_MIN_LEN {
            return Err(VaultError::BadInput(format!("PIN короче {PIN_MIN_LEN} символов")));
        }
        if len > PIN_MAX_LEN {
            return Err(VaultError::BadInput(format!("PIN длиннее {PIN_MAX_LEN} символов")));
        }
        if is_too_simple(pin) {
            return Err(VaultError::BadInput(
                "PIN слишком простой (последовательность или повтор)".into(),
            ));
        }
        return Ok(());
    }

    // Режим 2 (L-05): буквенно-цифровой PIN. Разрешаем ЛЮБЫЕ Unicode-буквы и
    // цифры (в т.ч. кириллицу) — пользователь с русской раскладкой должен иметь
    // возможность набрать буквенный PIN, не переключая язык. Символы/пробелы
    // по-прежнему запрещены (детерминированный набор без путаницы).
    if pin.chars().all(|c| c.is_alphanumeric()) {
        if len < PIN_ALNUM_MIN_LEN {
            return Err(VaultError::BadInput(format!(
                "PIN короче {PIN_ALNUM_MIN_LEN} символов"
            )));
        }
        if len > PIN_ALNUM_MAX_LEN {
            return Err(VaultError::BadInput(format!(
                "PIN длиннее {PIN_ALNUM_MAX_LEN} символов"
            )));
        }
        return Ok(());
    }

    Err(VaultError::BadInput(
        "PIN должен содержать только буквы и цифры".into(),
    ))
}

fn is_too_simple(pin: &str) -> bool {
    let bytes = pin.as_bytes();
    if bytes.len() < 4 {
        return true;
    }
    // Все одинаковые цифры.
    let mut all_same = true;
    for &c in bytes {
        if c != bytes[0] {
            all_same = false;
            break;
        }
    }
    if all_same {
        return true;
    }
    // Возрастающая или убывающая последовательность с шагом ±1.
    let mut asc = true;
    let mut desc = true;
    for w in bytes.windows(2) {
        if w[1] as i32 - w[0] as i32 != 1 {
            asc = false;
        }
        if w[0] as i32 - w[1] as i32 != 1 {
            desc = false;
        }
    }
    asc || desc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short() {
        assert!(validate_pin_format("1234567").is_err());
    }

    #[test]
    fn rejects_long() {
        assert!(validate_pin_format("1234567890123").is_err());
    }

    #[test]
    fn accepts_alphanumeric() {
        // L-05: буквенно-цифровой PIN ≥8 допустим (латиница и кириллица).
        assert!(validate_pin_format("abcd1234").is_ok());
        assert!(validate_pin_format("Str0ngPass99").is_ok());
        assert!(validate_pin_format("пароль12").is_ok());
        assert!(validate_pin_format("Пароль2026").is_ok());
    }

    #[test]
    fn rejects_short_alphanumeric() {
        assert!(validate_pin_format("abc123").is_err()); // 6 < 8
    }

    #[test]
    fn rejects_symbols() {
        assert!(validate_pin_format("abcd!@#$").is_err());
        assert!(validate_pin_format("pass word").is_err());
    }

    #[test]
    fn rejects_repeat() {
        assert!(validate_pin_format("00000000").is_err());
        assert!(validate_pin_format("9999999999").is_err());
    }

    #[test]
    fn rejects_sequence() {
        assert!(validate_pin_format("12345678").is_err());
        assert!(validate_pin_format("87654321").is_err());
    }

    #[test]
    fn accepts_normal() {
        assert!(validate_pin_format("19472856").is_ok());
        assert!(validate_pin_format("58392071").is_ok());
    }

    #[test]
    fn accepts_passphrase() {
        assert!(validate_pin_format("my strong passphrase 2026").is_ok());
        assert!(validate_pin_format("P@ssw0rd!Strong#2026").is_ok());
    }

    #[test]
    fn rejects_short_symbols() {
        assert!(validate_pin_format("short!pwd").is_err());
    }
}
