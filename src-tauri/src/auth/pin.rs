//! Валидация PIN и мастер-пароля.
//!
//! Три режима ввода, согласованные с `src/lib/pinRules.ts` на фронтенде:
//!
//! 1. Цифровой PIN — 11…16 цифр, с отсевом тривиальных (повтор, последовательность).
//!    Удобен для цифровой клавиатуры; стойкость держится на Argon2id и Device Secret.
//! 2. Буквенно-цифровой PIN — 11…64 символа, любые буквы (включая кириллицу) и цифры.
//! 3. Парольная фраза — от 15 символов, любые символы. На машине без TPM 2.0
//!    это ЕДИНСТВЕННЫЙ допустимый режим: аппаратного якоря нет, поэтому вся
//!    стойкость держится на энтропии самого пароля.

use crate::error::{Result, VaultError};

/// Границы цифрового PIN.
pub const PIN_DIGIT_MIN: usize = 11;
pub const PIN_DIGIT_MAX: usize = 16;
/// Минимальная длина буквенно-цифрового PIN.
pub const PIN_ALNUM_MIN: usize = 11;
/// Минимум для парольной фразы и для режима без TPM.
pub const PASSPHRASE_MIN: usize = 15;
/// Верхняя граница любого секрета. Argon2id не ограничивает длину входа,
/// но принимать мегабайтные строки из webview незачем.
pub const SECRET_MAX: usize = 256;

/// Проверить формат секрета, которым будет обёрнут мастер-ключ.
///
/// `tpm_backed` — есть ли на машине TPM 2.0 и, соответственно, Device Secret.
/// Без него короткий PIN недопустим ни в каком виде.
pub fn validate_secret_format(secret: &str, tpm_backed: bool) -> Result<()> {
    let len = secret.chars().count();

    if len > SECRET_MAX {
        return Err(VaultError::BadInput(format!(
            "Секрет длиннее {SECRET_MAX} символов"
        )));
    }

    if !tpm_backed {
        if len < PASSPHRASE_MIN {
            return Err(VaultError::BadInput(format!(
                "Без TPM 2.0 требуется мастер-пароль не короче {PASSPHRASE_MIN} символов"
            )));
        }
        return Ok(());
    }

    if !secret.is_empty() && secret.chars().all(|c| c.is_ascii_digit()) {
        if len < PIN_DIGIT_MIN {
            return Err(VaultError::BadInput(format!(
                "PIN короче {PIN_DIGIT_MIN} символов"
            )));
        }
        if len > PIN_DIGIT_MAX {
            return Err(VaultError::BadInput(format!(
                "PIN длиннее {PIN_DIGIT_MAX} символов"
            )));
        }
        if is_too_simple(secret) {
            return Err(VaultError::BadInput(
                "PIN слишком простой (последовательность или повтор)".into(),
            ));
        }
        return Ok(());
    }

    // Парольная фраза: любые символы, но заметно длиннее.
    if len >= PASSPHRASE_MIN {
        return Ok(());
    }

    // Короче парольной фразы допустим только буквенно-цифровой PIN от 11 знаков.
    if secret.chars().all(char::is_alphanumeric) {
        if len < PIN_ALNUM_MIN {
            return Err(VaultError::BadInput(format!(
                "PIN короче {PIN_ALNUM_MIN} символов"
            )));
        }
        return Ok(());
    }

    Err(VaultError::BadInput(format!(
        "PIN должен содержать только буквы и цифры либо быть парольной фразой от {PASSPHRASE_MIN} символов"
    )))
}

/// Тривиальный цифровой PIN: всё одинаковое, шесть одинаковых подряд или
/// строгая арифметическая последовательность из шести цифр.
fn is_too_simple(pin: &str) -> bool {
    let bytes = pin.as_bytes();
    if bytes.len() < 4 {
        return true;
    }
    if bytes.iter().all(|&c| c == bytes[0]) {
        return true;
    }
    for window in bytes.windows(6) {
        if window.iter().all(|&c| c == window[0]) {
            return true;
        }
        let mut ascending = true;
        let mut descending = true;
        for pair in window.windows(2) {
            let delta = pair[1] as i32 - pair[0] as i32;
            if delta != 1 {
                ascending = false;
            }
            if delta != -1 {
                descending = false;
            }
        }
        if ascending || descending {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tpm(secret: &str) -> Result<()> {
        validate_secret_format(secret, true)
    }

    fn no_tpm(secret: &str) -> Result<()> {
        validate_secret_format(secret, false)
    }

    #[test]
    fn digit_pin_bounds() {
        assert!(tpm("19472856302").is_ok()); // 11 цифр
        assert!(tpm("5839207146582").is_ok()); // 13 цифр
        assert!(tpm("1947285630294").is_ok());
        assert!(tpm("1234567890").is_err(), "10 цифр — слишком коротко");
        assert!(
            tpm("19472856302947156").is_err(),
            "17 цифр — слишком длинно"
        );
    }

    #[test]
    fn trivial_digit_pins_are_rejected() {
        assert!(tpm("00000000000").is_err());
        assert!(tpm("99999999999").is_err());
        assert!(tpm("12300000045").is_err(), "шесть одинаковых подряд");
        assert!(
            tpm("12345678901").is_err(),
            "возрастающая последовательность"
        );
        assert!(tpm("98765432101").is_err(), "убывающая последовательность");
    }

    #[test]
    fn alphanumeric_pins_including_cyrillic() {
        assert!(tpm("abcd1234567").is_ok());
        assert!(tpm("Str0ngPass99").is_ok());
        assert!(tpm("пароль12345").is_ok());
        assert!(tpm("abc1234567").is_err(), "10 символов — коротко");
        // 65 букв — это уже парольная фраза, а не PIN: длина приветствуется.
        assert!(tpm(&"a".repeat(65)).is_ok());
    }

    #[test]
    fn passphrases_allow_any_characters() {
        assert!(tpm("my strong passphrase 2026").is_ok());
        assert!(tpm("P@ssw0rd!Strong#2026").is_ok());
        assert!(tpm("short!pwd").is_err(), "спецсимволы и меньше 15");
    }

    /// Без аппаратного якоря короткий PIN недопустим ни в каком виде:
    /// офлайн-перебор упирается только в Argon2id.
    #[test]
    fn without_tpm_only_long_secrets_are_accepted() {
        assert!(
            no_tpm("19472856302").is_err(),
            "11 цифр без TPM недостаточно"
        );
        assert!(no_tpm("abcd1234567").is_err());
        assert!(no_tpm(&"a".repeat(PASSPHRASE_MIN - 1)).is_err());
        assert!(no_tpm(&"a".repeat(PASSPHRASE_MIN)).is_ok());
        assert!(no_tpm("my strong passphrase 2026").is_ok());
    }

    #[test]
    fn absurdly_long_secrets_are_rejected_in_both_modes() {
        let huge = "a".repeat(SECRET_MAX + 1);
        assert!(tpm(&huge).is_err());
        assert!(no_tpm(&huge).is_err());
        assert!(tpm(&"a".repeat(SECRET_MAX)).is_ok());
    }

    #[test]
    fn empty_secret_is_rejected_in_both_modes() {
        assert!(tpm("").is_err());
        assert!(no_tpm("").is_err());
    }
}
