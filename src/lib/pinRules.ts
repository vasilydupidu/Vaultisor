// Чистые правила валидации PIN (используются в онбординге; вынесены отдельно
// для юнит-тестов — L-06). Согласованы с backend auth::pin::validate_pin_format.
import i18n from '@/lib/i18n';

export type PinMode = "digit" | "alnum" | "passphrase";

export const PIN_DIGIT_MIN = 8;
export const PIN_DIGIT_MAX = 12;
export const PIN_ALNUM_MIN = 8;
export const PIN_ALNUM_MAX = 64;
export const PASSPHRASE_MIN = 15;

/** Все одинаковые цифры: "00000000". */
export function isRepeatDigits(pin: string): boolean {
  return /^(\d)\1+$/.test(pin);
}

/** Строгая арифметическая последовательность ±1: "12345678" / "87654321". */
export function isSequence(s: string): boolean {
  if (s.length < 4) return false;
  let asc = true;
  let desc = true;
  for (let i = 1; i < s.length; i++) {
    const d = s.charCodeAt(i) - s.charCodeAt(i - 1);
    if (d !== 1) asc = false;
    if (d !== -1) desc = false;
  }
  return asc || desc;
}

/**
 * Локальная (клиентская) проверка формата PIN/пароля. Возвращает текст ошибки
 * или null, если ввод валиден. Финальная авторитетная проверка — на backend.
 */
export function validatePinLocal(val: string, mode: PinMode): string | null {
  if (mode === "passphrase") {
    if (val.length < PASSPHRASE_MIN) {
      return i18n.t('pinRules.passphraseTooShort', { min: PASSPHRASE_MIN });
    }
    return null;
  }
  if (mode === "alnum") {
    if (val.length < PIN_ALNUM_MIN) return i18n.t('pinRules.alnumTooShort', { min: PIN_ALNUM_MIN });
    if (val.length > PIN_ALNUM_MAX) return i18n.t('pinRules.alnumTooLong', { max: PIN_ALNUM_MAX });
    // Буквы любой раскладки (вкл. кириллицу) + цифры; символы/пробелы — нет.
    if (!/^[\p{L}\p{N}]+$/u.test(val)) return i18n.t('pinRules.alnumInvalidChars');
    return null;
  }
  // digit
  if (val.length < PIN_DIGIT_MIN) return i18n.t('pinRules.digitTooShort', { min: PIN_DIGIT_MIN });
  if (val.length > PIN_DIGIT_MAX) return i18n.t('pinRules.digitTooLong', { max: PIN_DIGIT_MAX });
  if (isRepeatDigits(val)) return i18n.t('pinRules.digitRepeat');
  if (isSequence(val)) return i18n.t('pinRules.digitSequence');
  return null;
}
