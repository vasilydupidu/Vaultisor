// Чистые правила валидации PIN (используются в онбординге; вынесены отдельно
// для юнит-тестов). Согласованы с backend auth::pin::validate_pin_format.
import i18n from '@/lib/i18n';

export type PinMode = "digit" | "alnum" | "passphrase";

export const PIN_DIGIT_MIN = 11;
export const PIN_DIGIT_MAX = 16;
export const PIN_ALNUM_MIN = 11;
export const PIN_ALNUM_MAX = 64;
export const PASSPHRASE_MIN = 15;
/** Верхняя граница любого секрета (как на backend). */
export const SECRET_MAX = 256;
/** Минимум различных символов в любом секрете. */
export const SECRET_MIN_DISTINCT = 6;

/** Все одинаковые цифры: "00000000000". */
export function isRepeatDigits(pin: string): boolean {
  if (/^(\d)\1+$/.test(pin)) return true;
  // Повтор 6+ одинаковых цифр подряд
  if (/(\d)\1{5,}/.test(pin)) return true;
  return false;
}

/** Строгая арифметическая последовательность 6+ цифр подряд: "123456" / "654321". */
export function isSequence(s: string): boolean {
  if (s.length < 6) return false;
  for (let i = 0; i <= s.length - 6; i++) {
    let asc = true;
    let desc = true;
    for (let j = i + 1; j < i + 6; j++) {
      const d = s.charCodeAt(j) - s.charCodeAt(j - 1);
      if (d !== 1) asc = false;
      if (d !== -1) desc = false;
    }
    if (asc || desc) return true;
  }
  return false;
}

/**
 * Общие требования к любому секрету: не пустой по сути, не один повторяющийся
 * символ и не менее SECRET_MIN_DISTINCT различных символов. Считаем символы
 * Unicode, как backend (`chars()`), а не UTF-16 единицы.
 */
export function weakSecretError(val: string): string | null {
  if (val.trim() === "") return i18n.t('pinRules.secretBlank');
  const distinct = new Set(Array.from(val)).size;
  if (distinct === 1) return i18n.t('pinRules.secretSingleChar');
  if (distinct < SECRET_MIN_DISTINCT) {
    return i18n.t('pinRules.secretFewDistinct', { min: SECRET_MIN_DISTINCT });
  }
  return null;
}

/**
 * Режим, в котором backend проверит секрет. Без TPM допустим только
 * мастер-пароль; с TPM цифры — это цифровой PIN, остальное от
 * PASSPHRASE_MIN символов — парольная фраза, иначе буквенно-цифровой PIN.
 */
export function secretMode(val: string, tpmAvailable: boolean): PinMode {
  if (!tpmAvailable) return "passphrase";
  if (val !== "" && /^\d+$/.test(val)) return "digit";
  return Array.from(val).length >= PASSPHRASE_MIN ? "passphrase" : "alnum";
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
    return weakSecretError(val);
  }
  if (mode === "alnum") {
    if (val.length < PIN_ALNUM_MIN) return i18n.t('pinRules.alnumTooShort', { min: PIN_ALNUM_MIN });
    if (val.length > PIN_ALNUM_MAX) return i18n.t('pinRules.alnumTooLong', { max: PIN_ALNUM_MAX });
    // Буквы любой раскладки (вкл. кириллицу) + цифры; символы/пробелы — нет.
    if (!/^[\p{L}\p{N}]+$/u.test(val)) return i18n.t('pinRules.alnumInvalidChars');
    return weakSecretError(val);
  }
  // digit
  if (val.length < PIN_DIGIT_MIN) return i18n.t('pinRules.digitTooShort', { min: PIN_DIGIT_MIN });
  if (val.length > PIN_DIGIT_MAX) return i18n.t('pinRules.digitTooLong', { max: PIN_DIGIT_MAX });
  if (isRepeatDigits(val)) return i18n.t('pinRules.digitRepeat');
  if (isSequence(val)) return i18n.t('pinRules.digitSequence');
  return weakSecretError(val);
}
