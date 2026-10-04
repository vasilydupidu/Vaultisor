/**
 * Проверка пароля на слабость (длина < 8 символов или частые простые
 * последовательности). Используется только для подсказки в карточке записи;
 * авторитетный расчёт делает backend при получении списка.
 *
 * AUDIT 3.1.1: длина считается в символах, а не в единицах UTF-16 — иначе
 * кириллический пароль из 8 букв мог быть признан достаточно длинным или
 * наоборот, в зависимости от кодовых точек.
 */
export function isPasswordWeak(val: string | null | undefined): boolean {
  if (!val) return false;
  const str = val.trim();
  if (str.length === 0) return false;
  if (Array.from(str).length < 8) return true;

  const lower = str.toLowerCase();
  if (
    lower.includes("12345") ||
    lower.includes("qwerty") ||
    lower.includes("password") ||
    lower.includes("admin") ||
    lower === "123456" ||
    lower === "12345678" ||
    lower === "123456789" ||
    lower === "00000000"
  ) {
    return true;
  }
  return false;
}
