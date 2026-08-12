import type { RecordModel } from "./api";

/**
 * Проверка пароля на слабость (длина < 8 или частые простые последовательности).
 */
export function isPasswordWeak(val: string | null | undefined): boolean {
  if (!val) return false;
  const str = val.trim();
  if (str.length === 0) return false;
  if (str.length < 8) return true;
  
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

export interface RecordHealthStatus {
  hasWeak: boolean;
  hasReused: boolean;
}

/**
 * Вычисление состояния безопасности по списку записей (для подсвечивания дубликатов и слабых паролей).
 */
export function computeVaultHealth(
  records: RecordModel[],
  revealedValues?: Record<string, string>,
): Map<string, RecordHealthStatus> {
  const result = new Map<string, RecordHealthStatus>();
  const valCounts = new Map<string, number>();

  // Шаг 1. Считаем частоту встречаемости известных секретных значений
  for (const r of records) {
    for (const f of r.fields) {
      if (f.is_secret || f.field_type === "secret") {
        const val = revealedValues?.[f.id] || (f.value_preview !== "••••••••" ? f.value_preview : null);
        if (val && val.trim()) {
          const trimmed = val.trim();
          valCounts.set(trimmed, (valCounts.get(trimmed) || 0) + 1);
        }
      }
    }
  }

  // Шаг 2. Анализируем каждую запись
  for (const r of records) {
    let hasWeak = false;
    let hasReused = false;

    for (const f of r.fields) {
      if (f.is_secret || f.field_type === "secret") {
        const val = revealedValues?.[f.id] || (f.value_preview !== "••••••••" ? f.value_preview : null);
        if (val && isPasswordWeak(val)) {
          hasWeak = true;
        }
        if (val && val.trim() && (valCounts.get(val.trim()) || 0) > 1) {
          hasReused = true;
        }
      }
    }

    if (hasWeak || hasReused) {
      result.set(r.id, { hasWeak, hasReused });
    }
  }

  return result;
}
