// R-06: единый хелпер очистки ошибки для UI (снимает машинный префикс кода вида
// "DEVICE_MISMATCH:" и не показывает сырой объект). Раньше идиома
// String(e).replace(/^[A-Z_]+:\s*/, "") была скопирована в Lock/Settings/
// StepRecovery/StepPin.
import i18n from '@/lib/i18n';

export function sanitizeError(e: unknown, fallback?: string): string {
  const actualFallback = fallback ?? i18n.t('sanitizeError.defaultMessage');
  const raw = typeof e === "string" ? e : e instanceof Error ? e.message : "";
  return raw.replace(/^[A-Z_]+:\s*/, "").trim() || actualFallback;
}
