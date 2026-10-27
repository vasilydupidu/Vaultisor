// Единый хелпер очистки ошибки для UI (снимает машинный префикс кода вида
// "DEVICE_MISMATCH:" и не показывает сырой объект). Раньше идиома
// String(e).replace(/^[A-Z_]+:\s*/, "") была скопирована в Lock/Settings/
// StepRecovery/StepPin.
import i18n from '@/lib/i18n';

// Два кода несут второй служебный сегмент перед текстом:
// "AUTH_REQUIRED:<действие>: …" и "DATA_ROLLBACK:<идентификатор снимка>: …".
// Он нужен коду (SecurityConfirm, Lock), но не пользователю.
const CODE_PREFIX = /^(?:AUTH_REQUIRED:[a-z0-9_]+|DATA_ROLLBACK:[0-9a-f]+|[A-Z_]+):\s*/;

export function sanitizeError(e: unknown, fallback?: string): string {
  const actualFallback = fallback ?? i18n.t('sanitizeError.defaultMessage');
  const raw = typeof e === "string" ? e : e instanceof Error ? e.message : "";
  return raw.replace(CODE_PREFIX, "").trim() || actualFallback;
}
