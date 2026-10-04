// Форматирование дат и времени для интерфейса.

import i18n from "@/lib/i18n";

/**
 * Локаль для Intl. i18next хранит выбранный язык, поэтому берём его оттуда:
 * AUDIT 3.1.1 — раньше дата всегда выводилась в формате ru-RU, даже когда
 * интерфейс был переключён на английский.
 */
function activeLocale(): string {
  return i18n.language?.startsWith("en") ? "en-US" : "ru-RU";
}

export function formatRelativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  const now = Date.now();
  const diff = Math.max(0, Math.floor((now - then) / 1000));
  if (diff < 60) return i18n.t("format.justNow");
  if (diff < 3600) return i18n.t("format.minutesAgo", { minutes: Math.floor(diff / 60) });
  if (diff < 86400) return i18n.t("format.hoursAgo", { hours: Math.floor(diff / 3600) });
  if (diff < 86400 * 7) return i18n.t("format.daysAgo", { days: Math.floor(diff / 86400) });
  return new Date(iso).toLocaleDateString(activeLocale());
}

/** Дата и время в локали активного языка интерфейса. */
export function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString(activeLocale());
}
