// Утилиты форматирования.

import i18n from '@/lib/i18n';

export function formatRelativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  const now = Date.now();
  const diff = Math.max(0, Math.floor((now - then) / 1000));
  if (diff < 60) return i18n.t('format.justNow');
  if (diff < 3600) return i18n.t('format.minutesAgo', { minutes: Math.floor(diff / 60) });
  if (diff < 86400) return i18n.t('format.hoursAgo', { hours: Math.floor(diff / 3600) });
  if (diff < 86400 * 7) return i18n.t('format.daysAgo', { days: Math.floor(diff / 86400) });
  return new Date(iso).toLocaleDateString("ru-RU");
}

export function pluralRu(n: number, forms: [string, string, string]): string {
  const mod10 = n % 10;
  const mod100 = n % 100;
  if (mod100 >= 11 && mod100 <= 14) return forms[2];
  if (mod10 === 1) return forms[0];
  if (mod10 >= 2 && mod10 <= 4) return forms[1];
  return forms[2];
}
