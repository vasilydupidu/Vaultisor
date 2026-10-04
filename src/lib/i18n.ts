import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import ru from '../locales/ru.json';
import en from '../locales/en.json';

const LANG_KEY = 'vaultisor_lang';
const saved = typeof window !== 'undefined' && typeof localStorage !== 'undefined' 
  ? (localStorage.getItem(LANG_KEY) ?? 'ru') 
  : 'ru';

i18n.use(initReactI18next).init({
  resources: { ru: { translation: ru }, en: { translation: en } },
  lng: saved,
  fallbackLng: 'ru',
  interpolation: { escapeValue: false },
});

export type AppLanguage = 'ru' | 'en';

export function normalizeLanguage(value: string | null | undefined): AppLanguage {
  return value === 'en' ? 'en' : 'ru';
}

/**
 * Переключить язык интерфейса.
 *
 * localStorage нужен для экрана блокировки (он рисуется ДО разблокировки, когда
 * зашифрованные настройки ещё недоступны). AUDIT 3.1.1: выбор дополнительно
 * сохраняется в метаданные хранилища — README обещает «сохранение выбора в
 * зашифрованных настройках», но backend-команда не вызывалась вовсе.
 */
export function setAppLanguage(lang: AppLanguage) {
  i18n.changeLanguage(lang);
  if (typeof window !== 'undefined' && typeof localStorage !== 'undefined') {
    localStorage.setItem(LANG_KEY, lang);
  }
}

/** Применить язык, пришедший из зашифрованных настроек хранилища. */
export function applyStoredLanguage(lang: string) {
  const normalized = normalizeLanguage(lang);
  if (i18n.language !== normalized) {
    setAppLanguage(normalized);
  }
}

export default i18n;
