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

/** Переключить язык + сохранить в localStorage */
export function setAppLanguage(lang: 'ru' | 'en') {
  i18n.changeLanguage(lang);
  if (typeof window !== 'undefined' && typeof localStorage !== 'undefined') {
    localStorage.setItem(LANG_KEY, lang);
  }
}

export default i18n;
