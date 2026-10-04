import { useTranslation } from 'react-i18next';
import { setAppLanguage } from '@/lib/i18n';

/**
 * Compact language toggle button (RU/EN).
 * Placed on Welcome and Lock screens so the user can switch
 * language before creating/unlocking the vault.
 */
export function LanguageToggle() {
  const { t, i18n } = useTranslation();
  const isRu = i18n.language === 'ru';

  return (
    <button
      onClick={() => setAppLanguage(isRu ? 'en' : 'ru')}
      className="lang-toggle"
      aria-label={
        isRu ? t('languageToggle.switchToEnglish') : t('languageToggle.switchToRussian')
      }
      title={isRu ? 'English' : t('settings.languageRu')}
    >
      {isRu ? 'RU' : 'EN'}
    </button>
  );
}
