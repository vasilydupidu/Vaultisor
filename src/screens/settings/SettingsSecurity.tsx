import type { SettingsDto } from "@/lib/api";
import { useTranslation } from 'react-i18next';
import { Section, ToggleRow } from "./controls";

interface Props {
  s: SettingsDto;
  setS: (s: SettingsDto) => void;
}

export function SettingsSecurity({ s, setS }: Props) {
  const { t } = useTranslation();
  return (
    <Section title={t('settingsSecurity.title')}>
      <ToggleRow
        title={t('settingsSecurity.authTitle')}
        description={
          s.use_windows_hello
            ? t('settingsSecurity.authDescEnabled')
            : t('settingsSecurity.authDescDisabled')
        }
        checked={s.require_auth_for_copy && s.use_windows_hello}
        disabled={!s.use_windows_hello}
        onChange={(v) => setS({ ...s, require_auth_for_copy: v })}
      />
      <ToggleRow
        title={t('settingsSecurity.helloTitle')}
        description={
          s.use_windows_hello
            ? t('settingsSecurity.helloDescEnabled')
            : t('settingsSecurity.helloDescDisabled')
        }
        checked={s.use_windows_hello}
        onChange={(v) =>
          // При выключении Hello сбрасываем зависимую настройку, иначе backend
          // отклонит сохранение (require_auth_for_copy требует Hello).
          setS({
            ...s,
            use_windows_hello: v,
            require_auth_for_copy: v ? s.require_auth_for_copy : false,
          })
        }
      />
      <p className="text-2xs text-white/40 leading-snug">
        {t('settingsSecurity.helloHint')}
      </p>
    </Section>
  );
}
