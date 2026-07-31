import type { SettingsDto } from "@/lib/api";
import { useTranslation } from 'react-i18next';
import { Section, OptionList } from "./controls";

interface Props {
  s: SettingsDto;
  setS: (s: SettingsDto) => void;
}

const pinAttemptsOptions = [
  { v: 3, l: "3" },
  { v: 5, l: "5" },
  { v: 10, l: "10" },
];

export function SettingsPinAttempts({ s, setS }: Props) {
  const { t } = useTranslation();
  return (
    <Section title={t('settingsPinAttempts.title')}>
      <p className="text-2xs text-white/50 leading-snug">
        {t('settingsPinAttempts.desc')}
      </p>
      <OptionList
        value={s.max_pin_attempts}
        options={pinAttemptsOptions}
        onChange={(v) => setS({ ...s, max_pin_attempts: v })}
      />
    </Section>
  );
}
