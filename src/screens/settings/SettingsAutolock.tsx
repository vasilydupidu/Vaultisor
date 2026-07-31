import type { SettingsDto } from "@/lib/api";
import { useTranslation } from 'react-i18next';
import { Section, OptionList, CustomMinutesInput } from "./controls";

interface Props {
  s: SettingsDto;
  setS: (s: SettingsDto) => void;
}

export function SettingsAutolock({ s, setS }: Props) {
  const { t } = useTranslation();

  const autolockPresets = [
    { v: 60, l: t('settingsAutolock.preset1m') },
    { v: 300, l: t('settingsAutolock.preset5m') },
    { v: 0, l: t('settingsAutolock.presetNever') },
  ];
  return (
    <Section title={t('settingsAutolock.title')}>
      <p className="text-2xs text-white/50">
        {t('settingsAutolock.desc')}
      </p>
      <OptionList
        value={s.autolock_seconds}
        options={autolockPresets}
        onChange={(v) => setS({ ...s, autolock_seconds: v })}
      />
      <CustomMinutesInput
        label={t('settingsAutolock.customLabel')}
        valueSeconds={s.autolock_seconds}
        presets={autolockPresets.map((o) => o.v)}
        onChange={(v) => setS({ ...s, autolock_seconds: v })}
        unit="min"
        maxMinutes={60}
      />
    </Section>
  );
}
