import type { SettingsDto } from "@/lib/api";
import { useTranslation } from 'react-i18next';
import { Section, OptionList, CustomMinutesInput } from "./controls";

interface Props {
  s: SettingsDto;
  setS: (s: SettingsDto) => void;
}

export function SettingsClipboard({ s, setS }: Props) {
  const { t } = useTranslation();

  const clipboardPresets = [
    { v: 10, l: t('settingsClipboard.preset10s') },
    { v: 30, l: t('settingsClipboard.preset30s') },
    { v: 0, l: t('settingsClipboard.presetNever') },
  ];
  return (
    <Section title={t('settingsClipboard.title')}>
      <p className="text-2xs text-white/50">
        {t('settingsClipboard.desc')}
      </p>
      <OptionList
        value={s.clipboard_clear_seconds}
        options={clipboardPresets}
        onChange={(v) => setS({ ...s, clipboard_clear_seconds: v })}
      />
      <CustomMinutesInput
        label={t('settingsClipboard.customLabel')}
        valueSeconds={s.clipboard_clear_seconds}
        presets={clipboardPresets.map((o) => o.v)}
        onChange={(v) => setS({ ...s, clipboard_clear_seconds: v })}
        unit="sec"
        maxMinutes={120}
      />
    </Section>
  );
}
