import { apiClipboardClear, type SettingsDto } from "@/lib/api";
import { useTranslation } from 'react-i18next';
import { Eraser } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { useToast } from "@/components/ui/Toast";
import { sanitizeError } from "@/lib/sanitizeError";
import { Section, OptionList, CustomMinutesInput } from "./controls";

interface Props {
  s: SettingsDto;
  setS: (s: SettingsDto) => void;
}

export function SettingsClipboard({ s, setS }: Props) {
  const { t } = useTranslation();
  const toast = useToast();

  const clipboardPresets = [
    { v: 10, l: t('settingsClipboard.preset10s') },
    { v: 30, l: t('settingsClipboard.preset30s') },
    { v: 0, l: t('settingsClipboard.presetNever') },
  ];

  const clearNow = async () => {
    try {
      await apiClipboardClear();
      toast.success(t('settingsClipboard.cleared'));
    } catch (e) {
      toast.error(sanitizeError(e));
    }
  };

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
      <Button
        variant="secondary"
        size="sm"
        fullWidth
        onClick={clearNow}
        leftIcon={<Eraser className="h-3.5 w-3.5" />}
      >
        {t('settingsClipboard.clearNow')}
      </Button>
    </Section>
  );
}
