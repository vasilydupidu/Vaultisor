import { useEffect, useState } from "react";
import { Check, ChevronLeft } from "lucide-react";
import {
  apiRecoveryDisable,
  apiRecoveryStatus,
  apiSettingsGet,
  apiSettingsUpdate,
  type SettingsDto,
} from "@/lib/api";
import { IconButton } from "@/components/ui/IconButton";
import { Button } from "@/components/ui/Button";
import { Spinner } from "@/components/ui/Spinner";
import { useToast } from "@/components/ui/Toast";
import { Sheet } from "@/components/ui/Sheet";
import { sanitizeError } from "@/lib/sanitizeError";
import { Trans, useTranslation } from 'react-i18next';
import { setAppLanguage } from '@/lib/i18n';
import { cn } from "@/lib/cn";
import { Section } from "./settings/controls";

import { SettingsAutolock } from "./settings/SettingsAutolock";
import { SettingsClipboard } from "./settings/SettingsClipboard";
import { SettingsSecurity } from "./settings/SettingsSecurity";
import { SettingsPinAttempts } from "./settings/SettingsPinAttempts";
import { SettingsRecovery, RecoveryRegenerate } from "./settings/SettingsRecovery";
import { SettingsBackup } from "./settings/SettingsBackup";

interface Props {
  onClose: () => void;
  onSettingsChanged: (s: SettingsDto) => void;
}

export function Settings({ onClose, onSettingsChanged }: Props) {
  const { t, i18n } = useTranslation();
  const [s, setS] = useState<SettingsDto | null>(null);
  const [saving, setSaving] = useState(false);
  const [recoveryConfigured, setRecoveryConfigured] = useState<boolean | null>(null);
  const [regenerateOpen, setRegenerateOpen] = useState(false);
  const [confirmDisable, setConfirmDisable] = useState(false);
  const [appVersion, setAppVersion] = useState("");
  const toast = useToast();

  const refreshRecovery = () => {
    apiRecoveryStatus()
      .then((r) => setRecoveryConfigured(r.configured))
      .catch(() => setRecoveryConfigured(null));
  };

  useEffect(() => {
    apiSettingsGet().then(setS).catch(() => toast.error(t('settings.loadError')));
    refreshRecovery();
    import("@tauri-apps/api/app")
      .then((m) => m.getVersion())
      .then(setAppVersion)
      .catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const save = async () => {
    if (!s) return;
    setSaving(true);
    try {
      await apiSettingsUpdate(s);
      onSettingsChanged(s);
      toast.success(t('settings.saved'));
      onClose();
    } catch (e) {
      toast.error(sanitizeError(e, t('settings.saveError')));
    } finally {
      setSaving(false);
    }
  };

  const handleDisableRecovery = async () => {
    try {
      await apiRecoveryDisable();
      toast.success(t('settings.recoveryDisabled'));
      setConfirmDisable(false);
      refreshRecovery();
    } catch {
      toast.error(t('settings.disableError'));
    }
  };

  if (!s) {
    return (
      <div className="h-full flex items-center justify-center text-white/60">
        <Spinner className="h-5 w-5" />
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      <header className="px-4 pt-3 pb-2 flex items-center gap-1 border-b border-white/[0.05] shrink-0">
        <IconButton
          icon={<ChevronLeft />}
          aria-label={t('common.close')}
          variant="subtle"
          onClick={onClose}
        />
        <div className="flex-1 ml-1 text-sm font-medium">{t('settings.title')}</div>
        <Button
          onClick={save}
          loading={saving}
          size="sm"
          leftIcon={<Check className="h-4 w-4" />}
        >
          {t('common.save')}
        </Button>
      </header>

      <div className="flex-1 overflow-y-auto min-h-0 px-4 py-4 space-y-5">
        <SettingsAutolock s={s} setS={setS} />
        <SettingsClipboard s={s} setS={setS} />
        <SettingsSecurity s={s} setS={setS} />
        <SettingsPinAttempts s={s} setS={setS} />
        
        <SettingsRecovery
          recoveryConfigured={recoveryConfigured}
          onRegenerateOpen={() => setRegenerateOpen(true)}
          onConfirmDisableOpen={() => setConfirmDisable(true)}
        />
        
        <SettingsBackup />

        <Section title={t('settings.languageTitle')}>
          <p className="text-2xs text-white/55 mb-2">{t('settings.languageDesc')}</p>
          <div className="grid grid-cols-2 gap-1.5">
            {[
              { id: 'ru', label: 'RU (Русский)' },
              { id: 'en', label: 'EN (English)' },
            ].map((o) => (
              <button
                key={o.id}
                type="button"
                onClick={() => setAppLanguage(o.id as 'ru' | 'en')}
                className={cn(
                  "px-2 py-1.5 rounded-lg text-xs transition-app text-center font-medium",
                  (i18n.language === o.id || (o.id === 'ru' && !['ru', 'en'].includes(i18n.language)))
                    ? "bg-brand-500/15 text-brand-300 border border-brand-500/30"
                    : "bg-white/[0.03] text-white/70 border border-white/[0.08] hover:bg-white/[0.06]"
                )}
              >
                {o.label}
              </button>
            ))}
          </div>
        </Section>

        <div className="text-2xs text-white/35 text-center pt-2 leading-relaxed">
          <Trans
            i18nKey="settings.footer"
            values={{ version: appVersion ? ` v${appVersion}` : "" }}
            components={{ br: <br /> }}
          />
        </div>
      </div>

      {/* Регенерация — открывает sheet с QR и кнопкой save USB */}
      <Sheet
        open={regenerateOpen}
        onClose={() => {
          setRegenerateOpen(false);
          refreshRecovery();
        }}
        title={t('settings.regenerateTitle')}
      >
        <RecoveryRegenerate onClose={() => setRegenerateOpen(false)} />
      </Sheet>

      <Sheet
        open={confirmDisable}
        onClose={() => setConfirmDisable(false)}
        title={t('settings.disableTitle')}
      >
        <div className="space-y-4">
          <p className="text-sm text-white/65">
            {t('settings.disableDesc')}
          </p>
          <div className="flex gap-2">
            <Button
              variant="secondary"
              fullWidth
              onClick={() => setConfirmDisable(false)}
            >
              {t('common.cancel')}
            </Button>
            <Button variant="danger" fullWidth onClick={handleDisableRecovery}>
              {t('settings.disableBtn')}
            </Button>
          </div>
        </div>
      </Sheet>
    </div>
  );
}
