import { useEffect, useState } from "react";
import { KeyRound, RefreshCw, Trash2, Copy, Save } from "lucide-react";
import { useTranslation } from 'react-i18next';

import { save as saveDialog } from "@tauri-apps/plugin-dialog";
import {
  apiRecoveryRegenerate,
  apiRecoverySaveToUsb,
  apiClipboardCopyText,
} from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Spinner } from "@/components/ui/Spinner";
import { useToast } from "@/components/ui/Toast";
import { cn } from "@/lib/cn";
import { Section } from "./controls";

interface Props {
  recoveryConfigured: boolean | null;
  onRegenerateOpen: () => void;
  onConfirmDisableOpen: () => void;
}

export function SettingsRecovery({
  recoveryConfigured,
  onRegenerateOpen,
  onConfirmDisableOpen,
}: Props) {
  const { t } = useTranslation();
  return (
    <Section title={t('settingsRecovery.title')}>
      <p className="text-2xs text-white/50 leading-snug">
        {t('settingsRecovery.desc')}
      </p>

      <div className="card-flat p-3 flex items-start gap-2.5">
        <div
          className={cn(
            "h-7 w-7 shrink-0 rounded-lg flex items-center justify-center [&_svg]:h-3.5 [&_svg]:w-3.5",
            recoveryConfigured
              ? "bg-success/15 text-success"
              : "bg-warning/15 text-warning",
          )}
        >
          <KeyRound />
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-xs font-medium">
            {recoveryConfigured === null
              ? t('common.loading')
              : recoveryConfigured
              ? t('settingsRecovery.configured')
              : t('settingsRecovery.notConfigured')}
          </div>
          <p className="text-2xs text-white/55 mt-0.5 leading-snug">
            {recoveryConfigured
              ? t('settingsRecovery.configuredDesc')
              : t('settingsRecovery.notConfiguredDesc')}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2">
        <Button
          variant="secondary"
          size="sm"
          onClick={onRegenerateOpen}
          leftIcon={<RefreshCw className="h-3.5 w-3.5" />}
        >
          {recoveryConfigured ? t('settingsRecovery.recreate') : t('settingsRecovery.setup')}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          disabled={!recoveryConfigured}
          onClick={onConfirmDisableOpen}
          leftIcon={<Trash2 className="h-3.5 w-3.5" />}
        >
          {t('settingsRecovery.disable')}
        </Button>
      </div>
    </Section>
  );
}

export function RecoveryRegenerate({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [shareB, setShareB] = useState<string | null>(null);
  const [shareC, setShareC] = useState<string | null>(null);
  const [usbSaved, setUsbSaved] = useState(false);
  const [paperSaved, setPaperSaved] = useState(false);
  const toast = useToast();

  useEffect(() => {
    let mounted = true;
    setBusy(true);
    apiRecoveryRegenerate()
      .then((out) => {
        if (!mounted) return;
        setShareB(out.recovery_share_b_hex);
        setShareC(out.recovery_share_c_hex);
      })
      .catch(() => toast.error(t('settingsRecovery.createError')))
      .finally(() => {
        if (mounted) setBusy(false);
      });
    return () => {
      mounted = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const saveUsb = async () => {
    if (!shareB) return;
    try {
      const path = await saveDialog({
        title: t('settingsRecovery.savePartBTitle'),
        defaultPath: "vaultisor-recovery-part-b.vss",
        filters: [{ name: "Vaultisor Share", extensions: ["vss"] }],
      });
      if (!path) return;
      await apiRecoverySaveToUsb(shareB, path);
      setUsbSaved(true);
    } catch {
      toast.error(t('settingsRecovery.saveError'));
    }
  };

  const copyC = async () => {
    if (!shareC) return;
    try {
      await apiClipboardCopyText(shareC);
      setPaperSaved(true);
    } catch {
      toast.error(t('settingsRecovery.copyError'));
    }
  };

  const saveFileC = async () => {
    if (!shareC) return;
    try {
      const path = await saveDialog({
        title: t('stepRecovery.saveCDialogTitle'),
        defaultPath: "vaultisor-recovery-part-c.txt",
        filters: [{ name: "Text File", extensions: ["txt"] }],
      });
      if (!path) return;
      await apiRecoverySaveToUsb(shareC, path);
      setPaperSaved(true);
    } catch {
      toast.error(t('settingsRecovery.saveError'));
    }
  };

  if (busy && !shareB) {
    return (
      <div className="py-6 flex flex-col items-center gap-3 text-white/60">
        <Spinner className="h-5 w-5" />
        <span className="text-sm">{t('settingsRecovery.generating')}</span>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <p className="text-2xs text-white/55 leading-snug">
        {t('settingsRecovery.regeneratedDesc')}
      </p>

      <div className="card-flat p-3 space-y-2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-medium">{t('settingsRecovery.partB')}</span>
          {usbSaved && <span className="text-success text-2xs ml-auto">✓</span>}
        </div>
        <Button
          variant="secondary"
          fullWidth
          size="sm"
          leftIcon={<Save className="h-3.5 w-3.5" />}
          onClick={saveUsb}
        >
          {t('settingsRecovery.savePartB')}
        </Button>
      </div>

      <div className="card-flat p-3 space-y-2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-medium">{t('settingsRecovery.partC')}</span>
          {paperSaved && <span className="text-success text-2xs ml-auto">✓</span>}
        </div>
        <div className="flex gap-2 pt-1">
          <Button
            variant="secondary"
            fullWidth
            size="sm"
            leftIcon={<Save className="h-3.5 w-3.5" />}
            onClick={saveFileC}
          >
            {t('stepRecovery.saveCFileBtn')}
          </Button>
          <Button
            variant="secondary"
            fullWidth
            size="sm"
            leftIcon={<Copy className="h-3.5 w-3.5" />}
            onClick={copyC}
          >
            {t('settingsRecovery.copyPartC')}
          </Button>
        </div>
      </div>

      <Button
        onClick={onClose}
        fullWidth
        size="md"
        disabled={!usbSaved || !paperSaved}
      >
        {t('settingsRecovery.done')}
      </Button>
      {(!usbSaved || !paperSaved) && (
        <p className="text-2xs text-white/40 text-center">
          {t('settingsRecovery.saveBothHint')}
        </p>
      )}
    </div>
  );
}
