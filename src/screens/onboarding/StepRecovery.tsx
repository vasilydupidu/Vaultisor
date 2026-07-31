import { useEffect, useState } from "react";
import { AlertTriangle, Copy, FileText, KeyRound, Save, Usb } from "lucide-react";
import { save as saveDialog } from "@tauri-apps/plugin-dialog";
import {
  apiClipboardCopyText,
  apiRecoveryDisable,
  apiRecoverySaveToUsb,
  type VaultCreateOutput,
} from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Switch } from "@/components/ui/Switch";
import { useToast } from "@/components/ui/Toast";
import { Spinner } from "@/components/ui/Spinner";
import { cn } from "@/lib/cn";
import { sanitizeError } from "@/lib/sanitizeError";
import { useTranslation, Trans } from "react-i18next";

interface Props {
  /** Если null — vault ещё не создан, нужно вызвать onCreate. */
  createdShares: { b: string; c: string } | null;
  onCreate: () => Promise<VaultCreateOutput>;
  onComplete: () => void;
}

export function StepRecovery({ createdShares, onCreate, onComplete }: Props) {
  const [busy, setBusy] = useState(false);
  const [shareB, setShareB] = useState<string | null>(createdShares?.b ?? null);
  const [shareC, setShareC] = useState<string | null>(createdShares?.c ?? null);
  const [usbSaved, setUsbSaved] = useState(false);
  const [paperSaved, setPaperSaved] = useState(false);
  // По умолчанию — recovery включено (рекомендуется).
  // Если выключить — части B и C можно не сохранять, vault создастся,
  // но при потере PIN восстановление будет НЕВОЗМОЖНО.
  const [enabled, setEnabled] = useState(true);
  const toast = useToast();
  const { t } = useTranslation();

  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Создаём vault при первом монтировании.
  useEffect(() => {
    if (createdShares) {
      setShareB(createdShares.b);
      setShareC(createdShares.c);
      return;
    }
    let mounted = true;
    setBusy(true);
    onCreate()
      .then((out) => {
        if (!mounted) return;
        setShareB(out.recovery_share_b_hex);
        setShareC(out.recovery_share_c_hex);
        setErrorMsg(null);
      })
      .catch((e) => {
        if (!mounted) return;
        setErrorMsg(sanitizeError(e, t("stepRecovery.createError")));
      })
      .finally(() => {
        if (mounted) setBusy(false);
      });
    return () => {
      mounted = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSaveUsb = async () => {
    if (!shareB) return;
    try {
      const path = await saveDialog({
        title: t("stepRecovery.saveBDialogTitle"),
        defaultPath: "vaultisor-recovery-part-b.vss",
        filters: [{ name: "Vaultisor Share", extensions: ["vss"] }],
      });
      if (!path) return;
      await apiRecoverySaveToUsb(shareB, path);
      setUsbSaved(true);
    } catch {
      toast.error(t("stepRecovery.saveBError"));
    }
  };

  const handleCopyC = async () => {
    if (!shareC) return;
    try {
      await apiClipboardCopyText(shareC);
      setPaperSaved(true);
      toast.success(t("stepRecovery.copyCSuccess"));
    } catch {
      toast.error(t("stepRecovery.copyCError"));
    }
  };

  // Сохранение Части C в файл .txt
  const handleSaveFileC = async () => {
    if (!shareC) return;
    try {
      const path = await saveDialog({
        title: t("stepRecovery.saveCDialogTitle"),
        defaultPath: "vaultisor-recovery-part-c.txt",
        filters: [{ name: "Text File", extensions: ["txt"] }],
      });
      if (!path) return;
      await apiRecoverySaveToUsb(shareC, path);
      setPaperSaved(true);
      toast.success(t("stepRecovery.saveCSuccess"));
    } catch {
      toast.error(t("stepRecovery.saveCError"));
    }
  };

  if (busy && !shareB) {
    return (
      <div className="h-full flex flex-col items-center justify-center gap-4 text-white/60">
        <Spinner className="h-6 w-6" />
        <span>{t("stepRecovery.creating")}</span>
      </div>
    );
  }

  if (errorMsg) {
    return (
      <div className="h-full flex flex-col">
        <div className="flex-1 overflow-y-auto min-h-0 space-y-3">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="h-4 w-4 text-danger" />
            <h2 className="text-base font-medium text-danger">
              {t("stepRecovery.failedTitle")}
            </h2>
          </div>
          <p className="text-xs text-white/60 leading-snug">
            {t("stepRecovery.failedDesc")}
          </p>
          <div className="card-flat p-3 text-2xs font-mono break-all text-white/80 max-h-[180px] overflow-y-auto">
            {errorMsg}
          </div>
          <p className="text-2xs text-white/45 leading-snug">
            <Trans i18nKey="stepRecovery.failedHint">
              Подробный лог: <span className="font-mono">./vault/logs/Vaultisor.log</span>
              <br />
              Закройте приложение и запустите снова — онбординг начнётся с нуля.
            </Trans>
          </p>
        </div>
      </div>
    );
  }

  const canFinish = !enabled || (usbSaved && paperSaved);

  return (
    <div className="h-full flex flex-col">
      <div className="flex-1 overflow-y-auto min-h-0">
        <div className="mb-3">
          <div className="flex items-center gap-2 mb-1.5">
            <KeyRound className="h-4 w-4 text-brand-400" />
            <h2 className="text-base font-medium">{t("stepRecovery.title")}</h2>
          </div>
          <p className="text-2xs text-white/55 leading-snug">
            {t("stepRecovery.desc")}
          </p>
        </div>

        {/* Toggle */}
        <div className="card-flat p-3 flex items-start gap-2.5 mb-3">
          <div className="flex-1 min-w-0">
            <div className="text-xs font-medium">{t("stepRecovery.savePartsTitle")}</div>
            <p className="text-2xs text-white/55 mt-0.5 leading-snug">
              {enabled
                ? t("stepRecovery.savePartsEnabledDesc")
                : t("stepRecovery.savePartsDisabledDesc")}
            </p>
          </div>
          <Switch checked={enabled} onChange={setEnabled} aria-label={t("stepRecovery.savePartsTitle")} />
        </div>

        {!enabled && (
          <div className="card-flat p-2.5 flex items-start gap-2 text-2xs text-warning/85 mb-3">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
            <span className="leading-snug">
              {t("stepRecovery.disabledWarning")}
            </span>
          </div>
        )}

        {enabled && (
          <div className="space-y-2.5">
            <div className="card-flat p-3 space-y-2">
              <div className="flex items-start gap-2.5">
                <div className="h-7 w-7 rounded-lg bg-brand-500/15 text-brand-300 flex items-center justify-center shrink-0">
                  <Usb className="h-3.5 w-3.5" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium">{t("stepRecovery.partBTitle")}</div>
                  <p className="text-2xs text-white/55 mt-0.5 leading-snug">
                    {t("stepRecovery.partBDesc")}
                  </p>
                </div>
                {usbSaved && <span className="text-success text-2xs">✓</span>}
              </div>
              <Button
                onClick={handleSaveUsb}
                variant="secondary"
                fullWidth
                size="sm"
                leftIcon={<Save className="h-3.5 w-3.5" />}
              >
                {t("stepRecovery.saveBBtn")}
              </Button>
            </div>

            <div className="card-flat p-3 space-y-2">
              <div className="flex items-start gap-2.5">
                <div className="h-7 w-7 rounded-lg bg-brand-500/15 text-brand-300 flex items-center justify-center shrink-0">
                  <FileText className="h-3.5 w-3.5" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium">{t("stepRecovery.partCTitle")}</div>
                  <p className="text-2xs text-white/55 mt-0.5 leading-snug">
                    {t("stepRecovery.partCDesc")}
                  </p>
                </div>
                {paperSaved && <span className="text-success text-2xs">✓</span>}
              </div>
              <div className="flex gap-2 pt-1">
                <Button
                  onClick={handleSaveFileC}
                  variant="secondary"
                  fullWidth
                  size="sm"
                  leftIcon={<Save className="h-3.5 w-3.5" />}
                >
                  {t("stepRecovery.saveCFileBtn")}
                </Button>
                <Button
                  onClick={handleCopyC}
                  variant="secondary"
                  fullWidth
                  size="sm"
                  leftIcon={<Copy className="h-3.5 w-3.5" />}
                >
                  {t("common.copy")}
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="shrink-0 pt-3 space-y-2">
        <Button
          onClick={async () => {
            // Если пользователь выключил восстановление, стираем
            // локальную часть A (которую backend уже сохранил при vault_create).
            if (!enabled) {
              try {
                await apiRecoveryDisable();
              } catch {
                // ignore — на онбординге сессия активна, ошибки маловероятны
              }
            }
            onComplete();
          }}
          fullWidth
          size="md"
          disabled={!canFinish}
          className={cn(!canFinish && "opacity-60")}
        >
          {enabled ? t("common.finish") : t("stepRecovery.finishWithout")}
        </Button>

        {enabled && !canFinish && (
          <Button
            variant="ghost"
            fullWidth
            size="sm"
            onClick={onComplete}
            className="text-white/45 hover:text-brand-400 hover:bg-brand-500/5 transition-app"
          >
            {t("stepRecovery.skipBtn")}
          </Button>
        )}
      </div>
    </div>
  );
}
