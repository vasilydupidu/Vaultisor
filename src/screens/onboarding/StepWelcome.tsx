import { Download, Lock, ShieldCheck, WifiOff } from "lucide-react";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { apiVaultImport } from "@/lib/api";
import { sanitizeError } from "@/lib/sanitizeError";
import { useToast } from "@/components/ui/Toast";
import { Button } from "@/components/ui/Button";
import { BrandLogo } from "@/components/BrandLogo";
import { useTranslation } from "react-i18next";
import { LanguageToggle } from "@/components/LanguageToggle";

interface Props {
  onNext: () => void;
  /** Колбэк после успешного импорта существующей БД. */
  onImported?: () => void;
}

const points = [
  {
    icon: <Lock className="h-3.5 w-3.5" />,
    titleKey: "welcome.localStoreTitle",
    textKey: "welcome.localStoreDesc",
  },
  {
    icon: <ShieldCheck className="h-3.5 w-3.5" />,
    titleKey: "welcome.hwProtectTitle",
    textKey: "welcome.hwProtectDesc",
  },
  {
    icon: <WifiOff className="h-3.5 w-3.5" />,
    titleKey: "welcome.noNetTitle",
    textKey: "welcome.noNetDesc",
  },
];

export function StepWelcome({ onNext, onImported }: Props) {
  const { t } = useTranslation();
  const toast = useToast();
  const handleImport = async () => {
    const path = await openDialog({
      multiple: false,
      title: t("welcome.importDialogTitle"),
      filters: [{ name: "Vaultisor Vault", extensions: ["vault", "db"] }],
    });
    if (!path || Array.isArray(path)) return;
    try {
      await apiVaultImport(path as string);
      toast.success(t("welcome.imported"));
      onImported?.();
    } catch (e) {
      toast.error(sanitizeError(e, t("welcome.importError")));
    }
  };

  return (
    <div className="h-full flex flex-col">
      <LanguageToggle />
      <div className="flex-1 flex flex-col items-center text-center pt-1 min-h-0">
        <div className="relative mb-3">
          <div className="absolute inset-0 -m-3 rounded-full bg-brand-500/10 blur-2xl" />
          <BrandLogo size={56} />
        </div>
        <h1 className="text-xl font-medium tracking-tight">Vaultisor</h1>
        <p className="text-xs text-white/55 mt-1 max-w-[260px]">
          {t("welcome.subtitle")}
        </p>

        <div className="w-full space-y-1.5 mt-5">
          {points.map((p, i) => (
            <div key={i} className="card-flat p-2.5 flex items-start gap-2.5 text-left">
              <div className="h-7 w-7 shrink-0 rounded-lg bg-brand-500/15 text-brand-300 flex items-center justify-center">
                {p.icon}
              </div>
              <div className="flex-1 space-y-0.5 min-w-0">
                <div className="text-xs font-medium leading-tight">{t(p.titleKey)}</div>
                <div className="text-2xs text-white/55 leading-snug">{t(p.textKey)}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="shrink-0 pt-3 space-y-1.5">
        <Button onClick={onNext} fullWidth size="md">
          {t("welcome.start")}
        </Button>
        <Button
          onClick={handleImport}
          variant="ghost"
          fullWidth
          size="sm"
          leftIcon={<Download className="h-3.5 w-3.5" />}
        >
          {t("welcome.importBtn")}
        </Button>
      </div>
    </div>
  );
}
