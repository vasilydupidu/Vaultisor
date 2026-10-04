import { Fingerprint } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Switch } from "@/components/ui/Switch";
import { useTranslation } from "react-i18next";

interface Props {
  available: boolean;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onNext: () => void;
  onSkip: () => void;
  /** Аппаратный CNG/TPM provider работает на этой системе. Без него Hello недоступен. */
  tpmSigningSupported?: boolean;
}

export function StepHello({
  available,
  enabled,
  onToggle,
  onNext,
  onSkip,
  tpmSigningSupported = true,
}: Props) {
  const { t } = useTranslation();
  return (
    <div className="h-full flex flex-col">
      <div className="flex-1 overflow-y-auto min-h-0">
        <div className="mb-4">
          <div className="flex items-center gap-2 mb-1.5">
            <Fingerprint className="h-4 w-4 text-brand-400" />
            <h2 className="text-base font-medium">{t("helloStep.title")}</h2>
          </div>
          <p className="text-xs text-white/55 leading-snug">
            {t("helloStep.desc")}
          </p>
        </div>

        {!available ? (
          <div className="card-flat p-3 space-y-1.5">
            <div className="text-xs font-medium">{t("helloStep.notAvailTitle")}</div>
            <p className="text-2xs text-white/55 leading-snug">
              {t("helloStep.notAvailDesc")}
            </p>
          </div>
        ) : !tpmSigningSupported ? (
          <div className="card-flat p-3 space-y-1.5 border-warning/30">
            <div className="text-xs font-medium text-warning">{t("helloStep.tpmNotAvailTitle")}</div>
            <p className="text-2xs text-white/65 leading-snug">
              {t("helloStep.tpmNotAvailDesc")}
            </p>
          </div>
        ) : (
          <div className="card-flat p-3 flex items-start gap-2.5">
            <div className="h-9 w-9 rounded-xl bg-brand-500/15 text-brand-300 flex items-center justify-center shrink-0">
              <Fingerprint className="h-4 w-4" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-xs font-medium">{t("helloStep.useHello")}</div>
              <p className="text-2xs text-white/55 mt-0.5 leading-snug">
                {t("helloStep.useHelloDesc")}
              </p>
            </div>
            <div className="mt-0.5">
              <Switch checked={enabled} onChange={onToggle} aria-label="Windows Hello" />
            </div>
          </div>
        )}
      </div>

      <div className="shrink-0 pt-3 space-y-2">
        <Button onClick={onNext} fullWidth size="md">
          {enabled ? t("helloStep.enableAndContinue") : t("common.continue")}
        </Button>
        {!enabled && available && (
          <Button variant="ghost" fullWidth size="sm" onClick={onSkip}>
            {t("common.skip")}
          </Button>
        )}
      </div>
    </div>
  );
}
