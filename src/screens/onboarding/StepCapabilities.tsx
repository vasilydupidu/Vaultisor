import { CheckCircle2, Info, ShieldCheck, XCircle } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Spinner } from "@/components/ui/Spinner";
import type { SystemCheck } from "@/lib/api";
import { cn } from "@/lib/cn";
import { useTranslation } from "react-i18next";

interface Props {
  caps: SystemCheck | null;
  onNext: () => void;
}

interface Row {
  title: string;
  description: string;
  state: "ok" | "missing" | "info";
}

export function StepCapabilities({ caps, onNext }: Props) {
  const { t } = useTranslation();

  const rows: Row[] = caps
    ? [
        {
          title: "TPM 2.0",
          description: caps.tpm_available
            ? t("capabilities.tpmOk")
            : t("capabilities.tpmMissing"),
          state: caps.tpm_available ? "ok" : "missing",
        },
        {
          title: "DPAPI (защита аккаунта Windows)",
          description: caps.dpapi_available
            ? t("capabilities.dpapiOk")
            : t("capabilities.dpapiMissing"),
          state: caps.dpapi_available ? "ok" : "missing",
        },
        {
          title: "Windows Hello",
          description: caps.windows_hello_available
            ? caps.tpm_available
              ? t("capabilities.helloTpmOk")
              : t("capabilities.helloTpmMissing")
            : t("capabilities.helloMissing"),
          state: caps.windows_hello_available ? "ok" : "missing",
        },
      ]
    : [];

  const isTpmMissing = caps ? !caps.tpm_available : false;
  const isDpapiMissing = caps ? !caps.dpapi_available : false;
  // Нет ни TPM, ни DPAPI → устройство не может привязать ключ → защищать нечем.
  const cannotProtect = isTpmMissing && isDpapiMissing;

  return (
    <div className="h-full flex flex-col">
      <div className="flex-1 overflow-y-auto min-h-0">
        <div className="mb-4">
          <div className="flex items-center gap-2 mb-1.5">
            <ShieldCheck className="h-4 w-4 text-brand-400" />
            <h2 className="text-base font-medium">{t("capabilities.title")}</h2>
          </div>
          <p className="text-xs text-white/55">
            {t("capabilities.desc")}
          </p>
        </div>

        {!caps ? (
          <div className="flex items-center justify-center py-8 text-white/60 gap-2 text-sm">
            <Spinner className="h-4 w-4" /> {t("capabilities.checking")}
          </div>
        ) : (
          <div className="space-y-1.5">
            {rows.map((r) => (
              <div key={r.title} className="card-flat p-2.5 flex items-start gap-2.5">
                <StateIcon state={r.state} />
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium leading-tight">{r.title}</div>
                  <div className="text-2xs text-white/55 leading-snug mt-0.5">
                    {r.description}
                  </div>
                </div>
              </div>
            ))}

          </div>
        )}
      </div>

      <div className="shrink-0 pt-3 space-y-3">
        {cannotProtect ? (
          <div className="card-flat border border-danger/30 bg-danger/10 p-3 rounded-lg flex items-start gap-2.5 text-xs text-danger leading-relaxed animate-fade-in">
            <XCircle className="h-4 w-4 text-danger shrink-0 mt-0.5" />
            <div>
              <div className="font-semibold text-danger">{t("capabilities.cannotProtectTitle")}</div>
              {t("capabilities.cannotProtectDesc")}
            </div>
          </div>
        ) : (
          isTpmMissing && (
            <div className="card-flat border border-warning/20 bg-warning/10 p-3 rounded-lg flex items-start gap-2.5 text-xs text-warning leading-relaxed animate-fade-in">
              <Info className="h-4 w-4 text-warning shrink-0 mt-0.5" />
              <div>
                <div className="font-semibold text-warning">{t("capabilities.tpmMissingTitle")}</div>
                {t("capabilities.tpmMissingDesc")}
              </div>
            </div>
          )
        )}
        <Button onClick={onNext} fullWidth size="md" disabled={!caps || cannotProtect}>
          {t("common.continue")}
        </Button>
      </div>
    </div>
  );
}

function StateIcon({ state }: { state: Row["state"] }) {
  const cls = cn(
    "h-7 w-7 shrink-0 rounded-lg flex items-center justify-center [&_svg]:h-3.5 [&_svg]:w-3.5",
    state === "ok" && "bg-success/15 text-success",
    state === "missing" && "bg-warning/15 text-warning",
    state === "info" && "bg-white/[0.06] text-white/50",
  );
  return (
    <div className={cls}>
      {state === "ok" && <CheckCircle2 />}
      {state === "missing" && <XCircle />}
      {state === "info" && <Info />}
    </div>
  );
}
