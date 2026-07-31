import { useEffect, useState } from "react";
import { ChevronLeft } from "lucide-react";
import { apiSystemCheck, apiVaultCreate, type SystemCheck } from "@/lib/api";
import { useToast } from "@/components/ui/Toast";
import { BackgroundPattern } from "@/components/BackgroundPattern";
import { IconButton } from "@/components/ui/IconButton";
import { StepWelcome } from "./StepWelcome";
import { StepCapabilities } from "./StepCapabilities";
import { StepPin } from "./StepPin";
import { StepHello } from "./StepHello";
import { StepRecovery } from "./StepRecovery";
import { cn } from "@/lib/cn";
import { useTranslation } from "react-i18next";

interface Props {
  onComplete: () => void;
  /** Если пользователь импортировал готовую БД на Welcome — переходим в Locked. */
  onImported?: () => void;
}

type Step = "welcome" | "caps" | "pin" | "hello" | "recovery";

const order: Step[] = ["welcome", "caps", "pin", "hello", "recovery"];

export function Onboarding({ onComplete, onImported }: Props) {
  const { t } = useTranslation();
  const [step, setStep] = useState<Step>("welcome");
  const [pin, setPin] = useState("");
  const [enableHello, setEnableHello] = useState(false);
  const [caps, setCaps] = useState<SystemCheck | null>(null);
  const [recoveryShares, setRecoveryShares] = useState<{ b: string; c: string } | null>(null);
  const toast = useToast();

  // Проверяем системные возможности один раз — при выходе из welcome.
  useEffect(() => {
    if (step === "caps" && !caps) {
      apiSystemCheck()
        .then(setCaps)
        .catch(() => setCaps({
          dpapi_available: false,
          windows_hello_available: false,
          vbs_enclave_available: false,
          tpm_available: false,
          windows_version: "—",
        }));
    }
  }, [step, caps]);

  const idx = order.indexOf(step);
  const goTo = (s: Step) => setStep(s);
  const next = () => {
    let nextIdx = idx + 1;
    if (order[nextIdx] === "hello" && !caps?.tpm_available) {
      nextIdx++;
    }
    goTo(order[Math.min(nextIdx, order.length - 1)]!);
  };
  const back = () => {
    let prevIdx = idx - 1;
    if (order[prevIdx] === "hello" && !caps?.tpm_available) {
      prevIdx--;
    }
    goTo(order[Math.max(prevIdx, 0)]!);
  };

  // Шаг recovery нажимает "Завершить" → создаём vault и завершаем онбординг.
  const finalize = async () => {
    try {
      const out = await apiVaultCreate({
        pin,
        use_dpapi: caps?.dpapi_available ?? false,
        use_windows_hello: enableHello,
      });
      setRecoveryShares({ b: out.recovery_share_b_hex, c: out.recovery_share_c_hex });
      setPin("");
      // Recovery-step сам закроет окно и вызовет onComplete после показа QR/USB.
      return out;
    } catch (e) {
      toast.error(`${t("stepRecovery.createError")}: ${formatErr(e, t)}`);
      throw e;
    }
  };

  return (
    <div className="relative flex flex-col h-full text-white">
      <BackgroundPattern />
      {/* Top-bar */}
      <div className="px-4 pt-3 pb-2 flex items-center justify-between min-h-[44px]">
        {idx > 0 && step !== "recovery" ? (
          <IconButton
            icon={<ChevronLeft />}
            aria-label={t("common.back")}
            variant="subtle"
            onClick={back}
          />
        ) : (
          <span className="w-10" />
        )}

        <div className="flex items-center gap-1.5">
          {order.map((s, i) => (
            <span
              key={s}
              className={cn(
                "h-1.5 rounded-full transition-app",
                i <= idx ? "w-5 bg-brand-500" : "w-2 bg-white/15",
              )}
            />
          ))}
        </div>

        <span className="w-10" />
      </div>

      {/*
        flex-1 + min-h-0 + px/pb даёт step'ам контейнер фиксированной
        высоты; внутри каждый StepX сам решает что скроллить, а кнопку
        прижимает к низу через свой flex.
      */}
      <div className="flex-1 min-h-0 px-5 pb-4 flex flex-col">
        {step === "welcome" && (
          <StepWelcome onNext={next} onImported={onImported} />
        )}
        {step === "caps" && (
          <StepCapabilities caps={caps} onNext={next} />
        )}
        {step === "pin" && (
          <StepPin
            value={pin}
            onChange={setPin}
            onNext={next}
            tpmAvailable={caps?.tpm_available ?? false}
          />
        )}
        {step === "hello" && (
          <StepHello
            available={caps?.windows_hello_available ?? false}
            tpmSigningSupported={caps?.tpm_available ?? false}
            enabled={enableHello}
            onToggle={setEnableHello}
            onNext={next}
            onSkip={next}
          />
        )}
        {step === "recovery" && (
          <StepRecovery
            createdShares={recoveryShares}
            onCreate={finalize}
            onComplete={onComplete}
          />
        )}
      </div>
    </div>
  );
}

function formatErr(e: unknown, t: (key: string) => string): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  try {
    return JSON.stringify(e);
  } catch {
    return t("onboarding.unknownError");
  }
}
