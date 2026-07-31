import { useEffect, useRef, useState } from "react";
import { KeyRound, RefreshCw, Eye, EyeOff } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { PinKeypad } from "@/components/ui/PinKeypad";
import { cn } from "@/lib/cn";
import { validatePinLocal } from "@/lib/pinRules";
import { useTranslation } from "react-i18next";

interface Props {
  value: string;
  onChange: (v: string) => void;
  onNext: () => void;
  tpmAvailable: boolean;
}

const PIN_MIN = 8;
const PIN_MAX = 12;
const PASS_MIN = 15;

export function StepPin({ value, onChange, onNext, tpmAvailable }: Props) {
  const { t } = useTranslation();
  // M-03: короткий цифровой PIN допустим ТОЛЬКО при аппаратном TPM (совпадает с
  // backend vault_create: без TPM Device Secret нельзя защитить PIN от офлайн-
  // перебора, поэтому backend требует мастер-пароль ≥15 символов). DPAPI сам по
  // себе — это ACL уровня ОС, а не крипто-якорь, поэтому короткий PIN он не
  // «разрешает». Иначе онбординг предлагал бы PIN, который backend отвергнет.
  const canUsePin = tpmAvailable;
  const [confirm, setConfirm] = useState("");
  const [stage, setStage] = useState<"create" | "confirm">("create");
  const [error, setError] = useState<string | null>(null);
  const [shake, setShake] = useState(false);
  const [showPass, setShowPass] = useState(false);
  // L-05: усиленный режим — PIN с буквами и цифрами (для тех, кому нужна
  // повышенная стойкость). Доступен на TPM-устройствах вместо цифрового PIN.
  const [alnum, setAlnum] = useState(false);
  const alnumInputRef = useRef<HTMLInputElement>(null);
  const toggleAlnum = () => {
    setAlnum((v) => !v);
    onChange("");
    setConfirm("");
    setError(null);
  };
  // В WebView2 autoFocus у условно-рендеримого <input> срабатывает ненадёжно:
  // после переключения на буквенный режим поле оставалось без фокуса, и
  // физическая клавиатура «не печатала». Фокусируем явно через ref.
  useEffect(() => {
    if (!alnum) return;
    const t = setTimeout(() => alnumInputRef.current?.focus(), 0);
    return () => clearTimeout(t);
  }, [alnum, stage]);

  // Генератор безопасных мастер-паролей (15 символов)
  const generatePassphrase = () => {
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=";
    let pass = "";
    const bytes = new Uint8Array(PASS_MIN);
    crypto.getRandomValues(bytes);
    for (let i = 0; i < PASS_MIN; i++) {
      pass += chars[bytes[i]! % chars.length];
    }
    onChange(pass);
    setError(null);
  };

  // Валидация
  const localValidate = (val: string): string | null =>
    validatePinLocal(val, !canUsePin ? "passphrase" : alnum ? "alnum" : "digit");

  const handleCreateSubmit = () => {
    const err = localValidate(value);
    if (err) {
      setError(err);
      setShake(true);
      setTimeout(() => setShake(false), 400);
      return;
    }
    setError(null);
    setStage("confirm");
  };

  const handleConfirmSubmit = () => {
    if (confirm !== value) {
      setError(canUsePin ? t("stepPin.pinNotMatch") : t("stepPin.passNotMatch"));
      setShake(true);
      setTimeout(() => setShake(false), 400);
      setConfirm("");
      return;
    }
    onNext();
  };

  useEffect(() => {
    if (stage === "create") {
      setConfirm("");
    }
  }, [stage]);

  // Вид с длинным паролем — только если НЕТ ни TPM, ни DPAPI (редкий случай).
  if (!canUsePin) {
    return (
      <div className="h-full flex flex-col">
        <div className="mb-3">
          <div className="flex items-center gap-2 mb-1">
            <KeyRound className="h-4 w-4 text-brand-400" />
            <h2 className="text-base font-medium">
              {stage === "create" ? t("stepPin.createPassTitle") : t("stepPin.confirmPassTitle")}
            </h2>
          </div>
          <p className="text-xs text-white/55 leading-snug">
            {stage === "create"
              ? t("stepPin.createPassDesc", { min: PASS_MIN })
              : t("stepPin.confirmPassDesc")}
          </p>
        </div>

        <div className="flex-1 flex flex-col items-center justify-center min-h-0 space-y-4 py-2">
          <div className={cn("w-full max-w-sm space-y-2.5", shake && "animate-shake")}>
            <div className="relative">
              <input
                type={showPass ? "text" : "password"}
                value={stage === "create" ? value : confirm}
                onChange={(e) => (stage === "create" ? onChange(e.target.value) : setConfirm(e.target.value))}
                placeholder={stage === "create" ? t("stepPin.passPlaceholder") : t("stepPin.passConfirmPlaceholder")}
                className="w-full bg-white/[0.04] border border-white/[0.08] focus:border-brand-500 rounded-lg py-2 px-3 text-sm text-white focus:outline-none transition-app pr-10"
              />
              <button
                type="button"
                onClick={() => setShowPass(!showPass)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-white/40 hover:text-white/70"
              >
                {showPass ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>

            {stage === "create" && (
              <div className="flex items-center justify-between">
                <Button
                  variant="secondary"
                  size="sm"
                  leftIcon={<RefreshCw className="h-3 w-3" />}
                  onClick={generatePassphrase}
                >
                  {t("stepPin.generate")}
                </Button>
                {value.length > 0 && (
                  <span
                    className={cn(
                      "text-2xs px-2 py-0.5 rounded font-medium",
                      value.length < 15 ? "bg-danger/10 text-danger" : "bg-success/15 text-success"
                    )}
                  >
                    {value.length < 15 ? t("stepPin.weak") : t("stepPin.strong")} {t("stepPin.length", { len: value.length })}
                  </span>
                )}
              </div>
            )}
          </div>

          {error && (
            <div className="text-xs text-danger animate-fade-in text-center">{error}</div>
          )}

          {stage === "confirm" && (
            <p className="text-3xs text-white/45 leading-normal text-center max-w-xs animate-fade-in">
              {t("stepPin.savePassHint")}
            </p>
          )}
        </div>

        <div className="shrink-0 pt-3 space-y-1.5">
          {stage === "create" ? (
            <Button onClick={handleCreateSubmit} fullWidth size="md" disabled={value.length < PASS_MIN}>
              {t("common.next")}
            </Button>
          ) : (
            <>
              <Button onClick={handleConfirmSubmit} fullWidth size="md" disabled={confirm.length < PASS_MIN}>
                {t("common.confirm")}
              </Button>
              <Button
                variant="ghost"
                fullWidth
                size="sm"
                onClick={() => {
                  setStage("create");
                  setError(null);
                }}
              >
                {t("stepPin.changePass")}
              </Button>
            </>
          )}
        </div>
      </div>
    );
  }

  // Обычный вид с PIN-клавиатурой при наличии TPM 2.0
  return (
    <div className="h-full flex flex-col">
      <div className="mb-3">
        <div className="flex items-center gap-2 mb-1.5">
          <KeyRound className="h-4 w-4 text-brand-400" />
          <h2 className="text-base font-medium">
            {stage === "create" ? t("stepPin.createPinTitle") : t("stepPin.confirmPinTitle")}
          </h2>
        </div>
        <p className="text-xs text-white/55 leading-snug">
          {stage === "create"
            ? alnum
              ? t("stepPin.createPinAlnumDesc", { min: PIN_MIN })
              : t("stepPin.createPinDigitDesc", { min: PIN_MIN, max: PIN_MAX })
            : t("stepPin.confirmPinDesc")}
        </p>
      </div>

      <div className="flex-1 flex flex-col items-center justify-center min-h-0 space-y-4">
        {alnum ? (
          <div className={cn("w-full max-w-sm", shake && "animate-shake")}>
            <div className="relative">
              <input
                ref={alnumInputRef}
                type={showPass ? "text" : "password"}
                value={stage === "create" ? value : confirm}
                onChange={(e) => {
                  // L-05: буквы (любой раскладки, вкл. кириллицу) и цифры;
                  // символы/пробелы отсекаем.
                  const v = e.target.value.replace(/[^\p{L}\p{N}]/gu, "");
                  if (stage === "create") onChange(v);
                  else setConfirm(v);
                }}
                onClick={() => alnumInputRef.current?.focus()}
                placeholder={stage === "create" ? t("stepPin.alnumPlaceholder") : t("stepPin.pinConfirmPlaceholder")}
                autoFocus
                className="w-full bg-white/[0.04] border border-white/[0.08] focus:border-brand-500 rounded-lg py-2 px-3 text-sm text-white focus:outline-none transition-app pr-10"
              />
              <button
                type="button"
                onClick={() => setShowPass(!showPass)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-white/40 hover:text-white/70"
              >
                {showPass ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </div>
        ) : (
          <PinKeypad
            value={stage === "create" ? value : confirm}
            onChange={stage === "create" ? onChange : setConfirm}
            minLen={PIN_MIN}
            maxLen={PIN_MAX}
            shake={shake}
            showDigits={false}
          />
        )}

        {stage === "create" && (
          <button
            type="button"
            onClick={toggleAlnum}
            className="text-2xs text-brand-300 hover:text-brand-200 underline underline-offset-2"
          >
            {alnum ? t("stepPin.digitalPin") : t("stepPin.alnumPin")}
          </button>
        )}

        {error && (
          <div className={cn("mt-1 text-xs text-danger animate-fade-in")}>{error}</div>
        )}
      </div>

      <div className="shrink-0 pt-3 space-y-1.5">
        {stage === "create" ? (
          <Button onClick={handleCreateSubmit} fullWidth size="md" disabled={value.length < PIN_MIN}>
            {t("common.next")}
          </Button>
        ) : (
          <>
            <Button
              onClick={handleConfirmSubmit}
              fullWidth
              size="md"
              disabled={confirm.length < PIN_MIN}
            >
              {t("common.confirm")}
            </Button>
            <Button
              variant="ghost"
              fullWidth
              size="sm"
              onClick={() => {
                setStage("create");
                setError(null);
              }}
            >
              {t("stepPin.changePin")}
            </Button>
          </>
        )}
      </div>
    </div>
  );
}

