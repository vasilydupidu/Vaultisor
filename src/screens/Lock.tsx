import { useEffect, useRef, useState } from "react";
import { Fingerprint, Key, Lock as LockIcon, RefreshCcw } from "lucide-react";
import {
  apiVaultLockInfo,
  apiVaultUnlock,
  apiVaultUnlockAcceptRollback,
  rollbackSnapshot,
  apiVaultUnlockWithFido2,
  apiSystemCheck,
} from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { PinKeypad } from "@/components/ui/PinKeypad";
import { BrandLogo } from "@/components/BrandLogo";
import { BackgroundPattern } from "@/components/BackgroundPattern";
import { useToast } from "@/components/ui/Toast";
import { Sheet } from "@/components/ui/Sheet";
import { cn } from "@/lib/cn";
import { sanitizeError } from "@/lib/sanitizeError";
import {
  PASSPHRASE_MIN,
  PIN_ALNUM_MAX,
  PIN_ALNUM_MIN,
  PIN_DIGIT_MAX,
  PIN_DIGIT_MIN,
} from "@/lib/pinRules";
import { RecoveryFlow } from "./lock/RecoveryFlow";
import { useTranslation } from 'react-i18next';
import { LanguageToggle } from '@/components/LanguageToggle';

interface Props {
  onUnlocked: () => void;
  onReset: () => void;
}

/**
 * Отмена пользователем не является ошибкой и не должна показывать тост.
 * Раньше проверка была по русской подстроке сообщения backend,
 * из-за чего при английском интерфейсе отмена Windows Hello всё равно
 * показывалась как ошибка.
 */
function isUserCancelled(message: string): boolean {
  const lower = message.toLowerCase();
  return (
    lower.includes("отменен") ||
    lower.includes("отменён") ||
    lower.includes("cancel")
  );
}

export function LockScreen({ onUnlocked, onReset }: Props) {
  const [pin, setPin] = useState("");
  const [busyTarget, setBusyTarget] = useState<"pin" | "hello" | "fido2" | null>(null);
  const busy = busyTarget !== null;
  const [shake, setShake] = useState(false);
  const [recoverOpen, setRecoverOpen] = useState(false);
  // DATA_ROLLBACK: базы старее подтверждённых. PIN держится только до решения
  // пользователя, чтобы явное «продолжить» не требовало ввода заново.
  const [rollbackPin, setRollbackPin] = useState<string | null>(null);
  const [rollbackId, setRollbackId] = useState<string | null>(null);
  const [acceptingRollback, setAcceptingRollback] = useState(false);
  const [recoverReason, setRecoverReason] =
    useState<"forgot-pin" | "device-mismatch">("forgot-pin");
  const [helloAvailable, setHelloAvailable] = useState(false);
  const [fido2Available, setFido2Available] = useState(false);
  const [tpmAvailable, setTpmAvailable] = useState(true);
  const [appVersion, setAppVersion] = useState("");
  // Ввод буквенно-цифрового PIN (для хранилищ, созданных с усиленным PIN).
  // Флаг не хранится в БД — пользователь переключается вручную; unlock просто
  // принимает строку и пробует развернуть master.
  const [alnum, setAlnum] = useState(false);
  const alnumInputRef = useRef<HTMLInputElement>(null);
  // WebView2: явный фокус для условно-рендеримого буквенного поля.
  useEffect(() => {
    if (!alnum) return;
    const t = setTimeout(() => alnumInputRef.current?.focus(), 0);
    return () => clearTimeout(t);
  }, [alnum]);
  const toast = useToast();
  const { t } = useTranslation();

  useEffect(() => {
    setPin("");
    apiVaultLockInfo()
      .then((info) => {
        setHelloAvailable(info.use_windows_hello);
        setFido2Available(info.fido2_enabled);
      })
      .catch(() => {
        setHelloAvailable(false);
        setFido2Available(false);
      });

    apiSystemCheck()
      .then((sys) => setTpmAvailable(sys.tpm_available))
      .catch(() => setTpmAvailable(true));

    import("@tauri-apps/api/app")
      .then((m) => m.getVersion())
      .then(setAppVersion)
      .catch(() => {});
  }, []);

  /** Разблокировка всегда начинается с PIN Vaultisor; Hello и FIDO2 —
   *  дополнительные факторы, а не альтернатива ему. */
  const handleError = (e: unknown) => {
    const raw = typeof e === "string" ? e : e instanceof Error ? e.message : String(e);
    if (raw.includes("DEVICE_MISMATCH")) {
      setRecoverReason("device-mismatch");
      setRecoverOpen(true);
      return;
    }
    const snapshot = rollbackSnapshot(raw);
    if (snapshot && pin) {
      setRollbackId(snapshot);
      setRollbackPin(pin);
      setPin("");
      return;
    }
    setShake(true);
    setTimeout(() => setShake(false), 380);
    setPin("");
    const sanitized = sanitizeError(e, t('lock.unlockFailed'));
    if (isUserCancelled(raw) || isUserCancelled(sanitized)) {
      return;
    }
    toast.error(sanitized);
  };

  const submit = async () => {
    if (busy) return;
    // Не отправляем заведомо короткий ввод — иначе он засчитывается как
    // неудачная попытка и увеличивает задержку PIN. Минимум согласован с backend:
    // 11 цифр для PIN (TPM) либо 15 символов для мастер-пароля.
    const minLen = tpmAvailable ? PIN_DIGIT_MIN : PASSPHRASE_MIN;
    if (pin.length < minLen) {
      toast.error(
        tpmAvailable ? t('lock.pinMinDigits', { min: minLen }) : t('lock.passMinChars', { min: minLen }),
      );
      return;
    }
    setBusyTarget("pin");
    try {
      await apiVaultUnlock(pin);
      onUnlocked();
    } catch (e) {
      handleError(e);
    } finally {
      setBusyTarget(null);
    }
  };

  const handleFido2Unlock = async () => {
    if (busy) return;
    setBusyTarget("fido2");
    try {
      await apiVaultUnlockWithFido2();
      onUnlocked();
    } catch (e) {
      handleError(e);
    } finally {
      setBusyTarget(null);
    }
  };

  return (
    <div className="relative h-full flex flex-col items-center px-5 pt-8 pb-5">
      {tpmAvailable && (
        <button
          onClick={() => {
            setAlnum((v) => !v);
            setPin("");
          }}
          className="absolute top-[12px] right-[54px] z-50 px-2 py-[2px] border border-white/15 rounded-sm bg-white/6 hover:bg-white/12 text-white/55 hover:text-white/85 text-[11px] font-semibold tracking-wider transition-all leading-[1.6] cursor-pointer"
          title={alnum ? t('lock.pinModeDigits') : t('lock.pinModeAlnum')}
        >
          {alnum ? "ABC" : "123"}
        </button>
      )}
      <LanguageToggle />
      <BackgroundPattern opacity={0.7} />

      <div className="flex flex-col items-center gap-3 mb-6">
        <BrandLogo size={56} />
        <div className="text-center space-y-0.5">
          <div className="text-2xs uppercase tracking-wider text-white/45 inline-flex items-center gap-1.5">
            <LockIcon className="h-3 w-3" /> {t('lock.locked')}
          </div>
          <h1 className="text-lg font-medium">
            {tpmAvailable ? t('lock.enterPin') : t('lock.enterMasterPass')}
          </h1>
          {helloAvailable && (
            <p className="text-xs text-white/45">{t('lock.enhancedHello')}</p>
          )}
        </div>
      </div>

      <div className="flex-1 flex items-center min-h-0 w-full justify-center">
        {tpmAvailable ? (
          alnum ? (
            <div className={cn("w-full max-w-[260px] px-1 py-4 flex flex-col items-center justify-center min-h-[140px]", shake && "animate-shake")}>
              <Input
                ref={alnumInputRef}
                type="password"
                value={pin}
                onChange={(e) => setPin(e.target.value.replace(/[^\p{L}\p{N}]/gu, ""))}
                onClick={() => alnumInputRef.current?.focus()}
                placeholder={t('lock.pinAlnumPlaceholder')}
                disabled={busy}
                autoFocus
                maxLength={PIN_ALNUM_MAX}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && pin.length >= PIN_ALNUM_MIN) submit();
                }}
                className="text-center font-mono tracking-widest text-lg"
              />
            </div>
          ) : (
            <PinKeypad
              value={pin}
              onChange={setPin}
              maxLen={PIN_DIGIT_MAX}
              minLen={PIN_DIGIT_MIN}
              onSubmit={submit}
              shake={shake}
              // Пока открыт Sheet восстановления, keypad не должен реагировать
              // на физическую клавиатуру.
              disabled={busy || recoverOpen}
            />
          )
        ) : (
          <div className={cn("w-full max-w-[260px] px-1 py-4 flex flex-col items-center justify-center min-h-[140px]", shake && "animate-shake")}>
            <Input
              type="password"
              value={pin}
              onChange={(e) => setPin(e.target.value)}
              placeholder={t('lock.masterPassPlaceholder')}
              disabled={busy}
              onKeyDown={(e) => {
                if (e.key === "Enter" && pin.length >= PASSPHRASE_MIN) {
                  submit();
                }
              }}
              className="text-center font-mono tracking-widest text-lg"
            />
          </div>
        )}
      </div>

      <div className="w-full pt-3 space-y-1.5 shrink-0">
        <Button
          onClick={submit}
          disabled={busy}
          fullWidth
          size="md"
          loading={busyTarget === "pin"}
          leftIcon={helloAvailable ? <Fingerprint className="h-4 w-4 text-emerald-400" /> : undefined}
        >
          {helloAvailable ? t('lock.unlockEnhanced') : t('lock.unlock')}
        </Button>
        {fido2Available && (
          <Button
            variant="secondary"
            onClick={handleFido2Unlock}
            disabled={busy}
            fullWidth
            size="md"
            loading={busyTarget === "fido2"}
            leftIcon={<Key className="h-4 w-4 text-brand-400" />}
            className="border-brand-500/30 hover:bg-brand-500/10 text-brand-300"
          >
            FIDO2
          </Button>
        )}
        <Button
          variant="ghost"
          fullWidth
          size="sm"
          leftIcon={<RefreshCcw className="h-3.5 w-3.5" />}
          onClick={() => {
            setRecoverReason("forgot-pin");
            setRecoverOpen(true);
          }}
        >
          {tpmAvailable ? t('lock.forgotPin') : t('lock.forgotPass')}
        </Button>
      </div>

      <Sheet
        open={recoverOpen}
        onClose={() => setRecoverOpen(false)}
        title={
          recoverReason === "device-mismatch"
            ? t('lock.deviceMismatchTitle')
            : t('lock.recoveryTitle')
        }
      >
        <RecoveryFlow
          reason={recoverReason}
          tpmAvailable={tpmAvailable}
          onDone={() => setRecoverOpen(false)}
          onResetParent={onReset}
        />
      </Sheet>
      <Sheet
        open={rollbackPin !== null}
        onClose={() => setRollbackPin(null)}
        title={t("lock.rollbackTitle")}
      >
        <div className="space-y-4">
          <p className="text-sm text-white/70 leading-snug">{t("lock.rollbackDesc")}</p>
          <p className="text-2xs text-danger leading-snug">{t("lock.rollbackWarning")}</p>
          <div className="flex gap-2">
            <Button variant="secondary" fullWidth onClick={() => setRollbackPin(null)}>
              {t("common.cancel")}
            </Button>
            <Button
              variant="danger"
              fullWidth
              loading={acceptingRollback}
              onClick={async () => {
                if (!rollbackPin || !rollbackId) return;
                setAcceptingRollback(true);
                try {
                  await apiVaultUnlockAcceptRollback(rollbackPin, rollbackId);
                  setRollbackPin(null);
                  onUnlocked();
                } catch (e) {
                  // Файлы сменились после предупреждения: показываем новый
                  // снимок заново, а не принимаем его молча.
                  const next = rollbackSnapshot(e);
                  if (next) {
                    setRollbackId(next);
                  } else {
                    setRollbackPin(null);
                    handleError(e);
                  }
                } finally {
                  setAcceptingRollback(false);
                }
              }}
            >
              {t("lock.rollbackAccept")}
            </Button>
          </div>
        </div>
      </Sheet>
      <div className="text-[10px] text-white/20 mt-2 select-none">
        Vaultisor{appVersion ? ` v${appVersion}` : ""}
      </div>
    </div>
  );
}
