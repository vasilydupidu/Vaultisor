import { useEffect, useRef, useState } from "react";
import { Fingerprint, Key, Lock as LockIcon, RefreshCcw } from "lucide-react";
import {
  apiVaultLockInfo,
  apiVaultUnlock,
  apiVaultUnlockWithHello,
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
import { RecoveryFlow } from "./lock/RecoveryFlow";
import { useTranslation } from 'react-i18next';
import { LanguageToggle } from '@/components/LanguageToggle';

interface Props {
  onUnlocked: () => void;
  onReset: () => void;
}

export function LockScreen({ onUnlocked, onReset }: Props) {
  const [pin, setPin] = useState("");
  const [busyTarget, setBusyTarget] = useState<"pin" | "hello" | "fido2" | null>(null);
  const busy = busyTarget !== null;
  const [shake, setShake] = useState(false);
  const [recoverOpen, setRecoverOpen] = useState(false);
  const [recoverReason, setRecoverReason] =
    useState<"forgot-pin" | "device-mismatch">("forgot-pin");
  const [helloAvailable, setHelloAvailable] = useState(false);
  const [fido2Available, setFido2Available] = useState(false);
  const [tpmAvailable, setTpmAvailable] = useState(true);
  const [appVersion, setAppVersion] = useState("");
  // L-05: ввод буквенно-цифрового PIN (для хранилищ, созданных с усиленным PIN).
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
        setHelloAvailable(info.use_windows_hello && info.hello_blob_present);
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

  /**
   * Универсальный submit:
   *  - если PIN введён → unlock через PIN;
   *  - если PIN пустой и доступен Hello → vault_unlock_with_hello.
   */
  const handleError = (e: unknown) => {
    const raw = typeof e === "string" ? e : e instanceof Error ? e.message : String(e);
    if (raw.includes("DEVICE_MISMATCH")) {
      setRecoverReason("device-mismatch");
      setRecoverOpen(true);
      return;
    }
    setShake(true);
    setTimeout(() => setShake(false), 380);
    setPin("");
    const sanitized = sanitizeError(e, t('lock.unlockFailed'));
    if (sanitized.includes("отменена пользователем") || raw.includes("отменена пользователем") || raw.includes("Canceled by user")) {
      return;
    }
    toast.error(sanitized);
  };

  const submit = async () => {
    if (busy) return;
    // L-08: не отправляем заведомо короткий ввод — иначе он засчитывается как
    // неудачная попытка и приближает lockout. Минимум согласован с backend:
    // 8 цифр для PIN (TPM) либо 15 символов для мастер-пароля.
    const minLen = tpmAvailable ? 8 : 15;
    if (pin.length > 0 && pin.length < minLen) {
      toast.error(
        tpmAvailable ? t('lock.pinMinDigits', { min: minLen }) : t('lock.passMinChars', { min: minLen }),
      );
      return;
    }
    const target = pin.length > 0 ? "pin" : "hello";
    setBusyTarget(target);
    try {
      if (pin.length > 0) {
        await apiVaultUnlock(pin);
      } else if (helloAvailable) {
        await apiVaultUnlockWithHello();
      } else {
        toast.error(tpmAvailable ? t('lock.enterPin') : t('lock.enterMasterPass'));
        return;
      }
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
          className="absolute top-[12px] right-[54px] z-50 px-2 py-[2px] border border-white/15 rounded bg-white/6 hover:bg-white/12 text-white/55 hover:text-white/85 text-[11px] font-semibold tracking-wider transition-all leading-[1.6] cursor-pointer"
          title={alnum ? "Цифровой PIN (123)" : "Буквенно-цифровой PIN (ABC)"}
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
                onKeyDown={(e) => {
                  if (e.key === "Enter" && pin.length >= 8) submit();
                }}
                className="text-center font-mono tracking-widest text-lg"
              />
            </div>
          ) : (
            <PinKeypad
              value={pin}
              onChange={setPin}
              minLen={8}
              onSubmit={submit}
              shake={shake}
              disabled={busy}
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
                if (e.key === "Enter" && pin.length >= 4) {
                  submit();
                }
              }}
              className="text-center font-mono tracking-widest text-lg"
            />
          </div>
        )}
      </div>

      <div className="w-full pt-3 space-y-1.5 shrink-0">
        {pin.length === 0 && helloAvailable && fido2Available ? (
          <div className="flex items-center gap-2 w-full">
            <Button
              onClick={submit}
              disabled={busy}
              fullWidth
              size="md"
              loading={busyTarget === "hello"}
              leftIcon={<Fingerprint className="h-4 w-4 text-emerald-400" />}
              className="flex-1"
            >
              Hello
            </Button>
            <Button
              variant="secondary"
              onClick={handleFido2Unlock}
              disabled={busy}
              fullWidth
              size="md"
              loading={busyTarget === "fido2"}
              leftIcon={<Key className="h-4 w-4 text-brand-400" />}
              className="flex-1 border-brand-500/30 hover:bg-brand-500/10 text-brand-300"
            >
              FIDO2
            </Button>
          </div>
        ) : (
          <>
            <Button
              onClick={submit}
              disabled={busy}
              fullWidth
              size="md"
              loading={pin.length > 0 ? busyTarget === "pin" : busyTarget === "hello"}
              leftIcon={pin.length === 0 && helloAvailable ? <Fingerprint className="h-4 w-4 text-emerald-400" /> : undefined}
            >
              {pin.length === 0 && helloAvailable ? t('lock.unlockHello') : t('lock.unlock')}
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
          </>
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
      <div className="text-[10px] text-white/20 mt-2 select-none">
        Vaultisor{appVersion ? ` v${appVersion}` : ""}
      </div>
    </div>
  );
}
