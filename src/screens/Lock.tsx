import { useEffect, useRef, useState } from "react";
import { Fingerprint, Lock as LockIcon, RefreshCcw } from "lucide-react";
import {
  apiVaultLockInfo,
  apiVaultUnlock,
  apiVaultUnlockWithHello,
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
  const [busy, setBusy] = useState(false);
  const [shake, setShake] = useState(false);
  const [recoverOpen, setRecoverOpen] = useState(false);
  const [recoverReason, setRecoverReason] =
    useState<"forgot-pin" | "device-mismatch">("forgot-pin");
  const [helloAvailable, setHelloAvailable] = useState(false);
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
      .then((info) =>
        setHelloAvailable(info.use_windows_hello && info.hello_blob_present),
      )
      .catch(() => setHelloAvailable(false));

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
    const msg = typeof e === "string" ? e : e instanceof Error ? e.message : String(e);
    if (msg.startsWith("DEVICE_MISMATCH")) {
      // Перенос на другое устройство → автоматически открываем Recovery.
      setRecoverReason("device-mismatch");
      setRecoverOpen(true);
      setPin("");
      return;
    }
    if (msg.startsWith("TOO_MANY_ATTEMPTS")) {
      // Лимит исчерпан → автоматически открываем Recovery с понятным
      // контекстом (рестарт не поможет — счётчик в БД, защищён MAC).
      setRecoverReason("device-mismatch");
      setRecoverOpen(true);
      toast.error(
        t('lock.limitExhausted'),
      );
      return;
    }
    setShake(true);
    setTimeout(() => setShake(false), 380);
    setPin("");
    toast.error(sanitizeError(e, t('lock.unlockFailed')));
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
    setBusy(true);
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
      setBusy(false);
    }
  };

  return (
    <div className="relative h-full flex flex-col items-center px-5 pt-8 pb-5">
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
        <Button
          onClick={submit}
          disabled={busy}
          fullWidth
          size="md"
          loading={busy}
          leftIcon={pin.length === 0 && helloAvailable ? <Fingerprint className="h-4 w-4" /> : undefined}
        >
          {pin.length === 0 && helloAvailable ? t('lock.unlockHello') : t('lock.unlock')}
        </Button>
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
        {tpmAvailable && (
          <Button
            variant="ghost"
            fullWidth
            size="sm"
            onClick={() => {
              setAlnum((v) => !v);
              setPin("");
            }}
          >
            {alnum ? t('lock.digitalPin') : t('lock.alnumPin')}
          </Button>
        )}
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
