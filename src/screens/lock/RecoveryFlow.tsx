import { useState } from "react";
import {
  apiRecoveryLoadFromUsb,
  apiRecoveryRestore,
} from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { useToast } from "@/components/ui/Toast";
import { sanitizeError } from "@/lib/sanitizeError";
import {
  PASSPHRASE_MIN,
  PIN_ALNUM_MAX,
  PIN_ALNUM_MIN,
  PIN_DIGIT_MAX,
  PIN_DIGIT_MIN,
} from "@/lib/pinRules";
import { useTranslation } from 'react-i18next';

interface RecoveryFlowProps {
  reason: "forgot-pin" | "device-mismatch";
  tpmAvailable: boolean;
  onDone: () => void;
  onResetParent: () => void;
}

export function RecoveryFlow({
  reason,
  tpmAvailable,
  onDone,
  onResetParent,
}: RecoveryFlowProps) {
  const [shareUsb, setShareUsb] = useState<string | null>(null);
  const [shareManual, setShareManual] = useState("");
  const [newPin, setNewPin] = useState("");
  const [newPinConfirm, setNewPinConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  // L-05: разрешить задать буквенно-цифровой PIN и при восстановлении.
  // Без TPM 2.0 нужен мастер-пароль ≥15 → сразу буквенный режим (цифровой
  // ограничен PIN_DIGIT_MAX символами и не даст набрать 15).
  const [alnum, setAlnum] = useState(!tpmAvailable);
  const sanitizePin = (v: string) =>
    alnum ? v.replace(/[^\p{L}\p{N}]/gu, "") : v.replace(/\D/g, "");
  // Без TPM 2.0 восстановление создаёт хранилище с мастер-паролем (≥15).
  // Границы берём из общих правил, чтобы UI не расходился с backend.
  const minPinLen = !tpmAvailable
    ? PASSPHRASE_MIN
    : alnum
      ? PIN_ALNUM_MIN
      : PIN_DIGIT_MIN;
  const toast = useToast();
  const { t } = useTranslation();

  const loadFromUsb = async () => {
    try {
      const out = await apiRecoveryLoadFromUsb();
      setShareUsb(out.share_hex);
      toast.success(t('recoveryFlow.usbLoaded'));
    } catch {
      toast.error(t('recoveryFlow.fileReadError'));
    }
  };

  const restore = async () => {
    if (newPin !== newPinConfirm) {
      toast.error(t('recoveryFlow.pinsNotMatch'));
      return;
    }
    if (newPin.length < minPinLen) {
      toast.error(
        !tpmAvailable
          ? t('recoveryFlow.passMinChars')
          : alnum
            ? t('recoveryFlow.alnumMinChars')
            : t('recoveryFlow.digitMinChars'),
      );
      return;
    }
    const shares: string[] = [];
    if (shareUsb) shares.push(shareUsb);
    if (shareManual.trim()) shares.push(shareManual.trim());
    // На том же ПК («забыл PIN») доля A подгружается на backend автоматически —
    // достаточно одной введённой части. На другом устройстве нужны обе (B+C).
    const minShares = reason === "forgot-pin" ? 1 : 2;
    if (shares.length < minShares) {
      toast.error(
        minShares === 1
          ? t('recoveryFlow.oneShareRequired')
          : t('recoveryFlow.twoSharesRequired'),
      );
      return;
    }
    setBusy(true);
    try {
      await apiRecoveryRestore(shares, newPin);
      toast.success(t('recoveryFlow.success'));
      onDone();
      onResetParent();
    } catch (e) {
      // Показываем реальную причину (например: доли не от этого хранилища),
      // а не проглатываем её — иначе понятная backend-ошибка теряется.
      toast.error(sanitizeError(e, t('recoveryFlow.failed')));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <p className="text-sm text-white/60">
        {reason === "device-mismatch"
          ? t('recoveryFlow.deviceMismatchDesc')
          : t('recoveryFlow.forgotPinDesc')}
      </p>

      <div className="space-y-2">
        <Button variant="secondary" fullWidth onClick={loadFromUsb}>
          {t('recoveryFlow.selectUsb')}
        </Button>
        {shareUsb && <div className="text-2xs text-success">{t('recoveryFlow.partLoaded')}</div>}
      </div>

      <Input
        label={t('recoveryFlow.manualLabel')}
        value={shareManual}
        onChange={(e) => setShareManual(e.target.value)}
        placeholder={t('recoveryFlow.manualPlaceholder')}
      />

      <div className="space-y-2">
        <Input
          label={t('recoveryFlow.newPin')}
          type="password"
          inputMode={alnum ? "text" : "numeric"}
          maxLength={alnum ? PIN_ALNUM_MAX : PIN_DIGIT_MAX}
          value={newPin}
          onChange={(e) => setNewPin(sanitizePin(e.target.value))}
        />
        <Input
          label={t('recoveryFlow.confirmPin')}
          type="password"
          inputMode={alnum ? "text" : "numeric"}
          maxLength={alnum ? PIN_ALNUM_MAX : PIN_DIGIT_MAX}
          value={newPinConfirm}
          onChange={(e) => setNewPinConfirm(sanitizePin(e.target.value))}
        />
        {tpmAvailable ? (
          <button
            type="button"
            onClick={() => {
              setAlnum((v) => !v);
              setNewPin("");
              setNewPinConfirm("");
            }}
            className="text-2xs text-brand-300 hover:text-brand-200 underline underline-offset-2"
          >
            {alnum ? t('recoveryFlow.digitalPin') : t('recoveryFlow.alnumPin')}
          </button>
        ) : (
          <p className="text-2xs text-white/45 leading-snug">
            {t('recoveryFlow.noTpmDesc')}
          </p>
        )}
      </div>

      <Button onClick={restore} fullWidth loading={busy} size="lg">
        {t('recoveryFlow.restore')}
      </Button>
    </div>
  );
}
