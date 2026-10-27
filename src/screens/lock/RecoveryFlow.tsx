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
  PIN_ALNUM_MAX,
  PIN_DIGIT_MAX,
  SECRET_MAX,
  validatePinLocal,
} from "@/lib/pinRules";
import { useTranslation } from 'react-i18next';

/** Одна из двух частей: либо прочитана из файла, либо вставлена текстом. */
interface ShareSlot {
  file: string | null;
  text: string;
}

const EMPTY_SLOT: ShareSlot = { file: null, text: "" };

const slotValue = (slot: ShareSlot): string => slot.file ?? slot.text.trim();

interface ShareSlotFieldProps {
  title: string;
  slot: ShareSlot;
  disabled: boolean;
  onPickFile: () => void;
  onChange: (slot: ShareSlot) => void;
}

function ShareSlotField({ title, slot, disabled, onPickFile, onChange }: ShareSlotFieldProps) {
  const { t } = useTranslation();
  const loaded = slotValue(slot) !== "";
  return (
    <div className="card-flat p-3 space-y-2">
      <div className="flex items-center justify-between gap-2">
        <div className="text-xs font-medium">{title}</div>
        {loaded && <div className="text-2xs text-success">{t('recoveryFlow.partLoaded')}</div>}
      </div>
      {slot.file !== null ? (
        <Button variant="secondary" size="sm" fullWidth disabled={disabled} onClick={() => onChange(EMPTY_SLOT)}>
          {t('recoveryFlow.clearPart')}
        </Button>
      ) : (
        <>
          <Button variant="secondary" size="sm" fullWidth disabled={disabled} onClick={onPickFile}>
            {t('recoveryFlow.selectFile')}
          </Button>
          <Input
            aria-label={`${title}: ${t('recoveryFlow.pasteLabel')}`}
            label={t('recoveryFlow.pasteLabel')}
            value={slot.text}
            onChange={(e) => onChange({ file: null, text: e.target.value })}
            placeholder={t('recoveryFlow.manualPlaceholder')}
            disabled={disabled}
          />
        </>
      )}
    </div>
  );
}

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
  const [shareB, setShareB] = useState<ShareSlot>(EMPTY_SLOT);
  const [shareC, setShareC] = useState<ShareSlot>(EMPTY_SLOT);
  const [newPin, setNewPin] = useState("");
  const [newPinConfirm, setNewPinConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  // Разрешить задать буквенно-цифровой PIN и при восстановлении.
  // Без TPM 2.0 нужен мастер-пароль ≥15 → сразу буквенный режим (цифровой
  // ограничен PIN_DIGIT_MAX символами и не даст набрать 15).
  const [alnum, setAlnum] = useState(!tpmAvailable);
  // Мастер-пароль без TPM может содержать любые символы, включая пробелы и
  // знаки (как в онбординге и на экране входа), поэтому фильтруем только PIN.
  const sanitizePin = (v: string) => {
    if (!tpmAvailable) return v;
    return alnum ? v.replace(/[^\p{L}\p{N}]/gu, "") : v.replace(/\D/g, "");
  };
  const maxLen = !tpmAvailable ? SECRET_MAX : alnum ? PIN_ALNUM_MAX : PIN_DIGIT_MAX;
  const toast = useToast();
  const { t } = useTranslation();

  const bothLoaded = slotValue(shareB) !== "" && slotValue(shareC) !== "";

  const loadFromFile = async (part: "B" | "C", set: (slot: ShareSlot) => void) => {
    try {
      const out = await apiRecoveryLoadFromUsb();
      set({ file: out.share_hex, text: "" });
      toast.success(t('recoveryFlow.fileLoaded', { part }));
    } catch {
      toast.error(t('recoveryFlow.fileReadError'));
    }
  };

  const restore = async () => {
    if (newPin !== newPinConfirm) {
      toast.error(t('recoveryFlow.pinsNotMatch'));
      return;
    }
    // Те же правила, что при создании хранилища: без TPM — пароль, иначе
    // цифровой или буквенно-цифровой PIN по выбранному режиму.
    const formatError = validatePinLocal(
      newPin,
      !tpmAvailable ? "passphrase" : alnum ? "alnum" : "digit",
    );
    if (formatError) {
      toast.error(formatError);
      return;
    }
    const b = slotValue(shareB);
    const c = slotValue(shareC);
    // Нужны обе части, B и C, на любом устройстве: на ПК части нет.
    if (!b || !c) {
      toast.error(t('recoveryFlow.twoSharesRequired'));
      return;
    }
    if (b === c) {
      toast.error(t('recoveryFlow.sharesSame'));
      return;
    }
    setBusy(true);
    try {
      await apiRecoveryRestore([b, c], newPin);
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

      <ShareSlotField
        title={t('recoveryFlow.partBTitle')}
        slot={shareB}
        disabled={busy}
        onPickFile={() => loadFromFile("B", setShareB)}
        onChange={setShareB}
      />
      <ShareSlotField
        title={t('recoveryFlow.partCTitle')}
        slot={shareC}
        disabled={busy}
        onPickFile={() => loadFromFile("C", setShareC)}
        onChange={setShareC}
      />

      <div className="space-y-2">
        <Input
          label={tpmAvailable ? t('recoveryFlow.newPin') : t('recoveryFlow.newPass')}
          type="password"
          inputMode={alnum ? "text" : "numeric"}
          maxLength={maxLen}
          value={newPin}
          onChange={(e) => setNewPin(sanitizePin(e.target.value))}
        />
        <Input
          label={tpmAvailable ? t('recoveryFlow.confirmPin') : t('recoveryFlow.confirmPass')}
          type="password"
          inputMode={alnum ? "text" : "numeric"}
          maxLength={maxLen}
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

      <Button onClick={restore} fullWidth loading={busy} disabled={!bothLoaded} size="lg">
        {t('recoveryFlow.restore')}
      </Button>
    </div>
  );
}
