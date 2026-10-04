import { useEffect, useRef, useState } from "react";
import {
  apiGetEnableHealthCheck,
  apiGetEnableGenerator,
  apiSetEnableGenerator,
  apiGetEnablePasswordHistory,
  apiSetEnableHealthCheck,
  apiSetEnablePasswordHistory,
  apiGetFido2Status,
  apiRegisterFido2Key,
  apiUnbindFido2Key,
  apiOpenSecurityKeySettings,
  apiVaultChangePin,
  apiSecuritySetHello,
  apiSecuritySetStepUp,
  apiSettingsGet,
  type Fido2Status,
  type Fido2KeyItem,
  type SettingsDto,
} from "@/lib/api";
import { useTranslation } from "react-i18next";
import { Section, ToggleRow } from "./controls";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { useToast } from "@/components/ui/Toast";
import { isAuthCancelled, useSecurityConfirm } from "@/components/SecurityConfirm";
import { sanitizeError } from "@/lib/sanitizeError";
import { KeyRound, Trash2, AlertTriangle, Shield, Fingerprint } from "lucide-react";
import { PIN_ALNUM_MAX } from "@/lib/pinRules";
import { RetryableRequest } from "@/lib/requestId";

interface Props {
  s: SettingsDto;
  /** Флаги безопасности изменены на backend — актуальные настройки. */
  onSecurityChanged: (s: SettingsDto) => void;
  /** Экран хранилища прячет кнопку генератора, когда его выключили. */
  onGeneratorChanged?: (enabled: boolean) => void;
}

export function SettingsSecurity({ s, onSecurityChanged, onGeneratorChanged }: Props) {
  const { t } = useTranslation();
  const toast = useToast();
  const authorized = useSecurityConfirm();
  const [securityBusy, setSecurityBusy] = useState(false);
  // Повтор привязки или смены PIN после потерянного ответа распознаётся
  // backend'ом и не выполняется второй раз.
  const bindRequest = useRef(new RetryableRequest());
  const pinRequest = useRef(new RetryableRequest());
  const [healthCheck, setHealthCheck] = useState(true);
  const [passwordHistory, setPasswordHistory] = useState(true);
  const [generator, setGenerator] = useState(false);
  const [fido2Status, setFido2Status] = useState<Fido2Status | null>(null);
  const [fido2Loading, setFido2Loading] = useState(false);
  const [addingKey, setAddingKey] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [requirePin, setRequirePin] = useState(true);
  const [confirmDeleteKey, setConfirmDeleteKey] = useState<Fido2KeyItem | null>(null);
  // Текущий PIN спрашивает диалог подтверждения, здесь — только новый.
  const [newPin, setNewPin] = useState("");
  const [confirmPin, setConfirmPin] = useState("");
  const [changingPin, setChangingPin] = useState(false);
  const [deletingLoading, setDeletingLoading] = useState(false);

  const reloadFido2Status = async () => {
    try {
      const st = await apiGetFido2Status();
      setFido2Status(st);
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    apiGetEnableHealthCheck().then(setHealthCheck).catch(() => {});
    apiGetEnableGenerator().then(setGenerator).catch(() => {});
    apiGetEnablePasswordHistory().then(setPasswordHistory).catch(() => {});
    reloadFido2Status();

  }, []);

  const handleToggleGenerator = async (val: boolean) => {
    setGenerator(val);
    try {
      await apiSetEnableGenerator(val);
      onGeneratorChanged?.(val);
    } catch (e) {
      setGenerator(!val);
      toast.error(sanitizeError(e, t("settings.saveError")));
    }
  };

  const handleToggleHealthCheck = async (val: boolean) => {
    setHealthCheck(val);
    try {
      await apiSetEnableHealthCheck(val);
    } catch {
      // ignore
    }
  };

  const handleTogglePasswordHistory = async (val: boolean) => {
    setPasswordHistory(val);
    try {
      await apiSetEnablePasswordHistory(val);
    } catch {
      // ignore
    }
  };

  /** Hello и подтверждение копирования применяются сразу, с подтверждением
   *  PIN; переключатель показывает только то, что backend действительно
   *  сохранил. */
  const applySecurity = async (change: () => Promise<void>) => {
    setSecurityBusy(true);
    try {
      await change();
    } catch (e) {
      if (!isAuthCancelled(e)) toast.error(sanitizeError(e, t("settings.saveError")));
    } finally {
      try {
        onSecurityChanged(await apiSettingsGet());
      } catch {
        // Сессия могла закрыться — экран блокировки покажет это сам.
      }
      setSecurityBusy(false);
    }
  };

  const handleToggleHello = (enabled: boolean) =>
    applySecurity(() =>
      authorized(enabled ? "enable_hello" : "disable_hello", () => apiSecuritySetHello(enabled)),
    );

  const handleToggleStepUp = (enabled: boolean) =>
    applySecurity(() =>
      authorized(enabled ? "enable_step_up" : "disable_step_up", () =>
        apiSecuritySetStepUp(enabled),
      ),
    );

  const handleAddFido2Key = async () => {
    setFido2Loading(true);
    try {
      const nameToUse = newKeyName.trim() || undefined;
      const requestId = bindRequest.current.idFor(JSON.stringify([nameToUse, requirePin]));
      await authorized("bind_fido", () => apiRegisterFido2Key(requestId, nameToUse, requirePin));
      bindRequest.current.done();
      toast.success(t("settingsSecurity.fido2Bound"));
      setAddingKey(false);
      setNewKeyName("");
      setRequirePin(true);
      await reloadFido2Status();
    } catch (e) {
      if (!isAuthCancelled(e)) toast.error(sanitizeError(e, t("sanitizeError.defaultMessage")));
    } finally {
      setFido2Loading(false);
    }
  };

  const handleConfirmDelete = async () => {
    if (!confirmDeleteKey) return;
    setDeletingLoading(true);
    try {
      const id = confirmDeleteKey.id;
      await authorized("unbind_fido", () => apiUnbindFido2Key(id));
      toast.success(t("settingsSecurity.fido2NotBound"));
      setConfirmDeleteKey(null);
      await reloadFido2Status();
    } catch (e) {
      if (!isAuthCancelled(e)) toast.error(sanitizeError(e, t("sanitizeError.defaultMessage")));
    } finally {
      setDeletingLoading(false);
    }
  };

  const handleChangePin = async () => {
    if (newPin !== confirmPin) {
      toast.error(t("settingsSecurity.pinsDoNotMatch"));
      return;
    }
    setChangingPin(true);
    try {
      const requestId = pinRequest.current.idFor(newPin);
      await authorized("change_pin", () => apiVaultChangePin(newPin, requestId));
      pinRequest.current.done();
      setNewPin("");
      setConfirmPin("");
      toast.success(t("settingsSecurity.changePinSuccess"));
    } catch (e) {
      if (!isAuthCancelled(e)) toast.error(sanitizeError(e));
    } finally {
      setChangingPin(false);
    }
  };

  const keysList = fido2Status?.keys ?? [];

  return (
    <>
      <Section title={t("settingsSecurity.title")}>
        <ToggleRow
          title={t("settingsSecurity.authTitle")}
          description={
            s.use_windows_hello
              ? t("settingsSecurity.authDescEnabled")
              : t("settingsSecurity.authDescDisabled")
          }
          checked={s.require_auth_for_copy && s.use_windows_hello}
          disabled={!s.use_windows_hello || securityBusy}
          onChange={handleToggleStepUp}
        />
        <ToggleRow
          title={t("settingsSecurity.helloTitle")}
          description={
            s.use_windows_hello
              ? t("settingsSecurity.helloDescEnabled")
              : t("settingsSecurity.helloDescDisabled")
          }
          checked={s.use_windows_hello}
          disabled={securityBusy}
          onChange={handleToggleHello}
        />
        <p className="text-2xs text-white/40 leading-snug">
          {t("settingsSecurity.helloHint")}
        </p>
        {s.use_windows_hello && (
          <p className="text-2xs text-danger font-medium leading-snug mt-1">
            {t("settingsSecurity.helloKeyWarning")}
          </p>
        )}
      </Section>

      <Section title={t("settingsSecurity.changePinTitle")}>
        <p className="text-2xs text-white/55 leading-snug">
          {t("settingsSecurity.changePinDesc")}
        </p>
        <Input
          type="password"
          autoComplete="new-password"
          value={newPin}
          onChange={(e) => setNewPin(e.target.value)}
          placeholder={t("settingsSecurity.newPinPrompt")}
          maxLength={PIN_ALNUM_MAX}
          disabled={changingPin}
        />
        <Input
          type="password"
          autoComplete="new-password"
          value={confirmPin}
          onChange={(e) => setConfirmPin(e.target.value)}
          placeholder={t("settingsSecurity.confirmNewPinPrompt")}
          maxLength={PIN_ALNUM_MAX}
          disabled={changingPin}
        />
        <Button
          variant="secondary"
          size="sm"
          fullWidth
          loading={changingPin}
          disabled={changingPin || !newPin}
          onClick={handleChangePin}
        >
          {t("settingsSecurity.changePinBtn")}
        </Button>
      </Section>

      <Section title={t("settingsSecurity.fido2Title")}>
        <p className="text-2xs text-white/55 mb-2 leading-snug">
          {t("settingsSecurity.fido2Desc")}
        </p>
        <Button
          variant="secondary"
          size="sm"
          fullWidth
          className="mb-3"
          onClick={async () => {
            try {
              await apiOpenSecurityKeySettings();
            } catch (e) {
              toast.error(sanitizeError(e, t("settingsSecurity.fido2OpenSetupFailed")));
            }
          }}
        >
          {t("settingsSecurity.fido2OpenWindowsSetup")}
        </Button>

        {keysList.length > 0 && (
          <div className="mb-3 space-y-2">
            <div className="text-2xs font-semibold text-white/40 uppercase tracking-wider">
              {t("settingsSecurity.fido2KeysListTitle", { count: keysList.length })}
            </div>
            {keysList.map((key) => (
              <div
                key={key.id}
                className="flex items-center justify-between p-2.5 rounded-lg bg-white/[0.04] border border-white/[0.08]"
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className="w-8 h-8 rounded-lg bg-indigo-500/15 border border-indigo-500/30 flex items-center justify-center shrink-0">
                    <KeyRound className="w-4 h-4 text-indigo-400" />
                  </div>
                  <div className="min-w-0">
                    <div className="text-xs font-medium text-white/90 truncate flex items-center gap-1.5">
                      {key.name}
                      <span className={`inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[10px] font-medium ${
                        key.require_pin
                          ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                          : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                      }`}>
                        {key.require_pin ? <Shield className="w-2.5 h-2.5" /> : <Fingerprint className="w-2.5 h-2.5" />}
                        {key.require_pin ? 'PIN' : 'Touch'}
                      </span>
                    </div>
                    <div className="text-2xs text-white/40 truncate">
                      {key.model_name} · <span className="font-mono">{key.credential_id_preview}</span>
                    </div>
                  </div>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setConfirmDeleteKey(key)}
                  className="text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 p-1.5 h-auto ml-2 shrink-0"
                  title={t("settingsSecurity.fido2Unbind")}
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </Button>
              </div>
            ))}
          </div>
        )}

        {/* Modal/Box подтверждения удаления */}
        {confirmDeleteKey && (
          <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 space-y-3 mb-3">
            <div className="flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div className="min-w-0">
                <div className="text-xs font-semibold text-rose-200">
                  {t("settingsSecurity.fido2UnbindConfirmTitle")}
                </div>
                <div className="text-2xs text-rose-300/80 leading-snug mt-0.5">
                  {t("settingsSecurity.fido2UnbindConfirmDesc", { name: confirmDeleteKey.name })}
                </div>
              </div>
            </div>
            <div className="flex items-center justify-end gap-2 pt-1 border-t border-rose-500/20">
              <Button
                variant="secondary"
                size="sm"
                onClick={() => setConfirmDeleteKey(null)}
                disabled={deletingLoading}
              >
                {t("common.cancel")}
              </Button>
              <Button
                variant="danger"
                size="sm"
                loading={deletingLoading}
                onClick={handleConfirmDelete}
              >
                {t("settingsSecurity.fido2UnbindConfirmAction")}
              </Button>
            </div>
          </div>
        )}

        {addingKey ? (
          <div className="p-3 rounded-lg bg-white/[0.04] border border-indigo-500/30 space-y-3 mb-2">
            <div className="text-xs text-white/80 font-medium">
              {t("settingsSecurity.fido2KeyNamePrompt")}
            </div>
            <Input
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
              placeholder={t("settingsSecurity.fido2KeyNamePlaceholder")}
              autoFocus
            />
            <div className="flex gap-2 mt-2">
              <button
                type="button"
                onClick={() => setRequirePin(true)}
                className={`flex-1 p-2 rounded-lg border text-xs text-center transition-all ${
                  requirePin
                    ? 'bg-indigo-500/15 border-indigo-500/50 text-indigo-200'
                    : 'bg-white/[0.03] border-white/[0.1] text-white/50 hover:border-white/20'
                }`}
              >
                <Shield className="w-4 h-4 mx-auto mb-1" />
                ПИН + Touch
                <div className="text-[10px] mt-0.5 opacity-60">Безопаснее</div>
              </button>
              <button
                type="button"
                onClick={() => setRequirePin(false)}
                className={`flex-1 p-2 rounded-lg border text-xs text-center transition-all ${
                  !requirePin
                    ? 'bg-emerald-500/15 border-emerald-500/50 text-emerald-200'
                    : 'bg-white/[0.03] border-white/[0.1] text-white/50 hover:border-white/20'
                }`}
              >
                <Fingerprint className="w-4 h-4 mx-auto mb-1" />
                Touch-only
                <div className="text-[10px] mt-0.5 opacity-60">Быстрее</div>
              </button>
            </div>
            <div className="flex items-center gap-2 justify-end">
              <Button
                variant="secondary"
                size="sm"
                onClick={() => {
                  setAddingKey(false);
                  setNewKeyName("");
                  setRequirePin(true);
                }}
                disabled={fido2Loading}
              >
                {t("common.cancel")}
              </Button>
              <Button
                variant="primary"
                size="sm"
                loading={fido2Loading}
                onClick={handleAddFido2Key}
              >
                {t("settingsSecurity.fido2Bind")}
              </Button>
            </div>
          </div>
        ) : (
          <div className="pt-1">
            <Button
              variant="primary"
              size="sm"
              loading={fido2Loading}
              onClick={() => setAddingKey(true)}
              fullWidth
            >
              {keysList.length > 0
                ? t("settingsSecurity.fido2AddKey")
                : t("settingsSecurity.fido2Bind")}
            </Button>
          </div>
        )}
      </Section>

      <Section title={t("settingsSecurity.healthCheckTitle")}>
        <ToggleRow
          title={t("settingsSecurity.healthCheckTitle")}
          description={t("settingsSecurity.healthCheckDesc")}
          checked={healthCheck}
          onChange={handleToggleHealthCheck}
        />
        <div className="pt-2 border-t border-white/[0.06]">
          <ToggleRow
            title={t("settingsSecurity.passwordHistoryTitle")}
            description={t("settingsSecurity.passwordHistoryDesc")}
            checked={passwordHistory}
            onChange={handleTogglePasswordHistory}
          />
        </div>
        <div className="pt-2 border-t border-white/[0.06]">
          <ToggleRow
            title={t("settingsGenerator.title")}
            description={t("settingsGenerator.desc")}
            checked={generator}
            onChange={handleToggleGenerator}
          />
        </div>
      </Section>
    </>
  );
}
