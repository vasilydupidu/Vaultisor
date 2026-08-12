import { useEffect, useState } from "react";
import {
  apiGetEnableHealthCheck,
  apiSetEnableHealthCheck,
  apiGetFido2Status,
  apiRegisterFido2Key,
  apiUnbindFido2Key,
  type Fido2Status,
  type Fido2KeyItem,
  type SettingsDto,
} from "@/lib/api";
import { useTranslation } from "react-i18next";
import { Section, ToggleRow } from "./controls";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { useToast } from "@/components/ui/Toast";
import { sanitizeError } from "@/lib/sanitizeError";
import { KeyRound, Trash2, AlertTriangle, Shield, Fingerprint } from "lucide-react";

interface Props {
  s: SettingsDto;
  setS: (s: SettingsDto) => void;
}

export function SettingsSecurity({ s, setS }: Props) {
  const { t } = useTranslation();
  const toast = useToast();
  const [healthCheck, setHealthCheck] = useState(true);
  const [passwordHistory, setPasswordHistory] = useState(true);
  const [fido2Status, setFido2Status] = useState<Fido2Status | null>(null);
  const [fido2Loading, setFido2Loading] = useState(false);
  const [addingKey, setAddingKey] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [requirePin, setRequirePin] = useState(true);
  const [confirmDeleteKey, setConfirmDeleteKey] = useState<Fido2KeyItem | null>(null);
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
    import("@/lib/api").then((m) => m.apiGetEnablePasswordHistory()).then(setPasswordHistory).catch(() => {});
    reloadFido2Status();
  }, []);

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
      const api = await import("@/lib/api");
      await api.apiSetEnablePasswordHistory(val);
    } catch {
      // ignore
    }
  };

  const handleAddFido2Key = async () => {
    setFido2Loading(true);
    try {
      const nameToUse = newKeyName.trim() || undefined;
      await apiRegisterFido2Key(nameToUse, requirePin);
      toast.success(t("settingsSecurity.fido2Bound"));
      setAddingKey(false);
      setNewKeyName("");
      setRequirePin(true);
      await reloadFido2Status();
    } catch (e) {
      toast.error(sanitizeError(e, t("sanitizeError.defaultMessage")));
    } finally {
      setFido2Loading(false);
    }
  };

  const handleConfirmDelete = async () => {
    if (!confirmDeleteKey) return;
    setDeletingLoading(true);
    try {
      await apiUnbindFido2Key(confirmDeleteKey.id);
      toast.success(t("settingsSecurity.fido2NotBound"));
      setConfirmDeleteKey(null);
      await reloadFido2Status();
    } catch (e) {
      toast.error(sanitizeError(e, t("sanitizeError.defaultMessage")));
    } finally {
      setDeletingLoading(false);
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
          disabled={!s.use_windows_hello}
          onChange={(v) => setS({ ...s, require_auth_for_copy: v })}
        />
        <ToggleRow
          title={t("settingsSecurity.helloTitle")}
          description={
            s.use_windows_hello
              ? t("settingsSecurity.helloDescEnabled")
              : t("settingsSecurity.helloDescDisabled")
          }
          checked={s.use_windows_hello}
          onChange={(v) =>
            setS({
              ...s,
              use_windows_hello: v,
              require_auth_for_copy: v ? s.require_auth_for_copy : false,
            })
          }
        />
        <p className="text-2xs text-white/40 leading-snug">
          {t("settingsSecurity.helloHint")}
        </p>
      </Section>

      <Section title={t("settingsSecurity.fido2Title")}>
        <p className="text-2xs text-white/55 mb-3 leading-snug">
          {t("settingsSecurity.fido2Desc")}
        </p>

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
              placeholder={t("settingsSecurity.fido2KeyNamePlaceholder") || "напр., Рутокен MFA #1, YubiKey 5C"}
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
      </Section>
    </>
  );
}
