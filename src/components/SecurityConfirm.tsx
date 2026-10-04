import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { apiSecurityAuthorize, type SecurityAction } from "@/lib/api";
import { sanitizeError } from "@/lib/sanitizeError";
import { PIN_ALNUM_MAX } from "@/lib/pinRules";
import { Sheet } from "@/components/ui/Sheet";
import { Input } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";

/**
 * Действия, меняющие политику безопасности, backend выполняет только по
 * свежему подтверждению PIN (и Hello, если он включён). Разрешение живёт на
 * стороне backend, привязано к действию и сессии и одноразово — фронтенд его
 * не хранит и передать «разрешено» не может.
 *
 * `authorized(action, run)`: выполнить `run`; если backend ответил
 * `AUTH_REQUIRED`, спросить PIN, получить разрешение и повторить `run` один
 * раз. Отмена диалога — `AuthCancelled`.
 */
export class AuthCancelled extends Error {
  constructor() {
    super("AUTH_CANCELLED");
  }
}

export const isAuthCancelled = (e: unknown) => e instanceof AuthCancelled;

export const isAuthRequired = (e: unknown) =>
  (typeof e === "string" ? e : e instanceof Error ? e.message : "").startsWith("AUTH_REQUIRED:");

/** Что именно подтверждает пользователь. */
function actionText(t: TFunction, action: SecurityAction): string {
  switch (action) {
    case "change_pin":
      return t("securityConfirm.action.changePin");
    case "enable_hello":
      return t("securityConfirm.action.enableHello");
    case "disable_hello":
      return t("securityConfirm.action.disableHello");
    case "enable_step_up":
      return t("securityConfirm.action.enableStepUp");
    case "disable_step_up":
      return t("securityConfirm.action.disableStepUp");
    case "bind_fido":
      return t("securityConfirm.action.bindFido");
    case "unbind_fido":
      return t("securityConfirm.action.unbindFido");
    case "regenerate_recovery":
      return t("securityConfirm.action.regenerateRecovery");
    case "disable_recovery":
      return t("securityConfirm.action.disableRecovery");
    case "restore_backup":
      return t("securityConfirm.action.restoreBackup");
    case "export_vault":
      return t("securityConfirm.action.exportVault");
    case "change_backup_directory":
      return t("securityConfirm.action.changeBackupDirectory");
  }
}

type Authorized = <T>(action: SecurityAction, run: () => Promise<T>) => Promise<T>;

const Ctx = createContext<Authorized | null>(null);

interface Pending {
  action: SecurityAction;
  resolve: () => void;
  reject: (e: unknown) => void;
}

export function SecurityConfirmProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  const [pending, setPending] = useState<Pending | null>(null);
  const [pin, setPin] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const pendingRef = useRef<Pending | null>(null);

  const close = (outcome: "done" | "cancel") => {
    const current = pendingRef.current;
    pendingRef.current = null;
    setPending(null);
    setPin("");
    setError("");
    if (!current) return;
    if (outcome === "done") current.resolve();
    else current.reject(new AuthCancelled());
  };

  const askPin = useCallback(
    (action: SecurityAction) =>
      new Promise<void>((resolve, reject) => {
        const next = { action, resolve, reject };
        pendingRef.current = next;
        setPending(next);
      }),
    [],
  );

  const authorized = useCallback<Authorized>(
    async (action, run) => {
      try {
        return await run();
      } catch (e) {
        if (!isAuthRequired(e)) throw e;
      }
      await askPin(action);
      return run();
    },
    [askPin],
  );

  const submit = async () => {
    if (!pending || !pin) return;
    setBusy(true);
    setError("");
    try {
      await apiSecurityAuthorize(pending.action, pin);
      close("done");
    } catch (e) {
      setPin("");
      setError(sanitizeError(e, t("securityConfirm.failed")));
    } finally {
      setBusy(false);
    }
  };

  const value = useMemo(() => authorized, [authorized]);

  return (
    <Ctx.Provider value={value}>
      {children}
      <Sheet open={pending !== null} onClose={() => close("cancel")} title={t("securityConfirm.title")}>
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <p className="text-sm text-white/65">
            {pending ? actionText(t, pending.action) : ""}
          </p>
          <Input
            type="password"
            autoComplete="current-password"
            autoFocus
            value={pin}
            onChange={(e) => setPin(e.target.value)}
            placeholder={t("securityConfirm.pinPrompt")}
            maxLength={PIN_ALNUM_MAX}
            disabled={busy}
            error={error || undefined}
          />
          <div className="flex gap-2">
            <Button variant="secondary" fullWidth type="button" onClick={() => close("cancel")} disabled={busy}>
              {t("common.cancel")}
            </Button>
            <Button fullWidth type="submit" loading={busy} disabled={!pin}>
              {t("securityConfirm.confirm")}
            </Button>
          </div>
        </form>
      </Sheet>
    </Ctx.Provider>
  );
}

export function useSecurityConfirm(): Authorized {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useSecurityConfirm: <SecurityConfirmProvider> not mounted");
  return ctx;
}
