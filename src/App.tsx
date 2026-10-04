import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { apiVaultExists, apiVaultLock, registerOnLockCallback } from "./lib/api";
import { ToastProvider } from "./components/ui/Toast";
import { SecurityConfirmProvider } from "./components/SecurityConfirm";
import { Onboarding } from "./screens/onboarding";
import { LockScreen } from "./screens/Lock";
import { VaultScreen } from "./screens/Vault";
import { Spinner } from "./components/ui/Spinner";

type AppPhase = "loading" | "onboarding" | "locked" | "unlocked";

/** Бэкенд сообщает, что сессию закрыла система (Win+L, сон, смена пользователя). */
const SESSION_LOCKED_EVENT = "vault://session-locked";

export function App() {
  const [phase, setPhase] = useState<AppPhase>("loading");
  // Колбэк «уйти на экран блокировки» должен работать только когда хранилище
  // действительно открыто: во время онбординга ошибка Locked не означает, что
  // пользователя нужно выкинуть из незавершённого создания хранилища.
  const phaseRef = useRef(phase);
  phaseRef.current = phase;

  const refreshPhase = useCallback(async () => {
    try {
      const exists = await apiVaultExists();
      setPhase(exists ? "locked" : "onboarding");
    } catch {
      // Если backend недоступен — оставляем экран загрузки.
      setPhase("loading");
    }
  }, []);

  useEffect(() => {
    refreshPhase();
  }, [refreshPhase]);

  useEffect(() => {
    registerOnLockCallback(() => {
      if (phaseRef.current === "unlocked") setPhase("locked");
    });
    return () => registerOnLockCallback(null);
  }, []);

  // AUDIT 3.1.1: блокировка сеанса Windows закрывает сессию на бэкенде
  // мгновенно; без этой подписки UI узнавал бы об этом только со следующим
  // heartbeat и до пяти секунд показывал бы открытое хранилище.
  useEffect(() => {
    const unlisten = listen(SESSION_LOCKED_EVENT, () => {
      if (phaseRef.current === "unlocked") setPhase("locked");
    });
    return () => {
      unlisten.then((off) => off()).catch(() => {});
    };
  }, []);

  return (
    <ToastProvider>
      <SecurityConfirmProvider>
      <div className="app-shell relative">
        {phase === "loading" && (
          <div className="flex-1 flex items-center justify-center text-white/60">
            <Spinner className="h-6 w-6" />
          </div>
        )}
        {phase === "onboarding" && (
          <Onboarding
            onComplete={() => setPhase("unlocked") /* vault_create уже разблокировал */}
            onImported={() => refreshPhase() /* импортирован .vault — переход в lock */}
          />
        )}
        {phase === "locked" && (
          <LockScreen onUnlocked={() => setPhase("unlocked")} onReset={() => refreshPhase()} />
        )}
        {phase === "unlocked" && (
          <VaultScreen
            onLock={async () => {
              try {
                await apiVaultLock();
              } finally {
                // Экран блокировки показываем даже если команда не удалась:
                // оставлять открытые данные на экране опаснее, чем показать
                // lock-screen при рассинхроне с бэкендом.
                setPhase("locked");
              }
            }}
          />
        )}
      </div>
      </SecurityConfirmProvider>
    </ToastProvider>
  );
}
