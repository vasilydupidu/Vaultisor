import { useCallback, useEffect, useState } from "react";
import { apiVaultExists, apiVaultLock, registerOnLockCallback } from "./lib/api";
import { ToastProvider } from "./components/ui/Toast";
import { Onboarding } from "./screens/onboarding";
import { LockScreen } from "./screens/Lock";
import { VaultScreen } from "./screens/Vault";
import { Spinner } from "./components/ui/Spinner";

type AppPhase = "loading" | "onboarding" | "locked" | "unlocked";

export function App() {
  const [phase, setPhase] = useState<AppPhase>("loading");

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
    registerOnLockCallback(() => {
      setPhase("locked");
    });
  }, [refreshPhase]);

  // Visibility-блокировка отключена: alt-tab и file-dialog'и
  // тоже триггерят visibilitychange, и пользователь оказывался в lock-экране
  // после каждой служебной операции. Полагаемся на idle-таймер из Settings
  // (apiIdleSeconds) и явную кнопку "Заблокировать" в шапке Vault.

  return (
    <ToastProvider>
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
              await apiVaultLock();
              setPhase("locked");
            }}
          />
        )}
      </div>
    </ToastProvider>
  );
}
