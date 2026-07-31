import { useEffect } from "react";
import { apiSessionHeartbeat } from "@/lib/api";

/**
 * R-01: авто-блокировка по бездействию В ПРИЛОЖЕНИИ + heartbeat синхронизации.
 * Вынесено из VaultScreen. Активность в окне (мышь/клавиатура) продлевает
 * сессию на бэкенде; локальный таймер мгновенно уводит UI в lock; heartbeat
 * возвращает состояние сессии — если бэкенд залочил, уходим тоже.
 */
export function useIdleAutolock(
  autolockSeconds: number | undefined,
  onLock: () => void,
) {
  useEffect(() => {
    if (!autolockSeconds) return;

    let activeSinceBeat = false;
    let lastActive = Date.now();
    const onActivity = () => {
      activeSinceBeat = true;
      lastActive = Date.now();
    };
    const events = ["mousemove", "mousedown", "keydown", "wheel", "touchstart"];
    events.forEach((e) => window.addEventListener(e, onActivity, { passive: true }));

    const id = window.setInterval(async () => {
      if (Date.now() - lastActive >= autolockSeconds * 1000) {
        onLock();
        return;
      }
      try {
        const wasActive = activeSinceBeat;
        activeSinceBeat = false;
        const stillUnlocked = await apiSessionHeartbeat(wasActive);
        if (!stillUnlocked) onLock();
      } catch {
        // ignore
      }
    }, 5000);

    return () => {
      window.clearInterval(id);
      events.forEach((e) => window.removeEventListener(e, onActivity));
    };
  }, [autolockSeconds, onLock]);
}
