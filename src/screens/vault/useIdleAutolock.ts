import { useEffect, useRef } from "react";
import { apiSessionHeartbeat } from "@/lib/api";

/** Период опроса состояния сессии на бэкенде. */
const HEARTBEAT_MS = 5000;

/**
 * Авто-блокировка по бездействию В ПРИЛОЖЕНИИ + heartbeat синхронизации.
 *
 * Активность в окне (мышь/клавиатура) продлевает сессию на бэкенде; локальный
 * таймер мгновенно уводит UI в lock; heartbeat возвращает состояние сессии —
 * если бэкенд залочил (idle, Win+L, сон), уходим тоже.
 *
 * Исправленные ошибки:
 *  - heartbeat раньше запускался только при autolockSeconds > 0. При значении
 *    «никогда» и пока настройки ещё грузились UI вообще не спрашивал бэкенд,
 *    поэтому оставался «разблокированным» после блокировки сессии на бэкенде.
 *    Теперь heartbeat идёт всегда, а локальный таймер простоя — только когда
 *    автоблокировка включена.
 *  - onLock мог вызываться повторно каждые 5 секунд, пока родитель
 *    асинхронно размонтировал экран. Добавлен одноразовый guard.
 */
export function useIdleAutolock(
  autolockSeconds: number | undefined,
  onLock: () => void,
) {
  // Идентичность колбэка не должна перезапускать интервал.
  const onLockRef = useRef(onLock);
  onLockRef.current = onLock;

  useEffect(() => {
    let activeSinceBeat = false;
    let lastActive = Date.now();
    let locked = false;
    let inFlight = false;

    const lockOnce = () => {
      if (locked) return;
      locked = true;
      onLockRef.current();
    };

    const onActivity = () => {
      activeSinceBeat = true;
      lastActive = Date.now();
    };
    const events = ["mousemove", "mousedown", "keydown", "wheel", "touchstart"];
    events.forEach((e) => window.addEventListener(e, onActivity, { passive: true }));

    const id = window.setInterval(async () => {
      if (locked) return;
      if (autolockSeconds && Date.now() - lastActive >= autolockSeconds * 1000) {
        lockOnce();
        return;
      }
      // Не накладываем запросы друг на друга, если backend отвечает медленно.
      if (inFlight) return;
      inFlight = true;
      try {
        const wasActive = activeSinceBeat;
        activeSinceBeat = false;
        const stillUnlocked = await apiSessionHeartbeat(wasActive);
        if (!stillUnlocked) lockOnce();
      } catch {
        // Сетевого канала нет; единичный сбой IPC не повод блокировать.
      } finally {
        inFlight = false;
      }
    }, HEARTBEAT_MS);

    return () => {
      window.clearInterval(id);
      events.forEach((e) => window.removeEventListener(e, onActivity));
    };
  }, [autolockSeconds]);
}
