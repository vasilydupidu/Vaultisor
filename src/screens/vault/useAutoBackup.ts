import { useEffect, useRef } from "react";
import { apiBackupGetConfig, apiBackupNow } from "@/lib/api";
import { RetryableRequest } from "@/lib/requestId";

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

/**
 * R-01: догоняющий авто-бэкап по расписанию, пока приложение открыто (AUDIT M11).
 * Проверка при монтировании и ежечасно. Полностью фоновый бэкап при закрытом
 * приложении невозможен без системной службы — осознанное ограничение portable.
 *
 * AUDIT 3.1.1: добавлен guard от параллельных и повторных запусков. В StrictMode
 * эффект монтируется дважды, а сама проверка асинхронная, поэтому раньше можно
 * было получить два одновременных `backup_now` — две копии с одинаковым
 * содержимым и лишний расход ретеншна.
 */
export function useAutoBackup() {
  const runningRef = useRef(false);
  // Неудавшаяся попытка повторяется со следующей проверкой тем же запросом.
  const requestRef = useRef(new RetryableRequest());

  useEffect(() => {
    let cancelled = false;

    const check = async () => {
      if (runningRef.current || cancelled) return;
      runningRef.current = true;
      try {
        const cfg = await apiBackupGetConfig();
        if (cancelled || !cfg.dir || cfg.frequency === "off") return;
        const intervalMs = cfg.frequency === "daily" ? DAY_MS : 7 * DAY_MS;
        const last = cfg.last_backup ? new Date(cfg.last_backup).getTime() : 0;
        if (Date.now() - last >= intervalMs) {
          await apiBackupNow(requestRef.current.idFor("auto-backup"));
          requestRef.current.done();
        }
      } catch {
        // тихо игнорируем — бэкап не должен мешать работе
      } finally {
        runningRef.current = false;
      }
    };

    check();
    const timer = setInterval(check, HOUR_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);
}
