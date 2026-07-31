import { useEffect } from "react";
import { apiBackupGetConfig, apiBackupNow } from "@/lib/api";

/**
 * R-01: догоняющий авто-бэкап по расписанию, пока приложение открыто (AUDIT M11).
 * Проверка при монтировании и ежечасно. Полностью фоновый бэкап при закрытом
 * приложении невозможен без системной службы — осознанное ограничение portable.
 */
export function useAutoBackup() {
  useEffect(() => {
    const check = async () => {
      try {
        const cfg = await apiBackupGetConfig();
        if (!cfg.dir || cfg.frequency === "off") return;
        const intervalMs = cfg.frequency === "daily" ? 86_400_000 : 7 * 86_400_000;
        const last = cfg.last_backup ? new Date(cfg.last_backup).getTime() : 0;
        if (Date.now() - last >= intervalMs) {
          await apiBackupNow(cfg.dir);
        }
      } catch {
        // тихо игнорируем — бэкап не должен мешать работе
      }
    };
    check();
    const t = setInterval(check, 60 * 60 * 1000);
    return () => clearInterval(t);
  }, []);
}
