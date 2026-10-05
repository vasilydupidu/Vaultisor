import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

const getConfig = vi.fn();
const backupNow = vi.fn();
vi.mock("@/lib/api", () => ({
  apiBackupGetConfig: () => getConfig(),
  apiBackupNow: () => backupNow(),
}));

import { useAutoBackup } from "./useAutoBackup";

const DAY = 24 * 60 * 60 * 1000;

function config(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    dir: "C:/backups",
    frequency: "daily",
    last_backup: null,
    ...overrides,
  };
}

describe("useAutoBackup", () => {
  beforeEach(() => {
    getConfig.mockReset().mockResolvedValue(config());
    backupNow.mockReset().mockResolvedValue({ path: "C:/backups/x.vault" });
  });
  afterEach(() => vi.useRealTimers());

  it("делает догоняющий бэкап, если срок вышел", async () => {
    renderHook(() => useAutoBackup());
    await waitFor(() => expect(backupNow).toHaveBeenCalledTimes(1));
  });

  it("ничего не делает, когда расписание выключено", async () => {
    getConfig.mockResolvedValue(config({ frequency: "off" }));
    renderHook(() => useAutoBackup());
    await waitFor(() => expect(getConfig).toHaveBeenCalled());
    expect(backupNow).not.toHaveBeenCalled();
  });

  it("ничего не делает без выбранного каталога", async () => {
    getConfig.mockResolvedValue(config({ dir: null }));
    renderHook(() => useAutoBackup());
    await waitFor(() => expect(getConfig).toHaveBeenCalled());
    expect(backupNow).not.toHaveBeenCalled();
  });

  it("не дублирует свежий ежедневный бэкап", async () => {
    getConfig.mockResolvedValue(
      config({ last_backup: new Date(Date.now() - 60_000).toISOString() }),
    );
    renderHook(() => useAutoBackup());
    await waitFor(() => expect(getConfig).toHaveBeenCalled());
    expect(backupNow).not.toHaveBeenCalled();
  });

  it("еженедельное расписание не срабатывает на третий день", async () => {
    getConfig.mockResolvedValue(
      config({
        frequency: "weekly",
        last_backup: new Date(Date.now() - 3 * DAY).toISOString(),
      }),
    );
    renderHook(() => useAutoBackup());
    await waitFor(() => expect(getConfig).toHaveBeenCalled());
    expect(backupNow).not.toHaveBeenCalled();
  });

  it("еженедельное расписание срабатывает на восьмой день", async () => {
    getConfig.mockResolvedValue(
      config({
        frequency: "weekly",
        last_backup: new Date(Date.now() - 8 * DAY).toISOString(),
      }),
    );
    renderHook(() => useAutoBackup());
    await waitFor(() => expect(backupNow).toHaveBeenCalledTimes(1));
  });

  /**
   * В StrictMode эффект монтируется дважды, а проверка
   * асинхронная — раньше можно было получить два параллельных backup_now.
   */
  it("не запускает бэкап параллельно самому себе", async () => {
    const gate: { release: (() => void) | null } = { release: null };
    getConfig.mockImplementation(
      () =>
        new Promise((resolve) => {
          gate.release = () => resolve(config());
        }),
    );
    const { rerender } = renderHook(() => useAutoBackup());
    rerender();
    await waitFor(() => expect(gate.release).not.toBeNull());
    gate.release?.();
    await waitFor(() => expect(backupNow).toHaveBeenCalledTimes(1));
    expect(getConfig).toHaveBeenCalledTimes(1);
  });

  it("ошибка бэкапа не всплывает наружу", async () => {
    getConfig.mockRejectedValue(new Error("locked"));
    expect(() => renderHook(() => useAutoBackup())).not.toThrow();
    await waitFor(() => expect(getConfig).toHaveBeenCalled());
  });

  it("после размонтирования проверки прекращаются", async () => {
    vi.useFakeTimers();
    const { unmount } = renderHook(() => useAutoBackup());
    unmount();
    getConfig.mockClear();
    await vi.advanceTimersByTimeAsync(3 * 60 * 60 * 1000);
    expect(getConfig).not.toHaveBeenCalled();
  });
});
