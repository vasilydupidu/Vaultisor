import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { renderHook } from "@testing-library/react";

const heartbeat = vi.fn();
vi.mock("@/lib/api", () => ({
  apiSessionHeartbeat: (active: boolean) => heartbeat(active),
}));

import { useIdleAutolock } from "./useIdleAutolock";

describe("useIdleAutolock", () => {
  beforeEach(() => {
    heartbeat.mockReset();
    heartbeat.mockResolvedValue(true);
  });
  afterEach(() => vi.useRealTimers());

  it("вызывает onLock при простое >= autolock_seconds", async () => {
    vi.useFakeTimers();
    const onLock = vi.fn();
    renderHook(() => useIdleAutolock(1, onLock)); // порог 1с, интервал 5с
    // Первый тик интервала (5с) — простой 5с >= 1с → блокировка.
    await vi.advanceTimersByTimeAsync(5000);
    expect(onLock).toHaveBeenCalled();
  });

  it("не блокирует по простою при autolock=0 (выключено)", async () => {
    vi.useFakeTimers();
    const onLock = vi.fn();
    renderHook(() => useIdleAutolock(0, onLock));
    await vi.advanceTimersByTimeAsync(20000);
    expect(onLock).not.toHaveBeenCalled();
  });

  /**
   * Heartbeat раньше запускался только вместе с локальным
   * таймером простоя. При autolock=0 и пока настройки грузились UI не
   * опрашивал бэкенд и оставался «разблокированным» после блокировки сессии.
   */
  it("опрашивает бэкенд даже когда автоблокировка выключена", async () => {
    vi.useFakeTimers();
    renderHook(() => useIdleAutolock(0, vi.fn()));
    await vi.advanceTimersByTimeAsync(5000);
    expect(heartbeat).toHaveBeenCalled();
  });

  it("опрашивает бэкенд, пока настройки ещё не загружены", async () => {
    vi.useFakeTimers();
    renderHook(() => useIdleAutolock(undefined, vi.fn()));
    await vi.advanceTimersByTimeAsync(5000);
    expect(heartbeat).toHaveBeenCalled();
  });

  it("уходит на блокировку, если бэкенд сообщил о закрытой сессии", async () => {
    vi.useFakeTimers();
    heartbeat.mockResolvedValue(false);
    const onLock = vi.fn();
    renderHook(() => useIdleAutolock(0, onLock));
    await vi.advanceTimersByTimeAsync(5000);
    expect(onLock).toHaveBeenCalledTimes(1);
  });

  /** `onLock` вызывался каждые 5с, пока родитель размонтировался. */
  it("вызывает onLock не более одного раза", async () => {
    vi.useFakeTimers();
    heartbeat.mockResolvedValue(false);
    const onLock = vi.fn();
    renderHook(() => useIdleAutolock(1, onLock));
    await vi.advanceTimersByTimeAsync(30000);
    expect(onLock).toHaveBeenCalledTimes(1);
  });

  it("сбой IPC не блокирует сессию", async () => {
    vi.useFakeTimers();
    heartbeat.mockRejectedValue(new Error("ipc down"));
    const onLock = vi.fn();
    renderHook(() => useIdleAutolock(0, onLock));
    await vi.advanceTimersByTimeAsync(15000);
    expect(onLock).not.toHaveBeenCalled();
  });

  it("снимает слушатели и таймер при размонтировании", async () => {
    vi.useFakeTimers();
    const removeSpy = vi.spyOn(window, "removeEventListener");
    const { unmount } = renderHook(() => useIdleAutolock(60, vi.fn()));
    unmount();
    const removed = removeSpy.mock.calls.map((c) => c[0]);
    expect(removed).toContain("mousemove");
    expect(removed).toContain("keydown");
    heartbeat.mockClear();
    await vi.advanceTimersByTimeAsync(20000);
    expect(heartbeat).not.toHaveBeenCalled();
    removeSpy.mockRestore();
  });
});
