// @vitest-environment jsdom
import { describe, it, expect, vi, afterEach } from "vitest";
import { renderHook } from "@testing-library/react";

vi.mock("@/lib/api", () => ({
  apiSessionHeartbeat: vi.fn().mockResolvedValue(true),
}));

import { useIdleAutolock } from "./useIdleAutolock";

describe("useIdleAutolock", () => {
  afterEach(() => vi.useRealTimers());

  it("вызывает onLock при простое >= autolock_seconds", async () => {
    vi.useFakeTimers();
    const onLock = vi.fn();
    renderHook(() => useIdleAutolock(1, onLock)); // порог 1с, интервал 5с
    // Первый тик интервала (5с) — простой 5с >= 1с → блокировка.
    await vi.advanceTimersByTimeAsync(5000);
    expect(onLock).toHaveBeenCalled();
  });

  it("не запускает таймер при autolock=0 (выключено)", () => {
    vi.useFakeTimers();
    const onLock = vi.fn();
    renderHook(() => useIdleAutolock(0, onLock));
    vi.advanceTimersByTime(20000);
    expect(onLock).not.toHaveBeenCalled();
  });
});
