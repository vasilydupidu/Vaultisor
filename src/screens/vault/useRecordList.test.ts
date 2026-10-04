// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";

const listMock = vi.fn();
const reorderMock = vi.fn().mockResolvedValue(undefined);
vi.mock("@/lib/api", () => ({
  apiRecordList: (...a: unknown[]) => listMock(...a),
  apiRecordReorder: (...a: unknown[]) => reorderMock(...a),
}));

import { useRecordList } from "./useRecordList";

function rec(id: string) {
  return {
    id,
    name: id,
    project: null,
    icon: null,
    color: null,
    category: "personal",
    created_at: "",
    updated_at: "",
    fields: [],
  };
}

describe("useRecordList", () => {
  beforeEach(() => {
    listMock.mockReset();
    reorderMock.mockClear();
  });

  it("грузит первую страницу, hasMore=true при полной странице; loadMore добавляет", async () => {
    const page1 = Array.from({ length: 60 }, (_, i) => rec("a" + i));
    const page2 = [rec("b0"), rec("b1")]; // < 60 → hasMore=false
    listMock.mockResolvedValueOnce(page1).mockResolvedValueOnce(page2);

    const { result } = renderHook(() => useRecordList("records", "all", vi.fn()));

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.records.length).toBe(60);
    expect(result.current.hasMore).toBe(true);

    await act(async () => {
      await result.current.loadMore();
    });
    expect(result.current.records.length).toBe(62);
    expect(result.current.hasMore).toBe(false);
  });

  it("applyOrder оптимистично меняет порядок и вызывает reorder API", async () => {
    listMock.mockResolvedValue([rec("x"), rec("y"), rec("z")]);
    const { result } = renderHook(() => useRecordList("records", "all", vi.fn()));
    await waitFor(() => expect(result.current.records.length).toBe(3));

    act(() => result.current.applyOrder(["z", "y", "x"]));
    expect(result.current.records.map((r) => r.id)).toEqual(["z", "y", "x"]);
    expect(reorderMock).toHaveBeenCalledWith("records", ["z", "y", "x"]);
  });

  /**
   * AUDIT: главная заявленная гарантия R-04 — поздний ответ устаревшего
   * запроса не должен перезаписывать свежий результат. Раньше она не была
   * покрыта тестом вовсе.
   */
  it("поздний ответ устаревшего запроса не перезаписывает свежий", async () => {
    let resolveStale: ((v: unknown) => void) | null = null;
    const stale = new Promise((resolve) => {
      resolveStale = resolve;
    });
    listMock.mockReturnValueOnce(stale).mockResolvedValueOnce([rec("fresh")]);

    const { result, rerender } = renderHook(
      ({ category }: { category: "all" | "work" }) =>
        useRecordList("records", category, vi.fn()),
      { initialProps: { category: "all" as "all" | "work" } },
    );

    // Дожидаемся, пока дебаунс отпустит ПЕРВЫЙ запрос (он остаётся висеть).
    await waitFor(() => expect(listMock).toHaveBeenCalledTimes(1));

    // Смена категории запускает второй запрос, который завершается первым.
    rerender({ category: "work" as const });
    await waitFor(() => expect(result.current.records.map((r) => r.id)).toEqual(["fresh"]));

    // Теперь отвечает устаревший запрос — его результат обязан быть отброшен.
    await act(async () => {
      resolveStale?.([rec("stale-a"), rec("stale-b")]);
      await stale;
    });
    expect(result.current.records.map((r) => r.id)).toEqual(["fresh"]);
  });

  it("ошибка загрузки очищает список и сообщает наверх", async () => {
    const onError = vi.fn();
    listMock.mockRejectedValue("STORAGE_ERROR: Ошибка хранилища");
    const { result } = renderHook(() => useRecordList("records", "all", onError));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.records).toEqual([]);
    expect(onError).toHaveBeenCalledWith("STORAGE_ERROR: Ошибка хранилища");
  });

  it("applyOrder игнорирует неполный набор идентификаторов", async () => {
    listMock.mockResolvedValue([rec("x"), rec("y"), rec("z")]);
    const { result } = renderHook(() => useRecordList("records", "all", vi.fn()));
    await waitFor(() => expect(result.current.records.length).toBe(3));

    act(() => result.current.applyOrder(["z", "x"]));
    expect(result.current.records.map((r) => r.id)).toEqual(["x", "y", "z"]);
  });

  it("неудачный reorder приводит к перезагрузке списка", async () => {
    listMock.mockResolvedValue([rec("x"), rec("y")]);
    reorderMock.mockRejectedValueOnce(new Error("db down"));
    const { result } = renderHook(() => useRecordList("records", "all", vi.fn()));
    await waitFor(() => expect(result.current.records.length).toBe(2));

    listMock.mockClear();
    await act(async () => {
      result.current.applyOrder(["y", "x"]);
      await Promise.resolve();
    });
    await waitFor(() => expect(listMock).toHaveBeenCalled());
  });

  it("loadMore не запускается, когда больше нечего грузить", async () => {
    listMock.mockResolvedValue([rec("only")]);
    const { result } = renderHook(() => useRecordList("records", "all", vi.fn()));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.hasMore).toBe(false);

    listMock.mockClear();
    await act(async () => {
      await result.current.loadMore();
    });
    expect(listMock).not.toHaveBeenCalled();
  });
});
