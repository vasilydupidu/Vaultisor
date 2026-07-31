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
});
