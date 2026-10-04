import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { act, renderHook } from "@testing-library/react";
import type { PointerEvent as ReactPointerEvent } from "react";

import { useDragReorder } from "./useDragReorder";

/** Минимальная заглушка React-события указателя. */
function pointerDown(x: number, y: number, button = 0) {
  return { button, clientX: x, clientY: y } as unknown as ReactPointerEvent;
}

function move(x: number, y: number) {
  document.dispatchEvent(
    new MouseEvent("pointermove", { clientX: x, clientY: y, bubbles: true }),
  );
}

function up(x: number, y: number) {
  document.dispatchEvent(
    new MouseEvent("pointerup", { clientX: x, clientY: y, bubbles: true }),
  );
}

describe("useDragReorder", () => {
  const handlers = {
    onOpen: vi.fn(),
    onReorder: vi.fn(),
    onMoveCategory: vi.fn(),
  };
  let card: HTMLElement;
  let tab: HTMLElement;

  beforeEach(() => {
    handlers.onOpen.mockReset();
    handlers.onReorder.mockReset();
    handlers.onMoveCategory.mockReset();

    card = document.createElement("div");
    card.setAttribute("data-record-id", "target-1");
    document.body.appendChild(card);

    tab = document.createElement("div");
    tab.setAttribute("data-category-tab", "work");
    document.body.appendChild(tab);

    document.elementFromPoint = vi.fn(() => card);
  });

  afterEach(() => {
    document.body.innerHTML = "";
  });

  const setup = (canReorder = true) =>
    renderHook(() => useDragReorder({ ...handlers, canReorder }));

  it("клик без движения открывает запись", () => {
    const { result } = setup();
    act(() => result.current.handlePointerDown(pointerDown(10, 10), "source"));
    act(() => up(12, 11));
    expect(handlers.onOpen).toHaveBeenCalledWith("source");
    expect(handlers.onReorder).not.toHaveBeenCalled();
  });

  it("движение дальше порога начинает перетаскивание", () => {
    const { result } = setup();
    act(() => result.current.handlePointerDown(pointerDown(10, 10), "source"));
    act(() => move(14, 14)); // расстояние ~5.7 < 6 — ещё не drag
    expect(result.current.draggedId).toBeNull();
    act(() => move(30, 30));
    expect(result.current.draggedId).toBe("source");
  });

  it("бросок на другую карточку меняет порядок", () => {
    const { result } = setup();
    act(() => result.current.handlePointerDown(pointerDown(10, 10), "source"));
    act(() => move(60, 60));
    act(() => up(60, 60));
    expect(handlers.onReorder).toHaveBeenCalledWith("source", "target-1");
    expect(handlers.onOpen).not.toHaveBeenCalled();
  });

  it("при запрете сортировки бросок на карточку игнорируется", () => {
    const { result } = setup(false);
    act(() => result.current.handlePointerDown(pointerDown(10, 10), "source"));
    act(() => move(60, 60));
    expect(result.current.activeDragTargetId).toBeNull();
    act(() => up(60, 60));
    expect(handlers.onReorder).not.toHaveBeenCalled();
  });

  it("бросок на вкладку категории переносит запись", () => {
    document.elementFromPoint = vi.fn(() => tab);
    const { result } = setup();
    act(() => result.current.handlePointerDown(pointerDown(10, 10), "source"));
    act(() => move(60, 60));
    expect(result.current.dragOverTab).toBe("work");
    act(() => up(60, 60));
    expect(handlers.onMoveCategory).toHaveBeenCalledWith("source", "work");
    expect(handlers.onReorder).not.toHaveBeenCalled();
  });

  it("Escape отменяет перетаскивание и снимает слушатели", () => {
    const { result } = setup();
    act(() => result.current.handlePointerDown(pointerDown(10, 10), "source"));
    act(() => move(60, 60));
    expect(result.current.draggedId).toBe("source");

    act(() => {
      document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    });
    expect(result.current.draggedId).toBeNull();

    act(() => up(60, 60));
    expect(handlers.onReorder).not.toHaveBeenCalled();
    expect(handlers.onOpen).not.toHaveBeenCalled();
  });

  it("не реагирует на неосновную кнопку мыши", () => {
    const { result } = setup();
    act(() => result.current.handlePointerDown(pointerDown(10, 10, 2), "source"));
    act(() => up(10, 10));
    expect(handlers.onOpen).not.toHaveBeenCalled();
  });

  it("бросок на саму себя не вызывает reorder", () => {
    card.setAttribute("data-record-id", "source");
    const { result } = setup();
    act(() => result.current.handlePointerDown(pointerDown(10, 10), "source"));
    act(() => move(60, 60));
    expect(result.current.activeDragTargetId).toBeNull();
    act(() => up(60, 60));
    expect(handlers.onReorder).toHaveBeenCalledWith("source", "source");
  });
});
