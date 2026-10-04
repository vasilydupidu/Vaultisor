import { useState, type PointerEvent as ReactPointerEvent } from "react";

/**
 * R-01/R-02: pointer-based drag-and-drop, вынесенный из VaultScreen в хук.
 * Два действия: перетаскивание карточки на карточку (reorder — только в
 * неотфильтрованном виде, canReorder) и на вкладку категории (смена категории).
 * Простой клик (без движения) — открытие записи.
 *
 * Клавиатурная альтернатива reorder/смены категории живёт в самих экранах
 * (RecordCard focus + RecordEdit-категория), т.к. HTML5-DnD недоступен клавишами.
 */
export function useDragReorder(opts: {
  onOpen: (id: string) => void;
  onReorder: (sourceId: string, targetId: string) => void;
  onMoveCategory: (id: string, cat: "work" | "personal") => void;
  canReorder: boolean;
}) {
  const [draggedId, setDraggedId] = useState<string | null>(null);
  const [activeDragTargetId, setActiveDragTargetId] = useState<string | null>(null);
  const [dragOverTab, setDragOverTab] = useState<"all" | "work" | "personal" | null>(null);

  const handlePointerDown = (e: ReactPointerEvent, id: string) => {
    if (e.button !== 0) return; // только основная кнопка
    const startX = e.clientX;
    const startY = e.clientY;
    let isDragging = false;

    const onPointerMove = (moveEvent: PointerEvent) => {
      if (!isDragging) {
        const dist = Math.hypot(moveEvent.clientX - startX, moveEvent.clientY - startY);
        if (dist > 6) {
          isDragging = true;
          setDraggedId(id);
        }
      }
      if (isDragging) {
        const element = document.elementFromPoint(moveEvent.clientX, moveEvent.clientY);
        const cardEl = element?.closest("[data-record-id]");
        const targetId = cardEl?.getAttribute("data-record-id");
        setActiveDragTargetId(
          opts.canReorder && targetId && targetId !== id ? targetId : null,
        );
        const tabEl = element?.closest("[data-category-tab]");
        const cat = tabEl?.getAttribute("data-category-tab");
        setDragOverTab(cat === "work" || cat === "personal" ? cat : null);
      }
    };

    const onPointerUp = (upEvent: PointerEvent) => {
      cleanup();
      if (isDragging) {
        const element = document.elementFromPoint(upEvent.clientX, upEvent.clientY);
        const tabEl = element?.closest("[data-category-tab]");
        const cardEl = element?.closest("[data-record-id]");
        const cat = tabEl?.getAttribute("data-category-tab");
        if (cat === "work" || cat === "personal") {
          opts.onMoveCategory(id, cat);
        } else if (opts.canReorder && cardEl) {
          const targetId = cardEl.getAttribute("data-record-id");
          if (targetId) opts.onReorder(id, targetId);
        }
      } else {
        opts.onOpen(id);
      }
    };

    const onPointerCancel = () => cleanup();
    const onKeyDown = (k: KeyboardEvent) => {
      if (k.key === "Escape") cleanup();
    };

    const cleanup = () => {
      document.removeEventListener("pointermove", onPointerMove);
      document.removeEventListener("pointerup", onPointerUp);
      document.removeEventListener("pointercancel", onPointerCancel);
      document.removeEventListener("keydown", onKeyDown);
      setDraggedId(null);
      setActiveDragTargetId(null);
      setDragOverTab(null);
    };

    document.addEventListener("pointermove", onPointerMove);
    document.addEventListener("pointerup", onPointerUp);
    document.addEventListener("pointercancel", onPointerCancel);
    document.addEventListener("keydown", onKeyDown);
  };

  return { draggedId, activeDragTargetId, dragOverTab, handlePointerDown };
}
