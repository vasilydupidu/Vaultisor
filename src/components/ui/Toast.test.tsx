// @vitest-environment jsdom
import { describe, it, expect, vi } from "vitest";
import { act, render } from "@testing-library/react";
import { useEffect, useRef, useState } from "react";

vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (key: string) => key }),
  initReactI18next: { type: "3rdParty", init: () => {} },
}));

import { ToastProvider, useToast } from "./Toast";

/**
 * Регрессия: объект toast-api пересоздавался на каждом
 * рендере провайдера. Из-за этого у потребителей менялась идентичность
 * зависимости, useCallback-загрузчики пересоздавались, и RecordEdit перезагружал
 * запись, затирая несохранённый черновик — в том числе сразу после toast.error
 * о неудачном сохранении.
 */
function IdentityProbe({ onIdentityChange }: { onIdentityChange: () => void }) {
  const toast = useToast();
  const first = useRef(toast);
  const [, forceRender] = useState(0);

  useEffect(() => {
    if (first.current !== toast) onIdentityChange();
  }, [toast, onIdentityChange]);

  return (
    <button
      onClick={() => {
        toast.error("boom");
        forceRender((n) => n + 1);
      }}
    >
      fire
    </button>
  );
}

describe("ToastProvider", () => {
  it("сохраняет идентичность api при показе тостов", () => {
    const onIdentityChange = vi.fn();
    const { getByText } = render(
      <ToastProvider>
        <IdentityProbe onIdentityChange={onIdentityChange} />
      </ToastProvider>,
    );

    act(() => {
      getByText("fire").click();
    });
    act(() => {
      getByText("fire").click();
    });

    expect(onIdentityChange).not.toHaveBeenCalled();
  });

  it("показывает сообщение и скрывает его по истечении duration", () => {
    vi.useFakeTimers();
    try {
      function Trigger() {
        const toast = useToast();
        useEffect(() => {
          toast.success("saved", 1000);
        }, [toast]);
        return null;
      }
      const { queryByText } = render(
        <ToastProvider>
          <Trigger />
        </ToastProvider>,
      );
      expect(queryByText("saved")).not.toBeNull();
      act(() => {
        vi.advanceTimersByTime(1100);
      });
      expect(queryByText("saved")).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it("таймер тоста не перезапускается при появлении следующего тоста", () => {
    vi.useFakeTimers();
    try {
      function Trigger() {
        const toast = useToast();
        const fired = useRef(false);
        useEffect(() => {
          if (fired.current) return;
          fired.current = true;
          toast.info("first", 1000);
          setTimeout(() => toast.info("second", 1000), 600);
        }, [toast]);
        return null;
      }
      const { queryByText } = render(
        <ToastProvider>
          <Trigger />
        </ToastProvider>,
      );
      act(() => {
        vi.advanceTimersByTime(700);
      });
      expect(queryByText("first")).not.toBeNull();
      expect(queryByText("second")).not.toBeNull();
      // Первый тост обязан исчезнуть ровно через свою длительность, а не
      // получить новый отсчёт из-за рендера, вызванного вторым тостом.
      act(() => {
        vi.advanceTimersByTime(400);
      });
      expect(queryByText("first")).toBeNull();
      expect(queryByText("second")).not.toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });
});
