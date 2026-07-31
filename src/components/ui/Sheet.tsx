import { useEffect, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/cn";

interface SheetProps {
  open: boolean;
  onClose: () => void;
  children: ReactNode;
  /** "modal" — центрированное окно; "bottom" — лист снизу (мобильный pattern). */
  position?: "modal" | "bottom" | "full";
  title?: string;
  hideHandle?: boolean;
}

/**
 * Универсальный slide-up bottom-sheet или центрированный modal.
 * Поддерживает Esc для закрытия и блокировку body-scroll.
 */
export function Sheet({
  open,
  onClose,
  children,
  position = "bottom",
  title,
  hideHandle,
}: SheetProps) {
  const { t } = useTranslation();
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  const containerCls = cn(
    "fixed inset-0 z-50 flex animate-fade-in",
    position === "bottom" && "items-end",
    position === "modal" && "items-center justify-center p-4",
    position === "full" && "items-stretch",
  );

  const panelCls = cn(
    "card-elevated bg-ink-900/95 backdrop-blur-xl text-white animate-fade-in-up relative",
    position === "bottom" && "w-full rounded-t-3xl rounded-b-none max-h-[85vh] overflow-y-auto",
    position === "modal" && "w-full max-w-md rounded-2xl max-h-[85vh] overflow-y-auto",
    position === "full" && "w-full h-full rounded-none flex flex-col",
  );

  const bodyCls = cn(
    position === "full" ? "flex-1 min-h-0 flex flex-col" : "px-5 pb-6",
  );

  return (
    <div className={containerCls}>
      <button
        type="button"
        aria-label={t('common.close')}
        onClick={onClose}
        className="absolute inset-0 bg-black/60 backdrop-blur-[2px]"
      />
      <div className={panelCls} role="dialog" aria-modal="true">
        {position === "bottom" && !hideHandle && (
          <div className="flex justify-center pt-3 pb-1 shrink-0">
            <div className="h-1 w-10 rounded-full bg-white/15" />
          </div>
        )}
        {title && (
          <div className="px-5 pt-2 pb-3 text-base font-medium text-white/90 shrink-0">
            {title}
          </div>
        )}
        <div className={bodyCls}>{children}</div>
      </div>
    </div>
  );
}
