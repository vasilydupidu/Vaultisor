import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Check, CircleAlert, Info, X } from "lucide-react";
import { cn } from "@/lib/cn";

interface ToastItem {
  id: string;
  kind: "success" | "error" | "info";
  message: string;
  duration: number;
}

interface ToastApi {
  show: (kind: ToastItem["kind"], message: string, duration?: number) => void;
  success: (m: string, d?: number) => void;
  error: (m: string, d?: number) => void;
  info: (m: string, d?: number) => void;
}

const Ctx = createContext<ToastApi | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);

  const remove = useCallback((id: string) => {
    setItems((cur) => cur.filter((t) => t.id !== id));
  }, []);

  const show = useCallback(
    (kind: ToastItem["kind"], message: string, duration?: number) => {
      const id = Math.random().toString(36).slice(2);
      // Ошибки висят дольше — пользователь должен успеть прочитать.
      const dur = duration ?? (kind === "error" ? 6000 : 3200);
      setItems((cur) => [...cur, { id, kind, message, duration: dur }]);
    },
    [],
  );

  const api: ToastApi = {
    show,
    success: (m, d) => show("success", m, d),
    error: (m, d) => show("error", m, d),
    info: (m, d) => show("info", m, d),
  };

  return (
    <Ctx.Provider value={api}>
      {children}
      {/* Toast-стак рендерится сверху по центру, поверх любых sheets/modal'ов
          через высокий z-index. Это гарантирует видимость над окнами Hello-prompt
          и системными подсказками, которые перекрывают нижнюю часть экрана. */}
      <div className="fixed top-[50px] left-1/2 z-[1000] -translate-x-1/2 flex flex-col items-center gap-1 pointer-events-none max-w-[280px] w-full px-2">
        {items.map((t) => (
          <ToastView key={t.id} item={t} onClose={() => remove(t.id)} />
        ))}
      </div>
    </Ctx.Provider>
  );
}

function ToastView({ item, onClose }: { item: ToastItem; onClose: () => void }) {
  const { t } = useTranslation();
  useEffect(() => {
    const id = setTimeout(onClose, item.duration);
    return () => clearTimeout(id);
  }, [item.duration, onClose]);

  const Icon =
    item.kind === "success" ? Check : item.kind === "error" ? CircleAlert : Info;
  const color =
    item.kind === "success"
      ? "text-success"
      : item.kind === "error"
      ? "text-danger"
      : "text-brand-400";

  return (
    <div
      className={cn(
        "card-elevated pointer-events-auto px-2.5 py-1.5 max-w-[280px] w-full flex items-center gap-2 animate-fade-in-up border border-white/10 bg-black/90 backdrop-blur-md rounded-lg shadow-xl",
      )}
    >
      <Icon className={cn("h-3.5 w-3.5 shrink-0", color)} />
      <div className="text-2xs font-medium text-white/90 flex-1 truncate">{item.message}</div>
      <button
        onClick={onClose}
        aria-label={t('common.close')}
        className="text-white/40 hover:text-white/80 transition-app shrink-0 ml-0.5"
      >
        <X className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}

export function useToast(): ToastApi {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useToast: <ToastProvider> not mounted");
  return ctx;
}
