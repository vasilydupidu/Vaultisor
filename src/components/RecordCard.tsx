import type { RecordModel } from "@/lib/api";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/cn";
import { ChevronRight, Hash } from "lucide-react";

interface Props {
  record: RecordModel;
  healthStatus?: { hasWeak: boolean; hasReused: boolean };
  onPointerDown?: (e: React.PointerEvent) => void;
  /** R-02: открытие с клавиатуры (Enter/Space). */
  onOpen?: () => void;
  /** Фаза 2 (a11y): клавиатурный reorder — Alt+↑/↓. undefined = недоступно. */
  onMoveUp?: () => void;
  onMoveDown?: () => void;
  isDragging?: boolean;
  isDragTarget?: boolean;
  selectable?: boolean;
  selected?: boolean;
  onSelectToggle?: () => void;
}

const projectColors: Record<string, string> = {
  default: "bg-brand-500/15 text-brand-300 border-brand-500/20",
};

/**
 * F8: пропускаем только строгий 6-значный hex (#RRGGBB). Цвет попадает в
 * inline-style с дописыванием alpha (`${c}33`), поэтому произвольная строка
 * (напр. из импортированного хранилища) могла бы протащить `url(...)`/иную
 * CSS-конструкцию. Всё, что не #RRGGBB, игнорируем.
 */
function safeHexColor(c: string | null): string | undefined {
  return c && /^#[0-9a-fA-F]{6}$/.test(c) ? c : undefined;
}

/**
 * Карточка записи в общем списке.
 * Компактная: имя, проект, кол-во полей, иконка/инициалы.
 */
export function RecordCard({
  record,
  healthStatus,
  onPointerDown,
  onOpen,
  onMoveUp,
  onMoveDown,
  isDragging,
  isDragTarget,
  selectable,
  selected,
  onSelectToggle,
}: Props) {
  const { t } = useTranslation();
  const canReorder = !!(onMoveUp || onMoveDown);
  const initials = record.name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0]!.toUpperCase())
    .join("");

  return (
    <div
      onPointerDown={selectable ? undefined : onPointerDown}
      onClick={selectable ? onSelectToggle : undefined}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          if (selectable) {
            onSelectToggle?.();
          } else {
            onOpen?.();
          }
        } else if (e.altKey && e.key === "ArrowUp" && onMoveUp) {
          e.preventDefault();
          onMoveUp();
        } else if (e.altKey && e.key === "ArrowDown" && onMoveDown) {
          e.preventDefault();
          onMoveDown();
        }
      }}
      role="button"
      tabIndex={0}
      aria-label={
        canReorder
          ? t('recordCard.openReorder', { name: record.name })
          : t('recordCard.open', { name: record.name })
      }
      aria-keyshortcuts={canReorder ? "Alt+ArrowUp Alt+ArrowDown" : undefined}
      data-record-id={record.id}
      className={cn(
        "card-flat hover:border-white/10 hover:bg-white/[0.04] active:bg-white/[0.06] active:scale-[0.995] transition-all duration-300 cursor-pointer select-none touch-none",
        "w-full flex items-center gap-3 p-3 text-left relative overflow-hidden",
        isDragging && "opacity-40 border-dashed border-brand-500/40 cursor-grabbing bg-white/[0.01]",
        isDragTarget && "border-brand-500/70 shadow-[0_0_12px_rgba(12,164,159,0.25)] scale-[1.01] bg-white/[0.06]",
        selected && "border-brand-500/60 bg-brand-500/[0.08]"
      )}
    >
      {selectable && (
        <input
          type="checkbox"
          checked={selected}
          onChange={() => onSelectToggle?.()}
          onClick={(e) => e.stopPropagation()}
          className="h-4 w-4 rounded border-white/20 bg-black/40 text-brand-500 focus:ring-brand-500 shrink-0 cursor-pointer"
        />
      )}
      <div
        className={cn(
          "h-11 w-11 shrink-0 rounded-xl flex items-center justify-center text-base font-medium pointer-events-none",
          "bg-gradient-to-br from-brand-500/20 to-brand-700/20 border border-white/5 text-white",
        )}
        style={((c) =>
          c ? { background: `${c}33`, borderColor: `${c}55` } : undefined)(
          safeHexColor(record.color),
        )}
      >
        {record.icon ?? (initials || <Hash className="h-4 w-4 opacity-60" />)}
      </div>

      <div className="flex-1 min-w-0 pointer-events-none">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-sm font-medium text-white truncate">{record.name}</span>
        </div>
        <div className="flex items-center gap-1.5 flex-wrap mt-0.5">
          {record.project ? (
            <span
              className={cn(
                "text-2xs px-1.5 py-0.5 rounded-md border",
                projectColors.default,
              )}
            >
              {record.project}
            </span>
          ) : (
            <span className="text-2xs text-white/30">{t('recordCard.noProject')}</span>
          )}

          {(healthStatus?.hasReused || record.has_reused) && (
            <span className="text-2xs px-1.5 py-0.5 rounded-md bg-amber-500/15 text-amber-300 border border-amber-500/30">
              ⚠️ {t('healthCheck.duplicate')}
            </span>
          )}
          {(healthStatus?.hasWeak || record.has_weak) && !(healthStatus?.hasReused || record.has_reused) && (
            <span className="text-2xs px-1.5 py-0.5 rounded-md bg-red-500/15 text-red-300 border border-red-500/30">
              ⚠️ {t('healthCheck.weak')}
            </span>
          )}
        </div>
      </div>

      <ChevronRight className="h-4 w-4 text-white/30 shrink-0 pointer-events-none" />
    </div>
  );
}
