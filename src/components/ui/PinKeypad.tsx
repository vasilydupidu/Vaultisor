import { useCallback, useEffect, useMemo, useRef } from "react";
import { useTranslation } from "react-i18next";
import { Delete } from "lucide-react";
import { cn } from "@/lib/cn";

interface Props {
  value: string;
  onChange: (next: string) => void;
  maxLen?: number;
  disabled?: boolean;
  /** Минимальная длина PIN, до достижения которой кнопка "Готово" не активна. */
  minLen?: number;
  /** Колбэк при нажатии "Готово" (Enter). Если не задан — кнопки нет. */
  onSubmit?: () => void;
  /** Заголовок над клавиатурой. */
  label?: string;
  /** Состояние ошибки — будет shake-анимация. */
  shake?: boolean;
  /** Цельные точки или цифры в превью? Если showDigits — цифры. */
  showDigits?: boolean;
}

/**
 * Мобильный PIN-keypad. Цифры 0–9 + backspace.
 * Поддерживает физическую клавиатуру.
 */
export function PinKeypad({
  value,
  onChange,
  maxLen = 12,
  disabled,
  minLen = 4,
  onSubmit,
  label,
  shake = false,
  showDigits = false,
}: Props) {
  const { t } = useTranslation();
  const valueRef = useRef(value);
  const disabledRef = useRef(disabled);
  const onChangeRef = useRef(onChange);
  const onSubmitRef = useRef(onSubmit);

  useEffect(() => {
    valueRef.current = value;
    disabledRef.current = disabled;
    onChangeRef.current = onChange;
    onSubmitRef.current = onSubmit;
  }, [value, disabled, onChange, onSubmit]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (disabledRef.current) return;
      const current = valueRef.current;
      if (e.key >= "0" && e.key <= "9") {
        if (current.length < maxLen) onChangeRef.current(current + e.key);
      } else if (e.key === "Backspace") {
        onChangeRef.current(current.slice(0, -1));
      } else if (e.key === "Enter" && onSubmitRef.current && current.length >= minLen) {
        onSubmitRef.current();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [maxLen, minLen]);

  const press = useCallback((k: string) => {
    if (disabled) return;
    if (k === "back") {
      onChange(value.slice(0, -1));
    } else if (k === "ok") {
      if (onSubmit && value.length >= minLen) onSubmit();
    } else if (value.length < maxLen) {
      onChange(value + k);
    }
  }, [disabled, maxLen, minLen, onChange, onSubmit, value]);

  // Точки/цифры превью — ВСЕГДА maxLen элементов с фиксированной шириной,
  // чтобы row не "разъезжался" при наборе длинного PIN и не сжимал
  // grid с цифрами.
  const allDots = useMemo(
    () => Array.from({ length: maxLen }).map((_, i) => i < value.length),
    [maxLen, value.length],
  );

  // Цифровая часть — 11 ячеек (3×4 минус правая нижняя).
  // Кнопка "back" рендерится отдельно, чтобы избежать mixed-type union.
  // Подтверждение делает внешняя primary-кнопка экрана; Enter с физической
  // клавиатуры обрабатывает useEffect в начале файла.
  const digits: string[] = useMemo(() => [
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "",
    "0",
  ], []);

  return (
    <div className="flex flex-col items-center gap-6 select-none">
      {label && <div className="text-xs uppercase tracking-wider text-white/55">{label}</div>}

      <div
        className={cn(
          "flex items-center justify-center gap-1.5 w-full max-w-[260px] min-h-[12px]",
          shake && "animate-shake",
        )}
      >
        {showDigits
          ? Array.from({ length: maxLen }).map((_, i) => (
              <span
                key={i}
                className={cn(
                  "h-9 w-6 rounded-md flex items-center justify-center text-base font-mono shrink-0",
                  i < value.length
                    ? "bg-white/10 text-white"
                    : "bg-white/[0.03] text-white/20",
                )}
              >
                {value[i] ?? ""}
              </span>
            ))
          : allDots.map((on, i) => (
              <span
                key={i}
                className={cn(
                  "h-2.5 w-2.5 rounded-full transition-app shrink-0",
                  on ? "bg-brand-500" : "bg-white/15",
                )}
              />
            ))}
      </div>

      <div className="grid grid-cols-3 gap-3 w-full max-w-[260px]">
        {digits.map((d, i) => {
          if (d === "") return <div key={`empty-${i}`} />;
          return (
            <button
              key={d}
              type="button"
              onClick={() => press(d)}
              disabled={disabled}
              className="h-14 rounded-2xl bg-white/[0.03] hover:bg-white/[0.07] active:bg-white/[0.10] active:scale-[0.96] transition-app text-white text-xl font-light flex items-center justify-center"
            >
              {d}
            </button>
          );
        })}
        <button
          key="back"
          type="button"
          aria-label={t('pinKeypad.erase')}
          onClick={() => press("back")}
          disabled={disabled || value.length === 0}
          className="h-14 rounded-2xl bg-white/[0.03] hover:bg-white/[0.07] active:bg-white/[0.10] active:scale-[0.96] transition-app text-white/70 flex items-center justify-center disabled:opacity-40"
        >
          <Delete className="h-5 w-5" />
        </button>
      </div>
    </div>
  );
}
