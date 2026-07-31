import { forwardRef, useState, type InputHTMLAttributes, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Eye, EyeOff } from "lucide-react";
import { cn } from "@/lib/cn";

interface Props extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  hint?: string;
  error?: string;
  leftIcon?: ReactNode;
  rightSlot?: ReactNode;
}

/**
 * Универсальный Input. Для `type="password"` автоматически добавляется
 * кнопка-глазик (показать/скрыть значение). Если в `rightSlot` уже
 * передан кастомный элемент — глазик не показывается (не дублируется).
 */
export const Input = forwardRef<HTMLInputElement, Props>(
  ({ label, hint, error, leftIcon, rightSlot, className, id, type, ...props }, ref) => {
    const { t } = useTranslation();
    const inputId = id ?? `inp-${Math.random().toString(36).slice(2, 8)}`;
    const isPassword = type === "password";
    const [revealed, setRevealed] = useState(false);
    const effectiveType = isPassword && revealed ? "text" : type;

    // Если rightSlot не задан и поле — пароль, рендерим глазик.
    const finalRightSlot =
      rightSlot ??
      (isPassword ? (
        <button
          type="button"
          tabIndex={-1}
          onClick={() => setRevealed((v) => !v)}
          aria-label={revealed ? t('input.hideValue') : t('input.showValue')}
          className="px-2 text-white/40 hover:text-white/80 transition-app"
        >
          {revealed ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
        </button>
      ) : undefined);

    return (
      <div className="space-y-1.5 w-full">
        {label && (
          <label
            htmlFor={inputId}
            className="block text-xs uppercase tracking-wider text-white/55 font-medium"
          >
            {label}
          </label>
        )}
        <div
          className={cn(
            "transition-app group flex items-center rounded-xl bg-white/[0.04] border",
            error
              ? "border-danger/60 focus-within:border-danger"
              : "border-white/10 focus-within:border-brand-500/70 focus-within:bg-white/[0.06]",
            "focus-within:shadow-[0_0_0_4px_rgba(12,164,159,0.12)]",
          )}
        >
          {leftIcon && (
            <span className="pl-3 text-white/40 [&_svg]:h-4 [&_svg]:w-4">{leftIcon}</span>
          )}
          <input
            ref={ref}
            id={inputId}
            type={effectiveType}
            className={cn(
              "flex-1 bg-transparent px-3 py-2.5 text-sm placeholder:text-white/30 focus:outline-none",
              className,
            )}
            {...props}
          />
          {finalRightSlot && <span className="pr-2">{finalRightSlot}</span>}
        </div>
        {hint && !error && <p className="text-xs text-white/45">{hint}</p>}
        {error && <p className="text-xs text-danger animate-fade-in">{error}</p>}
      </div>
    );
  },
);
Input.displayName = "Input";
