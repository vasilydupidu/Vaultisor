import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react";
import { cn } from "@/lib/cn";

type Variant = "primary" | "secondary" | "ghost" | "danger" | "link";
type Size = "sm" | "md" | "lg";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  leftIcon?: ReactNode;
  rightIcon?: ReactNode;
  loading?: boolean;
  fullWidth?: boolean;
}

const variants: Record<Variant, string> = {
  primary:
    "bg-brand-500 text-white hover:bg-brand-600 active:bg-brand-700 disabled:bg-ink-700 disabled:text-ink-400 shadow-[0_4px_14px_-4px_rgba(12,164,159,0.6)]",
  secondary:
    "bg-white/[0.06] text-white border border-white/10 hover:bg-white/[0.10] hover:border-white/15 active:bg-white/[0.08]",
  ghost:
    "bg-transparent text-white/85 hover:bg-white/[0.06] active:bg-white/[0.10]",
  danger:
    "bg-danger/90 text-white hover:bg-danger active:bg-danger/80",
  link:
    "bg-transparent text-brand-400 hover:text-brand-300 underline-offset-4 hover:underline",
};

const sizes: Record<Size, string> = {
  sm: "h-9 px-3 text-sm rounded-lg",
  md: "h-11 px-4 text-base rounded-xl",
  lg: "h-13 px-5 text-base rounded-2xl",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      className,
      variant = "primary",
      size = "md",
      leftIcon,
      rightIcon,
      loading = false,
      fullWidth = false,
      children,
      disabled,
      ...props
    },
    ref,
  ) => {
    return (
      <button
        ref={ref}
        disabled={disabled || loading}
        className={cn(
          "transition-app inline-flex items-center justify-center gap-2 font-medium select-none disabled:cursor-not-allowed disabled:opacity-60 active:scale-[0.985]",
          variants[variant],
          sizes[size],
          fullWidth && "w-full",
          className,
        )}
        {...props}
      >
        {loading ? (
          <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
        ) : (
          leftIcon
        )}
        <span className="truncate">{children}</span>
        {!loading && rightIcon}
      </button>
    );
  },
);
Button.displayName = "Button";
