import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react";
import { cn } from "@/lib/cn";

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  size?: "sm" | "md" | "lg";
  variant?: "default" | "subtle" | "filled" | "danger";
  icon: ReactNode;
  /** Aria-label обязателен для иконочных кнопок. */
  "aria-label": string;
}

const sizeMap = {
  sm: "h-8 w-8 [&_svg]:h-4 [&_svg]:w-4",
  md: "h-10 w-10 [&_svg]:h-5 [&_svg]:w-5",
  lg: "h-12 w-12 [&_svg]:h-6 [&_svg]:w-6",
};

const variantMap = {
  default: "text-white/80 hover:text-white hover:bg-white/[0.06]",
  subtle: "text-white/55 hover:text-white hover:bg-white/[0.04]",
  filled: "bg-white/[0.06] text-white hover:bg-white/[0.10]",
  danger: "text-danger/85 hover:text-white hover:bg-danger/30",
};

export const IconButton = forwardRef<HTMLButtonElement, Props>(
  ({ icon, size = "md", variant = "default", className, ...rest }, ref) => (
    <button
      ref={ref}
      type="button"
      className={cn(
        "transition-app inline-flex items-center justify-center rounded-xl active:scale-[0.94] disabled:opacity-50 disabled:pointer-events-none",
        sizeMap[size],
        variantMap[variant],
        className,
      )}
      {...rest}
    >
      {icon}
    </button>
  ),
);
IconButton.displayName = "IconButton";
