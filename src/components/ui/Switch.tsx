import { cn } from "@/lib/cn";

// R-06: единый toggle-переключатель. Раньше дублировался в StepHello,
// StepRecovery и settings/controls (ToggleRow).
export function Switch({
  checked,
  onChange,
  disabled = false,
  "aria-label": ariaLabel,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  "aria-label"?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={ariaLabel}
      disabled={disabled}
      onClick={() => !disabled && onChange(!checked)}
      className={cn(
        "relative h-5 w-9 rounded-full transition-app shrink-0",
        checked ? "bg-brand-500" : "bg-white/15",
        disabled && "opacity-50 cursor-not-allowed",
      )}
    >
      <span
        className={cn(
          "absolute top-0.5 h-4 w-4 rounded-full bg-white transition-app",
          checked ? "left-4.5" : "left-0.5",
        )}
      />
    </button>
  );
}
