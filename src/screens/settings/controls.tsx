import React, { useState, useEffect } from "react";
import { cn } from "@/lib/cn";
import { Switch } from "@/components/ui/Switch";

export function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-2">
      <div className="section-title">{title}</div>
      <div className="card-flat p-3.5 space-y-3">{children}</div>
    </div>
  );
}

export function OptionList({
  value,
  options,
  onChange,
}: {
  value: number;
  options: { v: number; l: string }[];
  onChange: (v: number) => void;
}) {
  return (
    <div className="grid grid-cols-3 gap-1.5">
      {options.map((o) => (
        <button
          key={o.v}
          type="button"
          onClick={() => onChange(o.v)}
          className={cn(
            "px-2 py-1.5 rounded-lg text-xs transition-app text-center",
            value === o.v
              ? "bg-brand-500/15 text-brand-300 border border-brand-500/30"
              : "bg-white/[0.03] text-white/70 border border-white/[0.08] hover:bg-white/[0.06]",
          )}
        >
          {o.l}
        </button>
      ))}
    </div>
  );
}

/**
 * Кастомный ввод произвольного значения в минутах или секундах.
 * Активен (подсвечен), если текущее значение НЕ совпадает ни с одним пресетом.
 *  - unit="min": числа — это минуты, на бэк уходит value*60 секунд.
 *  - unit="sec": числа — это секунды, на бэк уходит как есть.
 */
export function CustomMinutesInput({
  label,
  valueSeconds,
  presets,
  onChange,
  unit,
  maxMinutes,
}: {
  label: string;
  valueSeconds: number;
  presets: number[];
  onChange: (v: number) => void;
  unit: "min" | "sec";
  maxMinutes: number;
}) {
  const isPreset = presets.includes(valueSeconds);
  const displayed =
    unit === "min" ? Math.round(valueSeconds / 60) : valueSeconds;

  const [text, setText] = useState<string>(isPreset ? "" : String(displayed));

  // Если значение из пресетов — поле пустое (пресет подсвечен сверху).
  // Если пользователь вводит — значение применяется при blur'е или нажатии Enter.
  useEffect(() => {
    if (isPreset) setText("");
    else setText(String(displayed));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [valueSeconds]);

  const apply = () => {
    const n = parseInt(text, 10);
    if (Number.isNaN(n) || n < 1) {
      setText("");
      return;
    }
    const seconds = unit === "min" ? n * 60 : n;
    const limit = unit === "min" ? maxMinutes * 60 : maxMinutes;
    onChange(Math.min(seconds, limit));
  };

  return (
    <div className="flex items-center gap-2 mt-1">
      <span className="text-2xs text-white/50 shrink-0">{label}</span>
      <input
        type="number"
        inputMode="numeric"
        min={1}
        max={maxMinutes}
        value={text}
        placeholder={isPreset ? "—" : ""}
        onChange={(e) => setText(e.target.value.replace(/\D/g, ""))}
        onBlur={apply}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            apply();
            (e.target as HTMLInputElement).blur();
          }
        }}
        className={cn(
          "flex-1 min-w-0 bg-white/[0.04] border rounded-lg px-2.5 py-1.5 text-xs text-white",
          "focus:outline-none focus:border-brand-500/60",
          !isPreset && text
            ? "border-brand-500/40"
            : "border-white/[0.08]",
        )}
      />
    </div>
  );
}

export function ToggleRow({
  title,
  description,
  checked,
  onChange,
  disabled = false,
}: {
  title: string;
  description: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <div className={cn("flex items-start gap-3", disabled && "opacity-50")}>
      <div className="flex-1">
        <div className="text-xs font-medium">{title}</div>
        <p className="text-2xs text-white/55 mt-0.5 leading-snug">{description}</p>
      </div>
      <div className="mt-0.5">
        <Switch checked={checked} onChange={onChange} disabled={disabled} aria-label={title} />
      </div>
    </div>
  );
}
