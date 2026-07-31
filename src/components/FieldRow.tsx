import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Copy, Eye, EyeOff } from "lucide-react";
import type { FieldMeta, FieldType } from "@/lib/api";
import { IconButton } from "@/components/ui/IconButton";
import { cn } from "@/lib/cn";
import { fieldTypeLabels } from "@/lib/fieldTypes";

interface Props {
  field: FieldMeta;
  /** Расшифрованное значение, если оно есть в локальном state. */
  revealedValue?: string;
  onReveal: () => Promise<void> | void;
  onHide: () => void;
  onCopy: () => void;
  loading?: boolean;
}

const fieldColors: Record<FieldType, string> = {
  secret: "bg-danger/15 text-danger border-danger/20",
  api: "bg-brand-500/15 text-brand-300 border-brand-500/20",
  key: "bg-accent-400/15 text-accent-300 border-accent-400/20",
  id: "bg-white/[0.05] text-white/70 border-white/10",
  comment: "bg-white/[0.03] text-white/50 border-white/5",
  custom: "bg-white/[0.05] text-white/70 border-white/10",
};

export function FieldRow({
  field,
  revealedValue,
  onReveal,
  onHide,
  onCopy,
  loading,
}: Props) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const isComment = field.field_type === "comment";

  const display = field.is_secret && !revealedValue ? field.value_preview : revealedValue ?? "";

  const handleToggle = async () => {
    if (revealedValue) {
      onHide();
      return;
    }
    setBusy(true);
    try {
      await onReveal();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card-flat p-3.5 space-y-2.5">
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm font-medium text-white truncate">{field.label}</span>
        <span
          className={cn(
            "text-2xs px-1.5 py-0.5 rounded-md border whitespace-nowrap",
            fieldColors[field.field_type],
          )}
        >
          {fieldTypeLabels[field.field_type]}
        </span>
      </div>

      <div className="flex items-center gap-1">
        <div
          className={cn(
            "flex-1 px-3 py-2 rounded-lg bg-black/30 text-sm font-mono break-all",
            field.is_secret && !revealedValue && "tracking-widest text-white/60",
          )}
          data-allow-select
        >
          {isComment && !revealedValue ? (
            <span className="text-white/40 italic">{field.value_preview}</span>
          ) : (
            display
          )}
        </div>

        {field.is_secret && (
          <IconButton
            icon={revealedValue ? <EyeOff /> : <Eye />}
            aria-label={revealedValue ? t('common.hide') : t('common.show')}
            size="md"
            variant="subtle"
            onClick={handleToggle}
            disabled={busy || loading}
          />
        )}
        <IconButton
          icon={<Copy />}
          aria-label={t('common.copy')}
          size="md"
          variant="subtle"
          onClick={onCopy}
          disabled={loading}
        />
      </div>
    </div>
  );
}
