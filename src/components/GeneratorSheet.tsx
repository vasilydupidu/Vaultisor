import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { RefreshCw, Wand2 } from "lucide-react";
import {
  generateSecret,
  CHARSET_LABELS,
  CHARSET_ORDER,
  type Charset,
} from "@/lib/generateSecret";
import { Sheet } from "@/components/ui/Sheet";
import { Button } from "@/components/ui/Button";
import { cn } from "@/lib/cn";

/**
 * Фаза 3 (#1): генератор значения поля. Локальный CSPRNG, без сети.
 * Возвращает значение через onInsert. Не хранит и не логирует его.
 */
export function GeneratorSheet({
  open,
  onClose,
  onInsert,
}: {
  open: boolean;
  onClose: () => void;
  onInsert: (value: string) => void;
}) {
  const { t } = useTranslation();
  const [length, setLength] = useState(32);
  const [charset, setCharset] = useState<Charset>("alnumSymbols");
  const [value, setValue] = useState("");

  useEffect(() => {
    if (open) setValue(generateSecret(length, charset));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, length, charset]);

  return (
    <Sheet open={open} onClose={onClose} title={t('generator.title')}>
      <div className="space-y-4">
        <div
          className="card-flat p-3 font-mono text-sm break-all min-h-[48px] flex items-center"
          data-allow-select
        >
          {value || "—"}
        </div>

        <div className="space-y-1.5">
          <label className="text-2xs uppercase tracking-wider text-white/50 flex items-center justify-between">
            <span>{t('generator.length')}</span>
            <span className="text-brand-300 font-mono">{length}</span>
          </label>
          <input
            type="range"
            min={8}
            max={128}
            value={length}
            onChange={(e) => setLength(Number(e.target.value))}
            className="w-full accent-brand-500"
            aria-label="Длина значения"
          />
        </div>

        <div className="grid grid-cols-2 gap-1.5">
          {CHARSET_ORDER.map((c) => (
            <button
              key={c}
              type="button"
              onClick={() => setCharset(c)}
              className={cn(
                "px-2 py-1.5 rounded-lg text-2xs border text-center transition-app",
                charset === c
                  ? "bg-brand-500/15 text-brand-300 border-brand-500/30"
                  : "bg-white/[0.03] text-white/70 border-white/[0.08] hover:bg-white/[0.06]",
              )}
            >
              {CHARSET_LABELS[c]}
            </button>
          ))}
        </div>

        <div className="flex gap-2">
          <Button
            variant="secondary"
            fullWidth
            leftIcon={<RefreshCw className="h-4 w-4" />}
            onClick={() => setValue(generateSecret(length, charset))}
          >
            {t('generator.more')}
          </Button>
          <Button
            fullWidth
            leftIcon={<Wand2 className="h-4 w-4" />}
            onClick={() => {
              onInsert(value);
              onClose();
            }}
          >
            {t('generator.insert')}
          </Button>
        </div>
      </div>
    </Sheet>
  );
}
