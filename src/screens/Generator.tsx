import { useCallback, useEffect, useMemo, useState } from "react";
import { ArrowLeft, Copy, RefreshCw, Trash2 } from "lucide-react";
import { useTranslation } from "react-i18next";

import {
  apiGeneratorCopy,
  apiGeneratorCreate,
  apiGeneratorDelete,
  apiGeneratorLimits,
  apiGeneratorList,
  type GeneratedKind,
  type GeneratedSecretMeta,
  type GeneratorLimits,
} from "@/lib/api";
import { generateSecret, type Charset } from "@/lib/generateSecret";
import { entropyBits } from "@/lib/entropy";
import { Button } from "@/components/ui/Button";
import { IconButton } from "@/components/ui/IconButton";
import { Input } from "@/components/ui/Input";
import { useToast } from "@/components/ui/Toast";
import { sanitizeError } from "@/lib/sanitizeError";
import { cn } from "@/lib/cn";

interface Props {
  onClose: () => void;
}

/** Набор символов, которым генерируется каждый тип. */
const CHARSET_FOR_KIND: Record<GeneratedKind, Charset> = {
  password: "alnumSymbols",
  alnum: "alnum",
  hex: "hex",
  base64url: "base64url",
};

/** В ряду кнопок показываем три типа; «только буквы и цифры» — галочка над
 *  паролем, потому что это тот же пароль другим набором, а не другая сущность. */
const KIND_ORDER: GeneratedKind[] = ["password", "hex", "base64url"];

/** Значения длины по умолчанию: пароль — с запасом над минимумом, ключи — 32
 *  символа, что для hex даёт 128 бит, для base64url — 192. */
const DEFAULT_LEN: Record<GeneratedKind, number> = {
  password: 20,
  // Меньший алфавит — чуть длиннее по умолчанию, чтобы биты не просели.
  alnum: 22,
  hex: 32,
  base64url: 43,
};

export function GeneratorScreen({ onClose }: Props) {
  const { t } = useTranslation();
  const toast = useToast();

  const [limits, setLimits] = useState<GeneratorLimits | null>(null);
  const [items, setItems] = useState<GeneratedSecretMeta[]>([]);
  const [kind, setKind] = useState<GeneratedKind>("password");
  const [alnumOnly, setAlnumOnly] = useState(false);
  const [length, setLength] = useState<number>(DEFAULT_LEN.password);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);

  // Тип, который реально уйдёт в backend. Галочка действует только на пароль:
  // у hex и base64url свои алфавиты, и «буквы и цифры» там ничего не значат.
  const effectiveKind: GeneratedKind = kind === "password" && alnumOnly ? "alnum" : kind;

  const minLen = useMemo(() => {
    if (!limits) return kind === "password" ? 15 : 16;
    return kind === "password" ? limits.password_min_len : 16;
  }, [kind, limits]);

  const refresh = useCallback(() => {
    apiGeneratorList()
      .then(setItems)
      .catch((e) => toast.error(sanitizeError(e, t("generatorScreen.loadFailed"))));
  }, [toast, t]);

  useEffect(() => {
    apiGeneratorLimits().then(setLimits).catch(() => {});
    refresh();
  }, [refresh]);

  // Переключение типа сбрасывает длину на разумную для него: 43 символа
  // base64url и 43 символа пароля — величины разного смысла.
  const switchKind = (next: GeneratedKind) => {
    setKind(next);
    setLength(DEFAULT_LEN[next]);
  };

  const clampedLength = Math.min(Math.max(length, minLen), limits?.max_len ?? 256);

  const handleGenerate = async () => {
    if (busy) return;
    setBusy(true);
    try {
      // Генерация — тем же CSPRNG, что и при заполнении поля записи.
      const value = generateSecret(clampedLength, CHARSET_FOR_KIND[effectiveKind]);
      const created = await apiGeneratorCreate(effectiveKind, value);
      setItems((prev) => [created, ...prev]);
    } catch (e) {
      toast.error(sanitizeError(e, t("generatorScreen.generateFailed")));
    } finally {
      setBusy(false);
    }
  };

  const handleCopy = async (id: string) => {
    try {
      await apiGeneratorCopy(id);
      toast.success(t("generatorScreen.copied"));
    } catch (e) {
      toast.error(sanitizeError(e, t("generatorScreen.copyFailed")));
    }
  };

  const toggle = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleDeleteSelected = async () => {
    if (selected.size === 0) return;
    try {
      await apiGeneratorDelete([...selected]);
      setSelected(new Set());
      refresh();
    } catch (e) {
      toast.error(sanitizeError(e, t("generatorScreen.deleteFailed")));
    }
  };

  return (
    <div className="h-full flex flex-col">
      <header className="flex items-center gap-2 px-4 py-3 border-b border-white/8 shrink-0">
        <IconButton icon={<ArrowLeft />} aria-label={t("common.back")} variant="subtle" onClick={onClose} />
        <h1 className="text-sm font-semibold flex-1">{t("generatorScreen.title")}</h1>
        {selected.size > 0 && (
          <Button variant="secondary" size="sm" onClick={handleDeleteSelected} leftIcon={<Trash2 className="h-3.5 w-3.5" />}>
            {t("generatorScreen.deleteSelected", { count: selected.size })}
          </Button>
        )}
      </header>

      <div className="px-4 py-3 space-y-3 border-b border-white/8 shrink-0">
        <div className="grid grid-cols-3 gap-1.5">
          {KIND_ORDER.map((k) => (
            <button
              key={k}
              type="button"
              onClick={() => switchKind(k)}
              className={cn(
                "px-2 py-2 rounded-lg border text-2xs font-medium transition-colors",
                kind === k
                  ? "border-brand-500/40 bg-brand-500/10 text-brand-200"
                  : "border-white/10 bg-white/4 text-white/55 hover:bg-white/8",
              )}
            >
              {t(`generatorScreen.kind_${k}`)}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <label htmlFor="gen-len" className="text-2xs text-white/55 shrink-0">
            {t("generatorScreen.length")}
          </label>
          <Input
            id="gen-len"
            type="number"
            inputMode="numeric"
            min={minLen}
            max={limits?.max_len ?? 256}
            value={String(length)}
            onChange={(e) => setLength(Number(e.target.value) || minLen)}
            className="w-24 text-center"
          />
          <span className="text-2xs text-white/40 flex-1">
            {t("generatorScreen.entropy", { bits: entropyBits(effectiveKind, clampedLength) })}
          </span>
        </div>

        {kind === "password" && (
          <label className="flex items-start gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={alnumOnly}
              onChange={(e) => setAlnumOnly(e.target.checked)}
              className="accent-brand-500 mt-0.5"
            />
            <span className="text-2xs text-white/55 leading-snug">
              {t("generatorScreen.alnumOnly")}
              <span className="block text-white/35">{t("generatorScreen.alnumOnlyHint")}</span>
            </span>
          </label>
        )}

        {length < minLen && (
          <p className="text-2xs text-warning/85">
            {t("generatorScreen.minLength", { min: minLen })}
          </p>
        )}

        <Button fullWidth onClick={handleGenerate} loading={busy} leftIcon={<RefreshCw className="h-4 w-4" />}>
          {t("generatorScreen.generate")}
        </Button>

        <p className="text-2xs text-white/40 leading-snug">
          {t("generatorScreen.retentionNotice", { hours: limits?.retention_hours ?? 24 })}
        </p>
      </div>

      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-2">
        {items.length === 0 && (
          <p className="text-2xs text-white/35 text-center pt-6">{t("generatorScreen.empty")}</p>
        )}
        {items.map((item) => (
          <div
            key={item.id}
            className={cn(
              "flex items-center gap-2 px-3 py-2 rounded-lg border transition-colors",
              selected.has(item.id)
                ? "border-brand-500/40 bg-brand-500/10"
                : "border-white/10 bg-white/4",
            )}
          >
            <input
              type="checkbox"
              checked={selected.has(item.id)}
              onChange={() => toggle(item.id)}
              aria-label={t("generatorScreen.selectItem")}
              className="accent-brand-500"
            />
            <div className="flex-1 min-w-0">
              {/* Значение не показывается: список рисуется из метаданных, а сам
                  секрет backend отдаёт только в буфер обмена. */}
              <div className="text-xs font-medium text-white/85">
                {t(`generatorScreen.kind_${item.kind}`)} · {item.length}
              </div>
              <div className="text-2xs text-white/40">
                {new Date(item.created_at).toLocaleString()} ·{" "}
                {t("generatorScreen.entropy", { bits: entropyBits(item.kind, item.length) })}
              </div>
            </div>
            <IconButton
              icon={<Copy className="h-4 w-4" />}
              aria-label={t("generatorScreen.copy")}
              variant="subtle"
              onClick={() => handleCopy(item.id)}
            />
          </div>
        ))}
      </div>
    </div>
  );
}
