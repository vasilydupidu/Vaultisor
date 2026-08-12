import { useCallback, useEffect, useRef, useState } from "react";
import { ChevronLeft, Pencil, ShieldCheck, Trash2 } from "lucide-react";
import { apiRecordDelete, apiRecordGet, apiGetEnableHealthCheck, type RecordModel } from "@/lib/api";
import { IconButton } from "@/components/ui/IconButton";
import { Button } from "@/components/ui/Button";
import { Spinner } from "@/components/ui/Spinner";
import { useToast } from "@/components/ui/Toast";
import { FieldRow } from "@/components/FieldRow";
import { formatRelativeTime } from "@/lib/format";
import { Sheet } from "@/components/ui/Sheet";
import { useTranslation, Trans } from 'react-i18next';
import { isPasswordWeak } from "@/lib/healthCheck";

// M-04: через сколько мс автоматически ре-маскировать раскрытый на экране секрет.
const REVEAL_HIDE_MS = 30_000;

interface Props {
  dbType: "records" | "web";
  recordId: string;
  /** N-03: включён гейт «копирование/просмотр» → показываем индикатор доверия. */
  requireAuth?: boolean;
  onBack: () => void;
  onEdit: () => void;
  onDeleted: () => void;
  onCopy: (recordId: string, fieldId: string) => Promise<void> | void;
  onReveal: (recordId: string, fieldId: string) => Promise<string>;
}

export function RecordView({
  dbType,
  recordId,
  requireAuth,
  onBack,
  onEdit,
  onDeleted,
  onCopy,
  onReveal,
}: Props) {
  const [record, setRecord] = useState<RecordModel | null>(null);
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [enableHealthCheck, setEnableHealthCheck] = useState(true);
  const toast = useToast();
  const { t } = useTranslation();

  useEffect(() => {
    apiGetEnableHealthCheck().then(setEnableHealthCheck).catch(() => {});
  }, []);

  // M-04: раскрытый на экране секрет не должен висеть в state/DOM бесконечно.
  // Через REVEAL_HIDE_MS автоматически ре-маскируем поле (согласовано с
  // авто-очисткой буфера обмена). Таймеры чистятся при hide и размонтировании.
  const hideTimers = useRef<Record<string, ReturnType<typeof setTimeout>>>({});
  const clearTimer = (fieldId: string) => {
    const t = hideTimers.current[fieldId];
    if (t) {
      clearTimeout(t);
      delete hideTimers.current[fieldId];
    }
  };
  useEffect(() => {
    const timers = hideTimers.current;
    return () => {
      Object.values(timers).forEach((t) => clearTimeout(t));
    };
  }, []);

  const refresh = useCallback(async () => {
    try {
      const r = await apiRecordGet(dbType, recordId);
      setRecord(r);

      // Авто-раскрытие открытых полей (Логин, URL сайта, Заметка)
      const nonSecrets = r.fields.filter((f) => !f.is_secret);
      if (nonSecrets.length > 0) {
        const revealedEntries = await Promise.all(
          nonSecrets.map(async (f) => {
            try {
              const val = await onReveal(r.id, f.id);
              return [f.id, val] as const;
            } catch {
              return [f.id, ""] as const;
            }
          }),
        );
        setRevealed((cur) => ({
          ...cur,
          ...Object.fromEntries(revealedEntries),
        }));
      }
    } catch (e) {
      toast.error(t('recordView.loadError'));
      onBack();
    }
  }, [dbType, recordId, onBack, onReveal, toast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleDelete = async () => {
    try {
      await apiRecordDelete(dbType, recordId);
      toast.success(t('recordView.deleted'));
      onDeleted();
    } catch {
      toast.error(t('recordView.deleteError'));
    }
  };

  if (!record) {
    return (
      <div className="h-full flex items-center justify-center text-white/60">
        <Spinner className="h-5 w-5" />
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      <header className="px-4 pt-3 pb-2 flex items-center gap-1 border-b border-white/[0.05]">
        <IconButton
          icon={<ChevronLeft />}
          aria-label={t('common.back')}
          variant="subtle"
          onClick={onBack}
        />
        <div className="flex-1 min-w-0 ml-1">
          <div className="text-sm font-medium truncate">{record.name}</div>
          {record.project && (
            <div className="text-2xs text-brand-300/80 truncate flex items-center gap-1">
              {dbType === "web" ? (
                <>
                  <span className="opacity-50 text-white/70">{t('recordView.sitePrefix')}</span>
                  <a
                    href={/^https?:\/\//i.test(record.project) ? record.project : `https://${record.project}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="hover:underline hover:text-brand-300 cursor-pointer"
                  >
                    {record.project}
                  </a>
                </>
              ) : (
                record.project
              )}
            </div>
          )}
        </div>
        <IconButton
          icon={<Pencil />}
          aria-label={t('common.edit')}
          variant="subtle"
          onClick={onEdit}
        />
        <IconButton
          icon={<Trash2 />}
          aria-label={t('common.delete')}
          variant="danger"
          onClick={() => setConfirmDelete(true)}
        />
      </header>

      {requireAuth && (
        <div className="px-4 pt-2">
          <div className="flex items-center gap-2 text-2xs text-brand-300/85 bg-brand-500/[0.07] border border-brand-500/15 rounded-lg px-2.5 py-1.5">
            <ShieldCheck className="h-3.5 w-3.5 shrink-0" />
            <span className="leading-snug">
              {t('recordView.authHint')}
            </span>
          </div>
        </div>
      )}

      <div className="flex-1 overflow-y-auto px-4 py-4 space-y-2.5">
        {record.fields.length === 0 && (
          <div className="card-flat p-4 text-center text-sm text-white/45">
            {t('recordView.noFields')}
          </div>
        )}
        {record.fields.map((f) => {
          const isSecretField = f.is_secret || f.field_type === "secret";
          const valToCheck = revealed[f.id] || (f.value_preview !== "••••••••" ? f.value_preview : "");
          const isWeak = enableHealthCheck && isSecretField && valToCheck && isPasswordWeak(valToCheck);

          return (
            <div key={f.id} className="space-y-1">
              <FieldRow
                field={f}
                revealedValue={revealed[f.id]}
                onReveal={async () => {
                  const v = await onReveal(record.id, f.id);
                  setRevealed((cur) => ({ ...cur, [f.id]: v }));
                  // M-04: запускаем авто-скрытие этого поля.
                  clearTimer(f.id);
                  hideTimers.current[f.id] = setTimeout(() => {
                    setRevealed((cur) => {
                      const next = { ...cur };
                      delete next[f.id];
                      return next;
                    });
                    delete hideTimers.current[f.id];
                  }, REVEAL_HIDE_MS);
                }}
                onHide={() => {
                  clearTimer(f.id);
                  setRevealed((cur) => {
                    const next = { ...cur };
                    delete next[f.id];
                    return next;
                  });
                }}
                onCopy={async () => {
                  await onCopy(record.id, f.id);
                }}
              />
              {isWeak && (
                <div className="text-2xs text-amber-300 bg-amber-500/10 border border-amber-500/20 rounded-md px-2.5 py-1.5 flex items-center gap-1.5 font-medium">
                  ⚠️ {t('healthCheck.weak')} — пароль слишком простой или короткий (&lt;8 символов)
                </div>
              )}
            </div>
          );
        })}

        <PasswordHistorySection
          dbType={dbType}
          recordId={recordId}
          onRestore={refresh}
        />

        <div className="text-2xs text-white/35 text-center pt-4">
          {t('recordView.updatedAt', { time: formatRelativeTime(record.updated_at) })}
        </div>
      </div>

      <Sheet
        open={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        title={t('recordView.deleteTitle')}
      >
        <div className="space-y-4">
          <p className="text-sm text-white/65">
            <Trans
              i18nKey="recordView.deleteDesc"
              values={{ name: record.name }}
              components={{ span: <span className="text-white" /> }}
            />
          </p>
          <div className="flex gap-2">
            <Button variant="secondary" fullWidth onClick={() => setConfirmDelete(false)}>
              {t('common.cancel')}
            </Button>
            <Button variant="danger" fullWidth onClick={handleDelete}>
              {t('common.delete')}
            </Button>
          </div>
        </div>
      </Sheet>
    </div>
  );
}

function PasswordHistorySection({
  dbType,
  recordId,
  onRestore,
}: {
  dbType: "records" | "web";
  recordId: string;
  onRestore: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [enabled, setEnabled] = useState(true);
  const [history, setHistory] = useState<import("@/lib/api").PasswordHistoryEntry[]>([]);
  const toast = useToast();
  const { t } = useTranslation();

  useEffect(() => {
    import("@/lib/api").then(m => m.apiGetEnablePasswordHistory()).then(setEnabled).catch(() => {});
  }, []);

  const loadHistory = useCallback(async () => {
    try {
      const items = await import("@/lib/api").then((m) =>
        m.apiGetPasswordHistory(dbType, recordId),
      );
      setHistory(items);
    } catch {
      setHistory([]);
    }
  }, [dbType, recordId]);

  useEffect(() => {
    if (open && enabled) {
      loadHistory();
    }
  }, [open, enabled, loadHistory]);

  if (!enabled) return null;

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="w-full mt-2 card-flat p-3 flex items-center justify-between text-xs text-white/60 hover:text-white/90 hover:bg-white/[0.04] transition-colors"
      >
        <span className="flex items-center gap-2 font-medium">
          📜 {t('recordView.historyTitle')}
        </span>
        <span className="text-2xs text-white/40">▼</span>
      </button>
    );
  }

  return (
    <div className="mt-2 card-flat p-3 space-y-2.5">
      <div className="flex items-center justify-between border-b border-white/[0.06] pb-2">
        <span className="text-xs font-semibold text-white/85 flex items-center gap-1.5">
          📜 {t('recordView.historyTitle')} ({history.length})
        </span>
        <div className="flex items-center gap-2">
          {history.length > 0 && (
            <button
              type="button"
              onClick={async () => {
                const api = await import("@/lib/api");
                await api.apiClearPasswordHistory(dbType, recordId);
                setHistory([]);
              }}
              className="text-2xs text-red-400/80 hover:text-red-300"
            >
              {t('recordView.historyClear')}
            </button>
          )}
          <button
            type="button"
            onClick={() => setOpen(false)}
            className="text-2xs text-white/40 hover:text-white/80"
          >
            ▲
          </button>
        </div>
      </div>

      {history.length === 0 ? (
        <div className="text-2xs text-white/40 text-center py-2">
          {t('recordView.historyEmpty')}
        </div>
      ) : (
        <div className="space-y-2">
          {history.map((h) => (
            <div
              key={h.id}
              className="bg-black/20 border border-white/[0.05] rounded-lg p-2.5 flex items-center justify-between gap-2 text-xs"
            >
              <div className="min-w-0 flex-1">
                <div className="text-2xs text-white/40 flex items-center gap-1">
                  <span>{h.field_label}</span>
                  <span>•</span>
                  <span>{formatRelativeTime(h.created_at)}</span>
                </div>
                <div className="font-mono text-white/80 truncate">••••••••••••</div>
              </div>
              <div className="flex items-center gap-1 shrink-0">
                <button
                  type="button"
                  title={t('common.copy')}
                  onClick={async () => {
                    const api = await import("@/lib/api");
                    await api.apiClipboardCopyText(h.value, 30);
                    toast.success(t('common.copy'));
                  }}
                  className="p-1.5 rounded hover:bg-white/10 text-white/70 hover:text-white text-2xs"
                >
                  📋
                </button>
                <button
                  type="button"
                  title={t('recordView.historyRestore')}
                  onClick={async () => {
                    try {
                      const api = await import("@/lib/api");
                      const curRecord = await api.apiRecordGet(dbType, recordId);
                      const updatedFields = curRecord.fields.map((f) => ({
                        id: f.id,
                        field_type: f.field_type,
                        label: f.label,
                        is_secret: f.is_secret,
                        sort_order: f.sort_order,
                        value: f.id === h.field_id ? h.value : null,
                      }));
                      await api.apiRecordUpdate(dbType, recordId, {
                        name: curRecord.name,
                        project: curRecord.project,
                        icon: curRecord.icon,
                        color: curRecord.color,
                        category: curRecord.category,
                        fields: updatedFields,
                      });
                      toast.success(t('recordView.historyRestoredToast'));
                      onRestore();
                      loadHistory();
                    } catch {
                      toast.error(t('sanitizeError.defaultMessage'));
                    }
                  }}
                  className="px-2 py-1 bg-brand-500/20 hover:bg-brand-500/30 text-brand-300 text-2xs font-medium rounded"
                >
                  {t('recordView.historyRestore')}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
