import { useCallback, useEffect, useRef, useState } from "react";
import { ChevronLeft, Pencil, ShieldCheck, Trash2 } from "lucide-react";
import { apiRecordDelete, apiRecordGet, type RecordModel } from "@/lib/api";
import { IconButton } from "@/components/ui/IconButton";
import { Button } from "@/components/ui/Button";
import { Spinner } from "@/components/ui/Spinner";
import { useToast } from "@/components/ui/Toast";
import { FieldRow } from "@/components/FieldRow";
import { formatRelativeTime } from "@/lib/format";
import { Sheet } from "@/components/ui/Sheet";
import { useTranslation, Trans } from 'react-i18next';

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
  const toast = useToast();
  const { t } = useTranslation();

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
        {record.fields.map((f) => (
          <FieldRow
            key={f.id}
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
        ))}

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
