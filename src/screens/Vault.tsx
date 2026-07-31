import { useCallback, useEffect, useState } from "react";
import { CheckSquare, Lock, Plus, Search, Settings as SettingsIcon, Trash2, X } from "lucide-react";
import {
  apiClipboardCopy,
  apiRecordReveal,
  apiSettingsGet,
  apiRecordGet,
  apiRecordUpdate,
  apiRecordsBatchDelete,
  type SettingsDto,
  type RecordInput,
} from "@/lib/api";
import { sanitizeError } from "@/lib/sanitizeError";
import { cn } from "@/lib/cn";
import { IconButton } from "@/components/ui/IconButton";
import { Input } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import { useToast } from "@/components/ui/Toast";
import { RecordCard } from "@/components/RecordCard";
import { BrandLogo } from "@/components/BrandLogo";
import { Sheet } from "@/components/ui/Sheet";
import { RecordEdit } from "./RecordEdit";
import { RecordView } from "./RecordView";
import { Settings } from "./Settings";
import { Spinner } from "@/components/ui/Spinner";
import { useRecordList, type Category } from "./vault/useRecordList";
import { useIdleAutolock } from "./vault/useIdleAutolock";
import { useAutoBackup } from "./vault/useAutoBackup";
import { useDragReorder } from "./vault/useDragReorder";
import { useTranslation } from 'react-i18next';

interface Props {
  onLock: () => void;
}

type Mode =
  | { kind: "list" }
  | { kind: "view"; id: string }
  | { kind: "create" }
  | { kind: "edit"; id: string };

export function VaultScreen({ onLock }: Props) {
  const [mode, setMode] = useState<Mode>({ kind: "list" });
  const [selectedCategory, setSelectedCategory] = useState<Category>("all");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settings, setSettings] = useState<SettingsDto | null>(null);
  const [dbType, setDbType] = useState<"records" | "web">("records");
  const toast = useToast();
  const { t } = useTranslation();

  const onListError = useCallback((msg: string) => toast.error(msg), [toast]);
  const {
    records,
    query,
    setQuery,
    loading,
    loadingMore,
    hasMore,
    loadMore,
    refresh,
    applyOrder,
  } = useRecordList(dbType, selectedCategory, onListError);

  useAutoBackup();
  useIdleAutolock(settings?.autolock_seconds, onLock);

  useEffect(() => {
    apiSettingsGet().then(setSettings).catch(() => {});
  }, []);

  // Reorder возможен только в неотфильтрованном виде (иначе sort_order по
  // подмножеству сломал бы глобальный порядок).
  const canReorder = selectedCategory === "all" && !query;
  // N-03: включён ли гейт «копирование/просмотр» (для индикатора в RecordView).
  const requireAuth = !!(settings?.require_auth_for_copy && settings?.use_windows_hello);

  const handleReorder = (sourceId: string, targetId: string) => {
    if (sourceId === targetId) return;
    const from = records.findIndex((r) => r.id === sourceId);
    const to = records.findIndex((r) => r.id === targetId);
    if (from === -1 || to === -1) return;
    const next = [...records];
    const [moved] = next.splice(from, 1);
    next.splice(to, 0, moved);
    applyOrder(next.map((r) => r.id));
  };

  // Фаза 2 (a11y): клавиатурное перемещение записи (Alt+↑/↓ на карточке).
  const moveRecord = (id: string, dir: -1 | 1) => {
    const i = records.findIndex((r) => r.id === id);
    const j = i + dir;
    if (i < 0 || j < 0 || j >= records.length) return;
    const next = [...records];
    [next[i], next[j]] = [next[j], next[i]];
    applyOrder(next.map((r) => r.id));
  };

  const handleMoveCategory = async (
    recordId: string,
    category: "work" | "personal",
  ) => {
    const record = records.find((r) => r.id === recordId);
    if (!record || record.category === category) return;
    try {
      const full = await apiRecordGet(dbType, recordId);
      const input: RecordInput = {
        name: full.name,
        project: full.project,
        icon: full.icon,
        color: full.color,
        category,
        // value:null → «не менять» (H-01 контракт): секреты не перезаписываются.
        fields: full.fields.map((f) => ({
          id: f.id,
          field_type: f.field_type,
          label: f.label,
          is_secret: f.is_secret,
          sort_order: f.sort_order,
          value: null,
        })),
      };
      await apiRecordUpdate(dbType, recordId, input);
      toast.success(category === "work" ? t('vault.movedToWork') : t('vault.movedToPersonal'));
      refresh();
    } catch (e) {
      toast.error(sanitizeError(e, t('vault.moveError')));
    }
  };

  const { draggedId, activeDragTargetId, dragOverTab, handlePointerDown } =
    useDragReorder({
      onOpen: (id) => setMode({ kind: "view", id }),
      onReorder: handleReorder,
      onMoveCategory: handleMoveCategory,
      canReorder,
    });

  const handleCopy = async (recordId: string, fieldId: string) => {
    try {
      await apiClipboardCopy(dbType, recordId, fieldId, settings?.clipboard_clear_seconds);
      toast.success(
        settings?.clipboard_clear_seconds
          ? t('vault.copiedClear', { seconds: settings.clipboard_clear_seconds })
          : t('vault.copied'),
      );
    } catch (e) {
      toast.error(sanitizeError(e, t('vault.copyError')));
    }
  };

  const handleReveal = (recordId: string, fieldId: string): Promise<string> =>
    apiRecordReveal(dbType, recordId, fieldId);

  const [selectionMode, setSelectionMode] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  const toggleSelect = (id: string) => {
    setSelectedIds((cur) => {
      const next = new Set(cur);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleSelectAll = () => {
    if (selectedIds.size === records.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(records.map((r) => r.id)));
    }
  };

  const handleBatchDelete = async () => {
    if (selectedIds.size === 0) return;
    const count = selectedIds.size;
    const ok = window.confirm(t('vault.deleteSelectedConfirm', { count }));
    if (!ok) return;
    try {
      await apiRecordsBatchDelete(dbType, Array.from(selectedIds));
      toast.success(t('recordView.deleted'));
      setSelectedIds(new Set());
      setSelectionMode(false);
      refresh();
    } catch (e) {
      toast.error(sanitizeError(e, t('recordView.deleteError')));
    }
  };

  const empty = !loading && records.length === 0 && !query;

  const switchDb = (t: "records" | "web") => {
    setDbType(t);
    setSelectedCategory("all");
    setQuery("");
    setSelectedIds(new Set());
    setSelectionMode(false);
  };

  return (
    <div className="h-full flex flex-col">
      {/* Top bar */}
      <header className="px-4 pt-3 pb-2 flex items-center gap-2 border-b border-white/[0.05]">
        <BrandLogo size={28} />
        <span className="text-sm font-medium tracking-tight ml-1 mr-auto">Vaultisor</span>
        <IconButton
          icon={<CheckSquare className={cn("h-4 w-4", selectionMode && "text-brand-300")} />}
          aria-label={t('vault.selectMode')}
          variant={selectionMode ? "filled" : "subtle"}
          onClick={() => {
            setSelectionMode(!selectionMode);
            if (selectionMode) setSelectedIds(new Set());
          }}
        />
        <IconButton icon={<SettingsIcon />} aria-label={t('vault.settings')} variant="subtle" onClick={() => setSettingsOpen(true)} />
        <IconButton icon={<Lock />} aria-label={t('vault.lock')} variant="subtle" onClick={onLock} />
      </header>

      {selectionMode && (
        <div className="px-4 py-1.5 flex items-center justify-between border-b border-brand-500/20 bg-brand-500/10 text-xs text-brand-300">
          <span>{t('vault.selectedCount', { count: selectedIds.size })}</span>
          <div className="flex gap-2">
            <button type="button" onClick={handleSelectAll} className="hover:underline font-medium">
              {t('vault.selectAll')}
            </button>
            <button
              type="button"
              onClick={() => {
                setSelectionMode(false);
                setSelectedIds(new Set());
              }}
              className="hover:underline opacity-70"
            >
              {t('vault.cancelSelect')}
            </button>
          </div>
        </div>
      )}

      {/* Partition Tabs */}
      <div className="px-4 py-2 flex border-b border-white/[0.05] bg-white/[0.01] gap-1.5">
        <button
          type="button"
          onClick={() => switchDb("records")}
          className={`flex-1 py-1.5 text-xs font-semibold rounded-lg border transition-all duration-300 ${
            dbType === "records"
              ? "bg-brand-500/15 text-brand-300 border-brand-500/40 shadow-[0_2px_12px_rgba(12,164,159,0.15)]"
              : "bg-white/[0.01] text-white/45 border-white/[0.04] hover:bg-white/[0.04] hover:text-white/80"
          }`}
        >
          {t('vault.tabProjects')}
        </button>
        <button
          type="button"
          onClick={() => switchDb("web")}
          className={`flex-1 py-1.5 text-xs font-semibold rounded-lg border transition-all duration-300 ${
            dbType === "web"
              ? "bg-brand-500/15 text-brand-300 border-brand-500/40 shadow-[0_2px_12px_rgba(12,164,159,0.15)]"
              : "bg-white/[0.01] text-white/45 border-white/[0.04] hover:bg-white/[0.04] hover:text-white/80"
          }`}
        >
          {t('vault.tabWeb')}
        </button>
      </div>

      {/* Search */}
      <div className="px-4 pt-3 pb-1">
        <Input
          leftIcon={<Search />}
          rightSlot={
            query ? (
              <IconButton icon={<X />} aria-label={t('vault.clear')} size="sm" variant="subtle" onClick={() => setQuery("")} />
            ) : undefined
          }
          placeholder={t('vault.searchPlaceholder')}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>

      {/* Category Tabs */}
      <div className="px-4 py-1.5 flex items-center gap-1.5 border-b border-white/[0.03] bg-white/[0.01]">
        {(["all", "work", "personal"] as const).map((cat) => {
          const active = selectedCategory === cat;
          const isOver = dragOverTab === cat;
          const label = cat === "all" ? t('vault.catAll') : cat === "work" ? t('vault.catWork') : t('vault.catPersonal');
          return (
            <div
              key={cat}
              role="button"
              tabIndex={0}
              data-category-tab={cat}
              onClick={() => setSelectedCategory(cat)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  setSelectedCategory(cat);
                }
              }}
              className={`px-4 py-1.5 text-xs font-semibold rounded-full border transition-all duration-300 cursor-pointer select-none ${
                isOver
                  ? "bg-brand-500/25 text-brand-200 border-brand-400 scale-[1.05] shadow-[0_0_15px_rgba(12,164,159,0.4)]"
                  : active
                  ? "bg-brand-500/15 text-brand-300 border-brand-500/40 shadow-[0_2px_12px_rgba(12,164,159,0.15)]"
                  : "bg-white/[0.01] text-white/45 border-white/[0.04] hover:bg-white/[0.04] hover:text-white/80"
              }`}
            >
              {label}
            </div>
          );
        })}
      </div>

      {/* List */}
      <main className="flex-1 overflow-y-auto px-3 pt-2 pb-24">
        {loading ? (
          <div className="flex items-center justify-center pt-16 text-white/60">
            <Spinner className="h-5 w-5" />
          </div>
        ) : empty ? (
          <EmptyState dbType={dbType} />
        ) : records.length === 0 ? (
          <div className="text-center py-12 text-sm text-white/45">{t('vault.notFound')}</div>
        ) : (
          <div className="space-y-1.5 px-1 pt-1">
            {records.map((r) => (
              <RecordCard
                key={r.id}
                record={r}
                selectable={selectionMode}
                selected={selectedIds.has(r.id)}
                onSelectToggle={() => toggleSelect(r.id)}
                onPointerDown={selectionMode ? undefined : (e) => handlePointerDown(e, r.id)}
                onOpen={() => setMode({ kind: "view", id: r.id })}
                onMoveUp={canReorder && !selectionMode ? () => moveRecord(r.id, -1) : undefined}
                onMoveDown={canReorder && !selectionMode ? () => moveRecord(r.id, 1) : undefined}
                isDragging={draggedId === r.id}
                isDragTarget={activeDragTargetId === r.id}
              />
            ))}
            {hasMore && (
              <div className="pt-2 pb-1 flex justify-center">
                <Button variant="secondary" size="sm" loading={loadingMore} onClick={loadMore}>
                  {t('vault.showMore')}
                </Button>
              </div>
            )}
          </div>
        )}
      </main>

      {/* FAB or Batch Action Bar */}
      {selectionMode ? (
        <div className="fixed bottom-4 left-4 right-4 p-3 rounded-2xl bg-black/80 backdrop-blur-xl border border-white/10 flex items-center justify-between shadow-2xl z-20 animate-fade-in">
          <span className="text-xs text-white/70 ml-2 font-medium">
            {t('vault.selectedCount', { count: selectedIds.size })}
          </span>
          <Button
            variant="danger"
            size="sm"
            disabled={selectedIds.size === 0}
            onClick={handleBatchDelete}
            leftIcon={<Trash2 className="h-4 w-4" />}
          >
            {t('vault.deleteSelected', { count: selectedIds.size })}
          </Button>
        </div>
      ) : (
        <button
          type="button"
          onClick={() => setMode({ kind: "create" })}
          aria-label={t('vault.createRecord')}
          className="absolute bottom-5 right-5 h-14 w-14 rounded-full bg-brand-500 hover:bg-brand-600 active:scale-[0.96] transition-app flex items-center justify-center text-white shadow-[0_8px_24px_-6px_rgba(12,164,159,0.6)]"
        >
          <Plus className="h-6 w-6" />
        </button>
      )}

      {/* Sheets */}
      <Sheet open={mode.kind === "view"} onClose={() => setMode({ kind: "list" })} position="full">
        {mode.kind === "view" && (
          <RecordView
            dbType={dbType}
            recordId={mode.id}
            requireAuth={requireAuth}
            onBack={() => setMode({ kind: "list" })}
            onEdit={() => setMode({ kind: "edit", id: mode.id })}
            onDeleted={() => {
              setMode({ kind: "list" });
              refresh();
            }}
            onCopy={handleCopy}
            onReveal={handleReveal}
          />
        )}
      </Sheet>

      <Sheet
        open={mode.kind === "create" || mode.kind === "edit"}
        onClose={() => setMode({ kind: "list" })}
        position="full"
      >
        {(mode.kind === "create" || mode.kind === "edit") && (
          <RecordEdit
            dbType={dbType}
            recordId={mode.kind === "edit" ? mode.id : null}
            initialCategory={selectedCategory === "all" ? "personal" : selectedCategory}
            onCancel={() => {
              if (mode.kind === "edit") setMode({ kind: "view", id: mode.id });
              else setMode({ kind: "list" });
            }}
            onSaved={(id) => {
              setMode({ kind: "view", id });
              refresh();
            }}
          />
        )}
      </Sheet>

      <Sheet open={settingsOpen} onClose={() => setSettingsOpen(false)} position="full">
        <Settings onClose={() => setSettingsOpen(false)} onSettingsChanged={(s) => setSettings(s)} />
      </Sheet>
    </div>
  );
}

function EmptyState({ dbType }: { dbType: "records" | "web" }) {
  const isWeb = dbType === "web";
  const { t } = useTranslation();
  return (
    <div className="text-center pt-20 px-6 space-y-3">
      <div className="mx-auto h-14 w-14 rounded-2xl bg-brand-500/15 flex items-center justify-center text-brand-300">
        <Plus className="h-6 w-6" />
      </div>
      <div className="space-y-1">
        <div className="font-medium">
          {isWeb ? t('vault.emptyWebTitle') : t('vault.emptyRecordsTitle')}
        </div>
        <p className="text-xs text-white/50 leading-relaxed max-w-[260px] mx-auto">
          {isWeb
            ? t('vault.emptyWebDesc')
            : t('vault.emptyRecordsDesc')}
        </p>
        <p className="text-2xs text-white/30 pt-1">{t('vault.emptyHint')}</p>
      </div>
    </div>
  );
}
