import { useCallback, useEffect, useState } from "react";
import { Check, ChevronLeft, Plus, Trash2, Wand2 } from "lucide-react";
import {
  apiRecordCreate,
  apiRecordGet,
  apiRecordReveal,
  apiRecordUpdate,
  type FieldInput,
  type FieldType,
} from "@/lib/api";
import { IconButton } from "@/components/ui/IconButton";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Spinner } from "@/components/ui/Spinner";
import { useToast } from "@/components/ui/Toast";
import { Sheet } from "@/components/ui/Sheet";
import { cn } from "@/lib/cn";
import { fieldSaveValue } from "@/lib/recordDraft";
import { allFieldTypes } from "@/lib/fieldTypes";
import { sanitizeError } from "@/lib/sanitizeError";
import { GeneratorSheet } from "@/components/GeneratorSheet";
import { useTranslation } from 'react-i18next';

interface Props {
  dbType: "records" | "web";
  recordId: string | null;
  /** Категория по умолчанию для НОВОЙ записи (из активной вкладки). */
  initialCategory?: "personal" | "work";
  onCancel: () => void;
  onSaved: (id: string) => void;
}

interface DraftField extends FieldInput {
  /** Локальный uid для React.key. */
  uid: string;
  /**
   * H-01: значение поля, загруженное при открытии редактора. Используется на
   * сохранении для детекции изменений: если value не менялся относительно
   * original, поле отправляется как value=null («не менять»), и его blob не
   * перезаписывается. Это защищает секрет от затирания, если расшифровка при
   * загрузке не удалась (тогда original="" и нетронутое поле сохраняет исходный
   * шифротекст вместо пустой строки).
   */
  original?: string;
  /** H-01: true — расшифровать поле при загрузке не удалось (показано пустым). */
  revealFailed?: boolean;
  /**
   * M-05: было ли значение поля уже подгружено (расшифровано) в редакторе.
   * Существующие поля загружаются лениво — значение расшифровывается только по
   * кнопке «Показать / изменить», а не жадно при открытии записи. Пока
   * revealed=false, поле не трогалось и на сохранении уйдёт как value:null.
   */
  revealed?: boolean;
}


export function RecordEdit({ dbType, recordId, initialCategory, onCancel, onSaved }: Props) {
  const isEdit = !!recordId;
  const toast = useToast();
  const { t } = useTranslation();

  const [loading, setLoading] = useState(isEdit);
  const [name, setName] = useState("");
  const [project, setProject] = useState("");
  // Новая запись наследует категорию активной вкладки (Работа/Личные).
  const [category, setCategory] = useState<"personal" | "work">(initialCategory ?? "personal");
  const [fields, setFields] = useState<DraftField[]>(() => {
    if (dbType === "web") {
      return [
        {
          uid: "default-login",
          field_type: "id",
          label: t('recordEdit.defaultLogin'),
          is_secret: false,
          sort_order: 0,
          value: "",
        },
        {
          uid: "default-password",
          field_type: "secret",
          label: t('recordEdit.defaultPassword'),
          is_secret: true,
          sort_order: 1,
          value: "",
        },
      ];
    }
    return [
      {
        uid: rid(),
        field_type: "secret",
        label: t('recordEdit.defaultSecret'),
        is_secret: true,
        sort_order: 0,
        value: "",
      },
    ];
  });
  const [pickerOpen, setPickerOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  // Фаза 3 (#1): генератор значения — для какого поля открыт.
  const [genOpen, setGenOpen] = useState(false);
  const [genUid, setGenUid] = useState<string | null>(null);

  // Загрузка существующей записи и расшифровка её полей.
  const load = useCallback(async () => {
    if (!recordId) return;
    setLoading(true);
    try {
      const rec = await apiRecordGet(dbType, recordId);
      setName(rec.name);
      setProject(rec.project ?? "");
      setCategory(rec.category ?? "personal");
      // Авто-расшифровка несекретных полей (Логин, URL, Заметки) для редактирования
      const loaded: DraftField[] = await Promise.all(
        rec.fields.map(async (f) => {
          if (!f.is_secret) {
            try {
              const val = await apiRecordReveal(dbType, recordId, f.id);
              return {
                uid: rid(),
                id: f.id,
                field_type: f.field_type,
                label: f.label,
                is_secret: false,
                sort_order: f.sort_order,
                value: val,
                original: val,
                revealed: true,
              };
            } catch {
              // fallback if reveal fails
            }
          }
          return {
            uid: rid(),
            id: f.id,
            field_type: f.field_type,
            label: f.label,
            is_secret: f.is_secret,
            sort_order: f.sort_order,
            value: "",
            original: undefined,
            revealed: false,
          };
        }),
      );
      if (loaded.length === 0) {
        loaded.push({
          uid: rid(),
          field_type: "secret",
          label: t('recordEdit.defaultSecret'),
          is_secret: true,
          sort_order: 0,
          value: "",
          revealed: true,
        });
      }
      setFields(loaded);
    } catch {
      toast.error(t('recordEdit.loadError'));
      onCancel();
    } finally {
      setLoading(false);
    }
  }, [dbType, recordId, onCancel, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const addField = (type: FieldType) => {
    setFields((cur) => [
      ...cur,
      {
        uid: rid(),
        field_type: type,
        label: t(`fieldTypes.${type}`),
        is_secret: type !== "comment" && type !== "id",
        sort_order: cur.length,
        value: "",
      },
    ]);
    setPickerOpen(false);
  };

  const updateField = (uid: string, patch: Partial<DraftField>) => {
    setFields((cur) => cur.map((f) => (f.uid === uid ? { ...f, ...patch } : f)));
  };

  const removeField = (uid: string) => {
    setFields((cur) => cur.filter((f) => f.uid !== uid));
  };

  // M-05: подгрузить (расшифровать) значение существующего поля по требованию.
  const revealField = async (uid: string) => {
    const f = fields.find((x) => x.uid === uid);
    if (!f || !f.id || f.revealed || !recordId) return;
    try {
      const v = await apiRecordReveal(dbType, recordId, f.id);
      updateField(uid, { value: v, original: v, revealed: true, revealFailed: false });
    } catch {
      // H-01: расшифровка не удалась. Помечаем поле; на сохранении оно уйдёт как
      // value:null (не менять), пока пользователь не введёт новое значение.
      updateField(uid, { value: "", original: "", revealed: true, revealFailed: true });
      toast.error(t('recordEdit.revealError'));
    }
  };

  const handleSave = async () => {
    if (!name.trim()) {
      toast.error(t('recordEdit.nameRequired'));
      return;
    }
    if (fields.length === 0) {
      toast.error(t('recordEdit.fieldRequired'));
      return;
    }
    setSaving(true);
    try {
      const payload = {
        name: name.trim(),
        project: project.trim() || null,
        icon: null,
        color: null,
        category,
        fields: fields.map((f, i) => {
          const base = {
            id: f.id,
            field_type: f.field_type,
            label: f.label.trim() || t(`fieldTypes.${f.field_type}`),
            is_secret: f.is_secret,
            sort_order: i,
          };
          // H-01/M-05: нетронутое/неподгруженное существующее поле уходит как
          // value:null («не менять»), секрет не перезаписывается; изменённые и
          // новые — строкой. Логика вынесена в чистую fieldSaveValue (покрыта
          // тестами L-06).
          return { ...base, value: fieldSaveValue(f) };
        }),
      };
      let id: string;
      if (recordId) {
        await apiRecordUpdate(dbType, recordId, payload);
        id = recordId;
      } else {
        id = await apiRecordCreate(dbType, payload);
      }
      toast.success(recordId ? t('recordEdit.saved') : t('recordEdit.created'));
      onSaved(id);
    } catch (e) {
      toast.error(sanitizeError(e, t('recordEdit.saveError')));
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
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
          aria-label={t('common.cancel')}
          variant="subtle"
          onClick={onCancel}
        />
        <div className="flex-1 ml-1 text-sm font-medium">
          {isEdit ? t('recordEdit.titleEdit') : t('recordEdit.titleNew')}
        </div>
        <Button onClick={handleSave} loading={saving} size="sm" leftIcon={<Check className="h-4 w-4" />}>
          {t('common.save')}
        </Button>
      </header>

      <div className="flex-1 overflow-y-auto px-4 py-4 space-y-3">
        <div className="card-flat p-3.5 space-y-3">
          <Input
            label={dbType === "web" ? t('recordEdit.webName') : t('recordEdit.recordName')}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={dbType === "web" ? t('recordEdit.webNamePlaceholder') : t('recordEdit.recordNamePlaceholder')}
            autoFocus
          />
          <Input
            label={dbType === "web" ? t('recordEdit.webProject') : t('recordEdit.recordProject')}
            value={project}
            onChange={(e) => setProject(e.target.value)}
            placeholder={dbType === "web" ? t('recordEdit.webProjectPlaceholder') : t('recordEdit.optional')}
          />

          {/* Категория */}
          <div className="space-y-1.5">
            <label className="text-2xs font-semibold text-white/40 uppercase tracking-wider block">
              {t('recordEdit.category')}
            </label>
            <div className="flex gap-1.5">
              {(["personal", "work"] as const).map((cat) => {
                const active = category === cat;
                const label = cat === "personal" ? t('recordEdit.catPersonal') : t('recordEdit.catWork');
                return (
                  <button
                    key={cat}
                    type="button"
                    onClick={() => setCategory(cat)}
                    className={`flex-1 py-1.5 text-xs font-semibold rounded-lg border text-center transition-all duration-300 ${
                      active
                        ? "bg-brand-500/15 text-brand-300 border-brand-500/40"
                        : "bg-white/[0.01] text-white/45 border-white/[0.04] hover:bg-white/[0.04] hover:text-white/80"
                    }`}
                  >
                    {label}
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        <div className="section-title pt-2">{t('recordEdit.fieldsTitle')}</div>

        {fields.map((f) => {
          const isPrimaryWeb = dbType === "web" && (f.label === t('recordEdit.defaultLogin') || f.label === t('recordEdit.defaultPassword'));
          return (
            <div key={f.uid} className="card-flat p-3.5 space-y-3">
              {!isPrimaryWeb ? (
                <>
                  <div className="flex items-center gap-2">
                    <FieldTypeBadge
                      value={f.field_type}
                      onChange={(t) => updateField(f.uid, { field_type: t })}
                    />
                    <button
                      type="button"
                      onClick={() => updateField(f.uid, { is_secret: !f.is_secret })}
                      className={cn(
                        "text-2xs px-2 py-1 rounded-md border transition-app",
                        f.is_secret
                          ? "bg-brand-500/15 text-brand-300 border-brand-500/20"
                          : "bg-white/[0.04] text-white/50 border-white/10",
                      )}
                    >
                      {f.is_secret ? t('recordEdit.secretType') : t('recordEdit.publicType')}
                    </button>
                    <div className="flex-1" />
                    <IconButton
                      icon={<Trash2 />}
                      aria-label={t('recordEdit.deleteField')}
                      variant="danger"
                      size="sm"
                      onClick={() => removeField(f.uid)}
                    />
                  </div>
                  <Input
                    label={t('recordEdit.fieldLabel')}
                    value={f.label}
                    onChange={(e) => updateField(f.uid, { label: e.target.value })}
                    placeholder={t('recordEdit.fieldLabelPlaceholder')}
                  />
                </>
              ) : null}
              {f.id && !f.revealed ? (
                // M-05: значение существующего поля ещё не подгружено — не
                // расшифровываем, пока пользователь явно не откроет поле.
                <button
                  type="button"
                  onClick={() => revealField(f.uid)}
                  className="w-full flex items-center justify-between px-3 py-2 rounded-lg bg-white/[0.04] border border-white/10 text-sm hover:bg-white/[0.06] transition-app"
                >
                  <span className="tracking-widest text-white/60">••••••••</span>
                  <span className="text-2xs text-brand-300">{t('recordEdit.revealChange')}</span>
                </button>
              ) : (
                <div className="space-y-1">
                  <Input
                    label={isPrimaryWeb ? f.label : t('recordEdit.value')}
                    value={f.value ?? ""}
                    onChange={(e) => updateField(f.uid, { value: e.target.value })}
                    type={f.is_secret ? "password" : "text"}
                    placeholder={isPrimaryWeb ? t('recordEdit.valuePlaceholderWeb', { label: f.label.toLowerCase() }) : t('recordEdit.valuePlaceholder')}
                  />
                  <button
                    type="button"
                    onClick={() => {
                      setGenUid(f.uid);
                      setGenOpen(true);
                    }}
                    className="text-2xs text-brand-300 hover:text-brand-200 inline-flex items-center gap-1"
                  >
                    <Wand2 className="h-3 w-3" /> {t('recordEdit.generateValue')}
                  </button>
                  {f.revealFailed && (
                    <p className="text-2xs text-amber-400/80 leading-snug">
                      {t('recordEdit.revealFailedWarn')}
                    </p>
                  )}
                </div>
              )}
            </div>
          );
        })}

        <Button
          variant="primary"
          fullWidth
          leftIcon={<Plus className="h-4 w-4" />}
          onClick={() => setPickerOpen(true)}
        >
          {t('recordEdit.newField')}
        </Button>
      </div>

      <Sheet open={pickerOpen} onClose={() => setPickerOpen(false)} title={t('recordEdit.fieldTypeTitle')}>
        <div className="grid grid-cols-2 gap-2">
          {allFieldTypes.map((ft) => (
            <button
              key={ft}
              type="button"
              onClick={() => addField(ft)}
              className="card-flat py-3 px-2 text-sm text-white hover:bg-white/[0.06] transition-app"
            >
              {t(`fieldTypes.${ft}`)}
            </button>
          ))}
        </div>
      </Sheet>

      <GeneratorSheet
        open={genOpen}
        onClose={() => setGenOpen(false)}
        onInsert={(v) => {
          if (genUid) updateField(genUid, { value: v });
        }}
      />
    </div>
  );
}

function FieldTypeBadge({
  value,
  onChange,
}: {
  value: FieldType;
  onChange: (t: FieldType) => void;
}) {
  const { t: translate } = useTranslation();
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value as FieldType)}
      className="bg-white/[0.04] border border-white/10 rounded-md text-2xs text-white px-2 py-1 focus:outline-none focus:border-brand-500/60"
    >
      {allFieldTypes.map((t) => (
        <option key={t} value={t} className="bg-ink-900">
          {translate(`fieldTypes.${t}`)}
        </option>
      ))}
    </select>
  );
}

function rid() {
  return Math.random().toString(36).slice(2, 10);
}
