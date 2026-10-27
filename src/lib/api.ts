import { invoke as tauriInvoke } from "@tauri-apps/api/core";

let onLockCallback: (() => void) | null = null;

export function registerOnLockCallback(cb: (() => void) | null) {
  onLockCallback = cb;
}

/**
 * Состояние «сессия заблокирована» определяется по машинному коду
 * LOCKED, а не по подстроке русского сообщения — иначе любая правка текста
 * ошибки тихо ломала авто-возврат на экран блокировки.
 */
function isLockedError(err: unknown): boolean {
  const raw = typeof err === "string" ? err : err instanceof Error ? err.message : "";
  return raw.startsWith("LOCKED:") || raw.includes("LOCKED:");
}

function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  return tauriInvoke<T>(cmd, args).catch((err) => {
    if (isLockedError(err)) {
      if (onLockCallback) {
        onLockCallback();
      }
    }
    throw err;
  });
}

export type FieldType = "secret" | "api" | "key" | "id" | "comment" | "custom";

export interface FieldMeta {
  id: string;
  field_type: FieldType;
  label: string;
  is_secret: boolean;
  sort_order: number;
  value_preview: string;
  created_at: string;
  updated_at: string;
}

export interface RecordModel {
  id: string;
  name: string;
  project: string | null;
  icon: string | null;
  color: string | null;
  category: "personal" | "work";
  created_at: string;
  updated_at: string;
  has_weak?: boolean;
  has_reused?: boolean;
  fields: FieldMeta[];
}

export interface FieldInput {
  id?: string;
  field_type: FieldType;
  label: string;
  is_secret: boolean;
  sort_order: number;
  value: string | null;
}

export interface RecordInput {
  name: string;
  project?: string | null;
  icon?: string | null;
  color?: string | null;
  category?: "personal" | "work";
  fields: FieldInput[];
}

export interface SystemCheck {
  dpapi_available: boolean;
  windows_hello_available: boolean;
  tpm_available: boolean;
  windows_version: string;
}

export interface SettingsDto {
  autolock_seconds: number;
  clipboard_clear_seconds: number;
  require_auth_for_copy: boolean;
  use_windows_hello: boolean;
}

/** Настройки удобства: меняются в открытой сессии без подтверждения. */
export interface ConvenienceSettings {
  autolock_seconds: number;
  clipboard_clear_seconds: number;
}

/**
 * Действия, которые backend выполняет только по свежему подтверждению PIN
 * (`security_authorize`). Использовать через `useSecurityConfirm`.
 */
export type SecurityAction =
  | "change_pin"
  | "enable_hello"
  | "disable_hello"
  | "enable_step_up"
  | "disable_step_up"
  | "bind_fido"
  | "unbind_fido"
  | "regenerate_recovery"
  | "disable_recovery"
  | "restore_backup"
  | "change_backup_directory"
  | "weaken_settings";

export const apiSecurityAuthorize = (action: SecurityAction, pin: string) =>
  invoke<void>("security_authorize", { input: { action, pin } });
export const apiSecuritySetHello = (enabled: boolean) =>
  invoke<void>("security_set_hello", { enabled });
export const apiSecuritySetStepUp = (enabled: boolean) =>
  invoke<void>("security_set_step_up", { enabled });

export interface VaultCreateInput {
  pin: string;
  use_windows_hello: boolean;
  autolock_seconds?: number;
  clipboard_clear_seconds?: number;
}

export interface VaultCreateOutput {
  /** Поколение восстановления: подтверждается `apiRecoveryAcknowledge`. */
  recovery_generation: number;
  recovery_share_b_hex: string;
  recovery_share_c_hex: string;
}

// === System ===
export const apiSystemCheck = () => invoke<SystemCheck>("system_check");
/** Открывает системный мастер Windows для настройки ключа безопасности.
 *  Аргументов нет: URI зашит в backend, webview не выбирает, что открыть. */
export const apiOpenSecurityKeySettings = () =>
  invoke<void>("open_security_key_settings");

// === Генератор секретов ===
/** Типы, которые умеет генератор. Совпадают с backend `GeneratedKind`. */
export type GeneratedKind = "password" | "alnum" | "hex" | "base64url";

export interface GeneratedSecretMeta {
  id: string;
  kind: GeneratedKind;
  length: number;
  created_at: string;
}

export interface GeneratorLimits {
  password_min_len: number;
  max_len: number;
  retention_hours: number;
}

export const apiGeneratorLimits = () => invoke<GeneratorLimits>("generator_limits");
/** Список выдач без значений. Просроченные удаляются backend'ом при вызове. */
export const apiGeneratorList = () => invoke<GeneratedSecretMeta[]>("generator_list");
export const apiGeneratorCreate = (kind: GeneratedKind, value: string) =>
  invoke<GeneratedSecretMeta>("generator_create", { input: { kind, value } });
export const apiGeneratorDelete = (ids: string[]) =>
  invoke<number>("generator_delete", { input: { ids } });
/** Копирование делает backend: значение не покидает его и идёт в буфер тем же
 *  защищённым путём, что и секреты записей. */
export const apiGeneratorCopy = (id: string) => invoke<void>("generator_copy", { id });

export const apiGetEnableGenerator = () => invoke<boolean>("get_enable_generator");
export const apiSetEnableGenerator = (enabled: boolean) =>
  invoke<void>("set_enable_generator", { enabled });
export const apiVaultExists = () => invoke<boolean>("vault_exists");
/** Heartbeat сессии: active=была ли активность в окне с прошлого вызова.
 *  Возвращает, разблокирована ли ещё сессия (false → надо уйти на lock). */
export const apiSessionHeartbeat = (active: boolean) =>
  invoke<boolean>("session_heartbeat", { active });

// === Vault lifecycle ===
export const apiVaultCreate = (input: VaultCreateInput) =>
  invoke<VaultCreateOutput>("vault_create", { input });
export const apiVaultUnlock = (pin: string) =>
  invoke<void>("vault_unlock", { input: { pin } });
/** Вход после DATA_ROLLBACK: владелец явно продолжает с показанным ему
 *  снимком баз (`snapshot` — идентификатор из ошибки). Если файлы успели
 *  подменить другими, backend снова вернёт DATA_ROLLBACK. */
export const apiVaultUnlockAcceptRollback = (pin: string, snapshot: string) =>
  invoke<void>("vault_unlock_accept_rollback", { input: { pin, snapshot } });

/** Идентификатор снимка из ошибки DATA_ROLLBACK. */
export function rollbackSnapshot(error: unknown): string | null {
  const raw = typeof error === "string" ? error : error instanceof Error ? error.message : "";
  return /DATA_ROLLBACK:([0-9a-f]{32}):/.exec(raw)?.[1] ?? null;
}
export const apiVaultUnlockWithFido2 = () =>
  invoke<void>("vault_unlock_with_fido2");
export const apiVaultLock = () => invoke<void>("vault_lock");
/** Текущий PIN подтверждается отдельно (`change_pin`), здесь — только новый. */
export const apiVaultChangePin = (newPin: string, requestId: string) =>
  invoke<void>("vault_change_pin", { input: { new_pin: newPin, request_id: requestId } });

/** Hello — второй фактор поверх PIN; FIDO2 — самостоятельный путь входа без PIN. */
export interface LockInfo {
  use_windows_hello: boolean;
  fido2_enabled: boolean;
}
export const apiVaultLockInfo = () => invoke<LockInfo>("vault_lock_info");

// === Импорт / восстановление ===
// Импорт резервной копии на чистую установку (онбординг). Восстановление
// ПОВЕРХ существующего vault (из Настроек) заменяет записи и требует
// повторного входа.
export const apiPrepareFile = (operation: "import" | "restore" | "backup_directory" | "csv_import" | "recovery_read") =>
  invoke<string>("file_prepare", { operation });
export const apiVaultImport = async () => {
  const capability = await apiPrepareFile("import");
  return invoke<void>("vault_import", { input: { capability } });
};
/** Полномочие на файл берётся заранее: повтор после подтверждения PIN не
 *  открывает диалог выбора файла второй раз. */
export const apiVaultRestore = (capability: string) =>
  invoke<void>("vault_restore", { input: { capability } });

// === Records ===
export interface RecordListOpts {
  query?: string;
  category?: "all" | "work" | "personal";
  limit?: number;
  offset?: number;
}
export const apiRecordList = (dbType: "records" | "web", opts?: RecordListOpts) =>
  invoke<RecordModel[]>("record_list", {
    input: {
      query: opts?.query ?? null,
      category: opts?.category && opts.category !== "all" ? opts.category : null,
      limit: opts?.limit ?? null,
      offset: opts?.offset ?? null,
      db_type: dbType,
    },
  });
/** Сохранить пользовательский порядок записей (в зашифрованном vault). */
export const apiRecordReorder = (dbType: "records" | "web", orderedIds: string[]) =>
  invoke<void>("record_reorder", { input: { ordered_ids: orderedIds, db_type: dbType } });
export const apiRecordGet = (dbType: "records" | "web", id: string) =>
  invoke<RecordModel>("record_get", { input: { id, db_type: dbType } });
/** `requestId` — см. `RetryableRequest`: повтор не создаёт дубликат. */
export const apiRecordCreate = (dbType: "records" | "web", data: RecordInput, requestId: string) =>
  invoke<string>("record_create", { input: { data, db_type: dbType, request_id: requestId } });
export const apiRecordUpdate = (dbType: "records" | "web", id: string, data: RecordInput) =>
  invoke<void>("record_update", { input: { id, data, db_type: dbType } });
export const apiRecordDelete = (dbType: "records" | "web", id: string) =>
  invoke<void>("record_delete", { input: { id, db_type: dbType } });
export const apiRecordReveal = (dbType: "records" | "web", recordId: string, fieldId: string) =>
  invoke<string>("record_reveal_field", {
    input: { record_id: recordId, field_id: fieldId, db_type: dbType },
  });

// === Clipboard ===
/** Срок автоочистки берёт backend из сохранённых настроек. */
export const apiClipboardCopy = (
  dbType: "records" | "web",
  recordId: string,
  fieldId: string,
) =>
  invoke<void>("clipboard_copy_secret", {
    input: {
      record_id: recordId,
      field_id: fieldId,
      db_type: dbType,
    },
  });
/** Ручная очистка буфера обмена из настроек. */
export const apiClipboardClear = () => invoke<void>("clipboard_clear");
/** Копирование Shamir-доли с авто-очисткой буфера (по умолчанию 30с). */
export const apiClipboardCopyText = (text: string, clearAfterSeconds = 30) =>
  invoke<void>("clipboard_copy_text", {
    input: { text, clear_after_seconds: clearAfterSeconds },
  });

// === Recovery ===
export const apiRecoveryPrepareSave = (shareHex: string, part: "B" | "C") =>
  invoke<string>("recovery_prepare_save", { input: { share_hex: shareHex, part } });
export const apiRecoveryCommitSave = (capability: string) =>
  invoke<void>("recovery_save_to_usb", { capability });
export const apiRecoveryLoadFromUsb = async () => {
  const capability = await apiPrepareFile("recovery_read");
  return invoke<{ share_hex: string }>("recovery_load_from_usb", {
    input: { capability },
  });
};
export const apiRecoveryRestore = (sharesHex: string[], newPin: string) =>
  invoke<{ recovered: boolean }>("recovery_restore", {
    input: { shares_hex: sharesHex, new_pin: newPin },
  });

/**
 * disabled — восстановления нет; pending — доли выданы, но их сохранение не
 * подтверждено (или они израсходованы): нужен новый комплект; active —
 * пользователь подтвердил, что сохранил обе доли.
 */
export type RecoveryState = "disabled" | "pending" | "active";
export interface RecoveryStatus {
  state: RecoveryState;
  generation: number;
}
export const apiRecoveryStatus = () => invoke<RecoveryStatus>("recovery_status");
export interface RecoveryShares {
  generation: number;
  recovery_share_b_hex: string;
  recovery_share_c_hex: string;
}
export const apiRecoveryRegenerate = () => invoke<RecoveryShares>("recovery_regenerate");
/** Пользователь сохранил обе доли этого поколения. */
export const apiRecoveryAcknowledge = (generation: number) =>
  invoke<void>("recovery_acknowledge", { input: { generation } });
export const apiRecoveryDisable = () => invoke<void>("recovery_disable");

// === Settings ===
export const apiSettingsGet = () => invoke<SettingsDto>("settings_get");
export const apiSettingsUpdate = (s: ConvenienceSettings) =>
  invoke<void>("settings_update", {
    input: { autolock_seconds: s.autolock_seconds, clipboard_clear_seconds: s.clipboard_clear_seconds },
  });

export async function getUiLanguage(): Promise<string> {
  return invoke<string>('get_ui_language');
}

export async function setUiLanguage(lang: string): Promise<void> {
  return invoke('set_ui_language', { lang });
}

// === Резервные копии (папка + расписание + ретеншн) ===
export interface BackupConfig {
  dir: string | null;
  frequency: "off" | "daily" | "weekly";
  last_backup: string | null;
}
export const apiBackupGetConfig = () => invoke<BackupConfig>("backup_get_config");
export const apiBackupSetConfig = (directoryCapability: string | null, frequency: string) =>
  invoke<void>("backup_set_config", { input: { directory_capability: directoryCapability, frequency } });
export const apiBackupNow = (requestId: string) =>
  invoke<{ path: string }>("backup_now", { requestId });

// === Массовые операции над записями ===
export const apiRecordsBatchDelete = (
  dbType: "records" | "web",
  recordIds: string[],
) =>
  invoke<number>("records_batch_delete", {
    input: { db_type: dbType, record_ids: recordIds },
  });

// === Импорт из браузера и безопасное удаление ===
/** Строка CSV, которую не удалось перенести, и причина. */
export interface RejectedCsvRow {
  row: number;
  site: string;
  reason: string;
}

/** Итог импорта: `imported` + число отклонённых = `total`. */
export interface CsvImportResult {
  total: number;
  imported: number;
  rejected: RejectedCsvRow[];
  imported_ids: string[];
  /** Выдаётся только при полном импорте: из неполностью перенесённого файла
   *  исходник уничтожать нельзя — это единственная копия непереносённых паролей. */
  deletion_token: string | null;
}

export const apiImportChromiumCsv = async () => {
  const capability = await apiPrepareFile("csv_import");
  return invoke<CsvImportResult>("import_chromium_csv", { capability });
};
export const apiSecureDeleteFile = (deletionToken: string) =>
  invoke<void>("secure_delete_file", { deletionToken });

// === История изменений паролей ===
/**
 * Запись истории больше НЕ содержит открытого пароля. Значение
 * не покидает backend; копирование и восстановление выполняются отдельными
 * командами по идентификатору записи истории.
 */
export interface PasswordHistoryEntry {
  id: string;
  record_id: string;
  field_id: string;
  field_label: string;
  created_at: string;
}

export const apiGetPasswordHistory = (dbType: "records" | "web", recordId: string) =>
  invoke<PasswordHistoryEntry[]>("record_get_password_history", {
    input: { record_id: recordId, db_type: dbType },
  });

export const apiCopyPasswordHistory = (
  dbType: "records" | "web",
  recordId: string,
  historyId: string,
) =>
  invoke<void>("record_copy_password_history", {
    input: { record_id: recordId, history_id: historyId, db_type: dbType },
  });

export const apiRestorePasswordHistory = (
  dbType: "records" | "web",
  recordId: string,
  historyId: string,
) =>
  invoke<void>("record_restore_password_history", {
    input: { record_id: recordId, history_id: historyId, db_type: dbType },
  });

export const apiClearPasswordHistory = (dbType: "records" | "web", recordId: string) =>
  invoke<void>("record_clear_password_history", {
    input: { record_id: recordId, db_type: dbType },
  });

// === Анализатор безопасности баз (Vault Health Check) ===
export const apiGetEnableHealthCheck = () => invoke<boolean>("get_enable_health_check");
export const apiSetEnableHealthCheck = (enabled: boolean) =>
  invoke<void>("set_enable_health_check", { enabled });

export const apiGetEnablePasswordHistory = () => invoke<boolean>("get_enable_password_history");
export const apiSetEnablePasswordHistory = (enabled: boolean) =>
  invoke<void>("set_enable_password_history", { enabled });

// === Аппаратный FIDO2-ключ ===
export interface Fido2KeyItem {
  id: string;
  name: string;
  created_at: string;
  credential_id_preview: string;
  /** Название модели ключа (Рутокен MFA, YubiKey 5 NFC, FIDO2 Security Key) */
  model_name: string;
  /** true = ПИН+Touch, false = Touch-only */
  require_pin: boolean;
}

export interface Fido2Status {
  enabled: boolean;
  available: boolean;
  keys: Fido2KeyItem[];
}

export const apiGetFido2Status = () => invoke<Fido2Status>("get_fido2_status");
/**
 * Аргументы команд Tauri сериализуются в camelCase, если у
 * команды не задан rename_all. Раньше здесь отправлялся `require_pin`, поэтому
 * backend его не видел и всегда применял `unwrap_or(true)` — режим Touch-only
 * молча не работал.
 */
export const apiRegisterFido2Key = (requestId: string, name?: string, requirePin?: boolean) =>
  invoke<Fido2KeyItem>("register_fido2_key", {
    name,
    requirePin: requirePin ?? true,
    requestId,
  });
/** Отвязать один ключ по id. */
export const apiUnbindFido2Key = (id: string) => invoke<void>("unbind_fido2_key", { id });
