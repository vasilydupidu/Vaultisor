import { invoke as tauriInvoke } from "@tauri-apps/api/core";

let onLockCallback: (() => void) | null = null;

export function registerOnLockCallback(cb: () => void) {
  onLockCallback = cb;
}

function invoke<T>(cmd: string, args?: any): Promise<T> {
  return tauriInvoke<T>(cmd, args).catch((err) => {
    if (typeof err === "string" && err.includes("Хранилище заблокировано")) {
      console.warn("[API] Detected Locked state from backend, locking frontend.");
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
  vbs_enclave_available: boolean;
  tpm_available: boolean;
  windows_version: string;
}

export interface SettingsDto {
  autolock_seconds: number;
  clipboard_clear_seconds: number;
  require_auth_for_copy: boolean;
  use_windows_hello: boolean;
  max_pin_attempts: number;
}

export interface VaultCreateInput {
  pin: string;
  use_dpapi: boolean;
  use_windows_hello: boolean;
  autolock_seconds?: number;
  clipboard_clear_seconds?: number;
}

export interface VaultCreateOutput {
  recovery_share_b_hex: string;
  recovery_share_c_hex: string;
}

// === System ===
export const apiSystemCheck = () => invoke<SystemCheck>("system_check");
export const apiVaultExists = () => invoke<boolean>("vault_exists");
export const apiIdleSeconds = () => invoke<number>("idle_seconds");
/** Heartbeat сессии: active=была ли активность в окне с прошлого вызова.
 *  Возвращает, разблокирована ли ещё сессия (false → надо уйти на lock). */
export const apiSessionHeartbeat = (active: boolean) =>
  invoke<boolean>("session_heartbeat", { active });

// === Vault lifecycle ===
export const apiVaultCreate = (input: VaultCreateInput) =>
  invoke<VaultCreateOutput>("vault_create", { input });
export const apiVaultUnlock = (pin: string) =>
  invoke<void>("vault_unlock", { input: { pin } });
export const apiVaultUnlockWithHello = () =>
  invoke<void>("vault_unlock_with_hello");
export const apiVaultUnlockWithFido2 = () =>
  invoke<void>("vault_unlock_with_fido2");
export const apiVaultLock = () => invoke<void>("vault_lock");
export const apiVaultChangePin = (oldPin: string, newPin: string) =>
  invoke<void>("vault_change_pin", { input: { old_pin: oldPin, new_pin: newPin } });

export interface LockInfo {
  use_windows_hello: boolean;
  hello_blob_present: boolean;
  fido2_enabled: boolean;
}
export const apiVaultLockInfo = () => invoke<LockInfo>("vault_lock_info");

// === Импорт / восстановление ===
// Импорт на чистую установку (онбординг). Восстановление ПОВЕРХ существующего
// vault (из Настроек) — заменяет текущие данные, требует повторного входа.
export const apiVaultImport = (sourcePath: string) =>
  invoke<void>("vault_import", { input: { source_path: sourcePath } });
export const apiVaultRestore = (sourcePath: string) =>
  invoke<void>("vault_restore", { input: { source_path: sourcePath } });

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
/** R-03: сохранить пользовательский порядок записей (в зашифрованном vault). */
export const apiRecordReorder = (dbType: "records" | "web", orderedIds: string[]) =>
  invoke<void>("record_reorder", { input: { ordered_ids: orderedIds, db_type: dbType } });
export const apiRecordGet = (dbType: "records" | "web", id: string) =>
  invoke<RecordModel>("record_get", { input: { id, db_type: dbType } });
export const apiRecordCreate = (dbType: "records" | "web", data: RecordInput) =>
  invoke<string>("record_create", { input: { data, db_type: dbType } });
export const apiRecordUpdate = (dbType: "records" | "web", id: string, data: RecordInput) =>
  invoke<void>("record_update", { input: { id, data, db_type: dbType } });
export const apiRecordDelete = (dbType: "records" | "web", id: string) =>
  invoke<void>("record_delete", { input: { id, db_type: dbType } });
export const apiRecordReveal = (dbType: "records" | "web", recordId: string, fieldId: string) =>
  invoke<string>("record_reveal_field", {
    input: { record_id: recordId, field_id: fieldId, db_type: dbType },
  });

// === Clipboard ===
export const apiClipboardCopy = (
  dbType: "records" | "web",
  recordId: string,
  fieldId: string,
  clearAfterSeconds?: number,
) =>
  invoke<void>("clipboard_copy_secret", {
    input: {
      record_id: recordId,
      field_id: fieldId,
      clear_after_seconds: clearAfterSeconds ?? null,
      db_type: dbType,
    },
  });
export const apiClipboardClear = () => invoke<void>("clipboard_clear");
/** AUDIT M9: копирование Shamir-доли с авто-очисткой буфера (по умолчанию 30с). */
export const apiClipboardCopyText = (text: string, clearAfterSeconds = 30) =>
  invoke<void>("clipboard_copy_text", {
    input: { text, clear_after_seconds: clearAfterSeconds },
  });

// === Recovery ===
export const apiRecoverySaveToUsb = (shareBHex: string, usbPath: string) =>
  invoke<void>("recovery_save_to_usb", {
    input: { share_b_hex: shareBHex, usb_path: usbPath },
  });
export const apiRecoveryLoadFromUsb = (usbPath: string) =>
  invoke<{ share_hex: string }>("recovery_load_from_usb", {
    input: { usb_path: usbPath },
  });
export const apiRecoveryRestore = (sharesHex: string[], newPin: string) =>
  invoke<{ recovered: boolean }>("recovery_restore", {
    input: { shares_hex: sharesHex, new_pin: newPin },
  });

export interface RecoveryStatus {
  configured: boolean;
}
export const apiRecoveryStatus = () => invoke<RecoveryStatus>("recovery_status");
export const apiRecoveryRegenerate = () =>
  invoke<{ recovery_share_b_hex: string; recovery_share_c_hex: string }>(
    "recovery_regenerate",
  );
export const apiRecoveryDisable = () => invoke<void>("recovery_disable");

// === Settings ===
export const apiSettingsGet = () => invoke<SettingsDto>("settings_get");
export const apiSettingsUpdate = (s: SettingsDto) =>
  invoke<void>("settings_update", { input: s });

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
export const apiBackupSetConfig = (dir: string | null, frequency: string) =>
  invoke<void>("backup_set_config", { input: { dir, frequency } });
export const apiBackupNow = (dir: string) =>
  invoke<{ path: string }>("backup_now", { dir });

// === Массовые операции над записями ===
export const apiRecordsBatchDelete = (
  dbType: "records" | "web",
  recordIds: string[],
) =>
  invoke<number>("records_batch_delete", {
    input: { db_type: dbType, record_ids: recordIds },
  });

// === Импорт из браузера и безопасное удаление ===
export const apiImportChromiumCsv = (filePath: string) =>
  invoke<{ count: number; imported_ids: string[] }>("import_chromium_csv", {
    filePath,
  });
export const apiSecureDeleteFile = (filePath: string) =>
  invoke<void>("secure_delete_file", { filePath });

// === История изменений паролей ===
export interface PasswordHistoryEntry {
  id: string;
  record_id: string;
  field_id: string;
  field_label: string;
  value: string;
  created_at: string;
}

export const apiGetPasswordHistory = (dbType: "records" | "web", recordId: string) =>
  invoke<PasswordHistoryEntry[]>("record_get_password_history", {
    input: { record_id: recordId, db_type: dbType },
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
export const apiRegisterFido2Key = (name?: string, requirePin?: boolean) =>
  invoke<Fido2KeyItem>("register_fido2_key", { name, require_pin: requirePin ?? true });
export const apiUnbindFido2Key = (id?: string) => invoke<void>("unbind_fido2_key", { id });
