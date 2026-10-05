import { describe, it, expect, vi, beforeEach } from "vitest";

const invokeMock = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invokeMock(...args),
}));

import {
  apiRegisterFido2Key,
  apiSecureDeleteFile,
  registerOnLockCallback,
  apiRecordList,
  apiRecoveryAcknowledge,
  apiSecurityAuthorize,
  apiSettingsUpdate,
  apiVaultUnlockAcceptRollback,
  rollbackSnapshot,
  apiVaultChangePin,
} from "./api";

describe("контракт аргументов IPC", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    invokeMock.mockResolvedValue(undefined);
  });

  /**
   * Регрессия: Tauri сериализует аргументы команд в
   * camelCase, если команда не объявила rename_all. Фронтенд слал require_pin,
   * backend его не видел и всегда применял unwrap_or(true) — режим Touch-only
   * молча не работал.
   */
  it("register_fido2_key получает requirePin в camelCase", async () => {
    await apiRegisterFido2Key("req-1", "YubiKey", false);
    expect(invokeMock).toHaveBeenCalledWith("register_fido2_key", {
      name: "YubiKey",
      requirePin: false,
      requestId: "req-1",
    });
  });

  it("register_fido2_key по умолчанию требует PIN", async () => {
    await apiRegisterFido2Key("req-2");
    expect(invokeMock).toHaveBeenCalledWith("register_fido2_key", {
      name: undefined,
      requirePin: true,
      requestId: "req-2",
    });
  });

  it("secure_delete_file использует camelCase", async () => {
    await apiSecureDeleteFile("token-1");
    expect(invokeMock).toHaveBeenCalledWith("secure_delete_file", {
      deletionToken: "token-1",
    });
  });

  it("record_list передаёт null вместо категории all", async () => {
    invokeMock.mockResolvedValue([]);
    await apiRecordList("web", { category: "all", query: "x" });
    expect(invokeMock).toHaveBeenCalledWith("record_list", {
      input: {
        query: "x",
        category: null,
        limit: null,
        offset: null,
        db_type: "web",
      },
    });
  });

  /**
   * Этап 2: backend принимает только новый PIN и настройки удобства; текущий
   * PIN подтверждается отдельной командой, а поля вида old_pin или
   * use_windows_hello в settings_update отвергаются deny_unknown_fields.
   */
  it("vault_change_pin передаёт новый PIN и идентификатор запроса", async () => {
    await apiVaultChangePin("58392071465", "req-3");
    expect(invokeMock).toHaveBeenCalledWith("vault_change_pin", {
      input: { new_pin: "58392071465", request_id: "req-3" },
    });
  });

  it("settings_update передаёт только настройки удобства", async () => {
    await apiSettingsUpdate({
      autolock_seconds: 300,
      clipboard_clear_seconds: 10,
      require_auth_for_copy: true,
      use_windows_hello: true,
    } as never);
    expect(invokeMock).toHaveBeenCalledWith("settings_update", {
      input: { autolock_seconds: 300, clipboard_clear_seconds: 10 },
    });
  });

  it("recovery_acknowledge подтверждает конкретное поколение", async () => {
    await apiRecoveryAcknowledge(3);
    expect(invokeMock).toHaveBeenCalledWith("recovery_acknowledge", {
      input: { generation: 3 },
    });
  });

  it("принятие отката — отдельная команда с PIN", async () => {
    await apiVaultUnlockAcceptRollback("19472856302", "ab".repeat(16));
    expect(invokeMock).toHaveBeenCalledWith("vault_unlock_accept_rollback", {
      input: { pin: "19472856302", snapshot: "ab".repeat(16) },
    });
  });

  it("идентификатор снимка извлекается только из DATA_ROLLBACK", () => {
    const id = "0123456789abcdef0123456789abcdef";
    expect(rollbackSnapshot(`DATA_ROLLBACK:${id}: Базы …`)).toBe(id);
    expect(rollbackSnapshot("META_TAMPERED: …")).toBeNull();
    expect(rollbackSnapshot("DATA_ROLLBACK:../x: …")).toBeNull();
  });

  it("security_authorize передаёт действие и PIN", async () => {
    await apiSecurityAuthorize("bind_fido", "19472856302");
    expect(invokeMock).toHaveBeenCalledWith("security_authorize", {
      input: { action: "bind_fido", pin: "19472856302" },
    });
  });
});

describe("детект заблокированной сессии", () => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it("вызывает onLock при коде LOCKED от backend и пробрасывает ошибку", async () => {
    const onLock = vi.fn();
    registerOnLockCallback(onLock);
    invokeMock.mockRejectedValue("LOCKED: Хранилище заблокировано");
    await expect(apiRecordList("records")).rejects.toBeTruthy();
    expect(onLock).toHaveBeenCalledTimes(1);
  });

  it("не вызывает onLock на прочих ошибках", async () => {
    const onLock = vi.fn();
    registerOnLockCallback(onLock);
    invokeMock.mockRejectedValue("Запись не найдена");
    await expect(apiRecordList("records")).rejects.toBeTruthy();
    expect(onLock).not.toHaveBeenCalled();
  });
});
