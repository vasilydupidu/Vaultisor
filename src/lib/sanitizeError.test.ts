import { describe, it, expect, vi } from "vitest";

vi.mock("@/lib/i18n", () => ({
  default: { t: (key: string) => key, language: "ru" },
}));

import { sanitizeError } from "./sanitizeError";

describe("sanitizeError", () => {
  it("снимает машинный префикс кода", () => {
    expect(sanitizeError("DEVICE_MISMATCH: Хранилище создано на другом устройстве")).toBe(
      "Хранилище создано на другом устройстве",
    );
    expect(sanitizeError("LOCKED: Хранилище заблокировано")).toBe("Хранилище заблокировано");
    expect(sanitizeError("PIN_BACKOFF: Повторите через 30 с.")).toBe("Повторите через 30 с.");
  });

  it("снимает код вместе со вторым служебным сегментом", () => {
    expect(sanitizeError("AUTH_REQUIRED:change_pin: Подтвердите PIN для этого действия")).toBe(
      "Подтвердите PIN для этого действия",
    );
    const snapshot = "0123456789abcdef0123456789abcdef";
    expect(sanitizeError(`DATA_ROLLBACK:${snapshot}: Базы старее подтверждённых`)).toBe(
      "Базы старее подтверждённых",
    );
    expect(sanitizeError(new Error(`DATA_ROLLBACK:${snapshot}: Откат`))).toBe("Откат");
  });

  it("не отрезает второй сегмент у остальных кодов", () => {
    expect(sanitizeError("LOCKED: проверьте: ввод")).toBe("проверьте: ввод");
    expect(sanitizeError("AUTH_REQUIRED:change_pin:")).toBe("sanitizeError.defaultMessage");
  });

  it("оставляет сообщение без префикса как есть", () => {
    expect(sanitizeError("Запись не найдена")).toBe("Запись не найдена");
  });

  it("не считает префиксом обычный текст с двоеточием", () => {
    expect(sanitizeError("Внимание: проверьте ввод")).toBe("Внимание: проверьте ввод");
  });

  it("разбирает Error и неизвестные типы", () => {
    expect(sanitizeError(new Error("SYSTEM_ERROR: Системная ошибка"))).toBe("Системная ошибка");
    expect(sanitizeError({ weird: true }, "fallback")).toBe("fallback");
    expect(sanitizeError(null, "fallback")).toBe("fallback");
    expect(sanitizeError(undefined, "fallback")).toBe("fallback");
  });

  it("использует fallback для пустого сообщения", () => {
    expect(sanitizeError("", "fallback")).toBe("fallback");
    expect(sanitizeError("   ", "fallback")).toBe("fallback");
    expect(sanitizeError("LOCKED:", "fallback")).toBe("fallback");
  });

  it("без явного fallback берёт ключ перевода по умолчанию", () => {
    expect(sanitizeError({})).toBe("sanitizeError.defaultMessage");
  });
});
