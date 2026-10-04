import { describe, it, expect } from "vitest";
import { fieldSaveValue } from "./recordDraft";

describe("fieldSaveValue (H-01/M-05 контракт)", () => {
  it("неподгруженное существующее поле → null (не менять)", () => {
    // value="" original=undefined (пользователь не открывал поле)
    expect(fieldSaveValue({ id: "f1", value: "", original: undefined })).toBeNull();
  });

  it("подгруженное, но неизменённое → null", () => {
    expect(fieldSaveValue({ id: "f1", value: "secret", original: "secret" })).toBeNull();
  });

  it("изменённое существующее → строка", () => {
    expect(fieldSaveValue({ id: "f1", value: "new", original: "secret" })).toBe("new");
  });

  it("новое поле (без id) → строка всегда", () => {
    expect(fieldSaveValue({ value: "created", original: undefined })).toBe("created");
    expect(fieldSaveValue({ value: "", original: undefined })).toBe("");
  });

  it("очистка существующего поля в пусто → отправляет пустую строку", () => {
    // пользователь открыл (original) и стёр — это осознанное изменение
    expect(fieldSaveValue({ id: "f1", value: "", original: "secret" })).toBe("");
  });
});
