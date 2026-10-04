import { describe, it, expect } from "vitest";
import { isRepeatDigits, isSequence, validatePinLocal } from "./pinRules";

describe("isRepeatDigits", () => {
  it("детектит одинаковые цифры", () => {
    expect(isRepeatDigits("00000000000")).toBe(true);
    expect(isRepeatDigits("99999999999")).toBe(true);
  });
  it("не срабатывает на разных", () => {
    expect(isRepeatDigits("19472856302")).toBe(false);
    expect(isRepeatDigits("abcd1234567")).toBe(false);
  });
});

describe("isSequence", () => {
  it("детектит возрастающие/убывающие", () => {
    expect(isSequence("12345678901")).toBe(true);
    expect(isSequence("98765432101")).toBe(true);
  });
  it("не срабатывает на обычных", () => {
    expect(isSequence("19472856302")).toBe(false);
  });
});

describe("validatePinLocal digit", () => {
  it("принимает нормальный цифровой PIN", () => {
    expect(validatePinLocal("19472856302", "digit")).toBeNull();
  });
  it("отвергает короткий / длинный / тривиальный", () => {
    expect(validatePinLocal("1234567890", "digit")).not.toBeNull(); // 10 < 11
    expect(validatePinLocal("12345678901234567", "digit")).not.toBeNull(); // 17 > 16
    expect(validatePinLocal("00000000000", "digit")).not.toBeNull();
    expect(validatePinLocal("12345678901", "digit")).not.toBeNull();
  });
});

describe("validatePinLocal alnum (L-05)", () => {
  it("принимает буквенно-цифровой ≥11 (латиница и кириллица)", () => {
    expect(validatePinLocal("abcd1234567", "alnum")).toBeNull();
    expect(validatePinLocal("Str0ngPass99", "alnum")).toBeNull();
    expect(validatePinLocal("пароль12345", "alnum")).toBeNull();
  });
  it("отвергает короткий и символы", () => {
    expect(validatePinLocal("abc1234567", "alnum")).not.toBeNull(); // 10 < 11
    expect(validatePinLocal("abcd!@#$123", "alnum")).not.toBeNull();
    expect(validatePinLocal("pass word123", "alnum")).not.toBeNull();
  });
});

describe("validatePinLocal passphrase", () => {
  it("требует ≥15 символов", () => {
    expect(validatePinLocal("short", "passphrase")).not.toBeNull();
    expect(validatePinLocal("a-long-enough-passphrase", "passphrase")).toBeNull();
  });
});
