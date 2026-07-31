import { describe, it, expect } from "vitest";
import { isRepeatDigits, isSequence, validatePinLocal } from "./pinRules";

describe("isRepeatDigits", () => {
  it("детектит одинаковые цифры", () => {
    expect(isRepeatDigits("00000000")).toBe(true);
    expect(isRepeatDigits("9999999999")).toBe(true);
  });
  it("не срабатывает на разных", () => {
    expect(isRepeatDigits("19472856")).toBe(false);
    expect(isRepeatDigits("abcd")).toBe(false);
  });
});

describe("isSequence", () => {
  it("детектит возрастающие/убывающие", () => {
    expect(isSequence("12345678")).toBe(true);
    expect(isSequence("87654321")).toBe(true);
  });
  it("не срабатывает на обычных", () => {
    expect(isSequence("19472856")).toBe(false);
  });
});

describe("validatePinLocal digit", () => {
  it("принимает нормальный цифровой PIN", () => {
    expect(validatePinLocal("19472856", "digit")).toBeNull();
  });
  it("отвергает короткий / длинный / тривиальный", () => {
    expect(validatePinLocal("1234567", "digit")).not.toBeNull();
    expect(validatePinLocal("1234567890123", "digit")).not.toBeNull();
    expect(validatePinLocal("00000000", "digit")).not.toBeNull();
    expect(validatePinLocal("12345678", "digit")).not.toBeNull();
  });
});

describe("validatePinLocal alnum (L-05)", () => {
  it("принимает буквенно-цифровой ≥8 (латиница и кириллица)", () => {
    expect(validatePinLocal("abcd1234", "alnum")).toBeNull();
    expect(validatePinLocal("Str0ngPass99", "alnum")).toBeNull();
    expect(validatePinLocal("пароль12", "alnum")).toBeNull();
  });
  it("отвергает короткий и символы", () => {
    expect(validatePinLocal("abc123", "alnum")).not.toBeNull();
    expect(validatePinLocal("abcd!@#$", "alnum")).not.toBeNull();
    expect(validatePinLocal("pass word", "alnum")).not.toBeNull();
  });
});

describe("validatePinLocal passphrase", () => {
  it("требует ≥15 символов", () => {
    expect(validatePinLocal("short", "passphrase")).not.toBeNull();
    expect(validatePinLocal("a-long-enough-passphrase", "passphrase")).toBeNull();
  });
});
