import { describe, it, expect } from "vitest";
import i18n from "@/lib/i18n";
import {
  isRepeatDigits,
  isSequence,
  secretMode,
  validatePinLocal,
  weakSecretError,
} from "./pinRules";

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

describe("validatePinLocal alnum", () => {
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

describe("weakSecretError", () => {
  it("отвергает пустой по сути секрет", () => {
    expect(weakSecretError(" ".repeat(15))).toBe(i18n.t("pinRules.secretBlank"));
    expect(weakSecretError("\t \n  ")).toBe(i18n.t("pinRules.secretBlank"));
  });
  it("отвергает один повторяющийся символ", () => {
    expect(weakSecretError("a".repeat(20))).toBe(i18n.t("pinRules.secretSingleChar"));
    expect(weakSecretError("7".repeat(11))).toBe(i18n.t("pinRules.secretSingleChar"));
  });
  it("отвергает меньше 6 различных символов", () => {
    expect(weakSecretError("abababababababab")).toBe(i18n.t("pinRules.secretFewDistinct", { min: 6 }));
    expect(weakSecretError("abcdeabcdeabcdeabcde")).not.toBeNull(); // 5 различных
    expect(weakSecretError("abcdefabcdefabcdef")).toBeNull(); // ровно 6
  });
  it("считает символы Unicode, а не UTF-16 единицы", () => {
    // Шесть различных эмодзи — по две UTF-16 единицы каждый.
    expect(weakSecretError("😀😁😂🤣😃😄")).toBeNull();
    expect(weakSecretError("😀😁😂🤣😃😀")).not.toBeNull(); // 5 различных
  });
});

describe("validatePinLocal: общие требования ко всем режимам", () => {
  it("passphrase: пробелы, один символ и бедный алфавит", () => {
    expect(validatePinLocal(" ".repeat(20), "passphrase")).not.toBeNull();
    expect(validatePinLocal("z".repeat(20), "passphrase")).not.toBeNull();
    expect(validatePinLocal("ababababababababab", "passphrase")).not.toBeNull();
    expect(validatePinLocal("пароль с пробелами и !", "passphrase")).toBeNull();
  });
  it("alnum: бедный алфавит", () => {
    expect(validatePinLocal("abababababab", "alnum")).not.toBeNull();
    expect(validatePinLocal("aaaaaaaaaaaa", "alnum")).not.toBeNull();
  });
  it("digit: чередование двух цифр и одинаковые цифры", () => {
    expect(validatePinLocal("12121212121", "digit")).not.toBeNull();
    expect(validatePinLocal("77777777777", "digit")).not.toBeNull();
    expect(validatePinLocal("19472856302", "digit")).toBeNull();
  });
});

describe("secretMode", () => {
  it("без TPM всегда мастер-пароль", () => {
    expect(secretMode("19472856302", false)).toBe("passphrase");
    expect(secretMode("short", false)).toBe("passphrase");
  });
  it("с TPM: цифры — PIN, длинное — парольная фраза, остальное — буквенно-цифровой PIN", () => {
    expect(secretMode("19472856302", true)).toBe("digit");
    expect(secretMode("abcd1234567", true)).toBe("alnum");
    expect(secretMode("a long phrase with spaces", true)).toBe("passphrase");
    expect(secretMode("", true)).toBe("alnum");
  });
});
