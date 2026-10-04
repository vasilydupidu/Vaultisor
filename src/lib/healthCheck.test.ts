import { describe, it, expect } from "vitest";
import { isPasswordWeak } from "./healthCheck";

describe("isPasswordWeak", () => {
  it("считает слабыми короткие значения", () => {
    expect(isPasswordWeak("abc")).toBe(true);
    expect(isPasswordWeak("1234567")).toBe(true);
    expect(isPasswordWeak("12345678")).toBe(true); // входит в список простых
  });

  it("считает сильными длинные нетривиальные значения", () => {
    expect(isPasswordWeak("kR7#vq2Lм9zT")).toBe(false);
    expect(isPasswordWeak("correct horse battery staple")).toBe(false);
  });

  /**
   * AUDIT 3.1.1: длина считается в символах. Кириллический пароль из 8 букв
   * занимает 16 байт, и побайтовая проверка ошибочно признавала его сильным.
   */
  it("считает символы, а не байты", () => {
    expect(isPasswordWeak("пароль")).toBe(true); // 6 символов
    expect(isPasswordWeak("паролище")).toBe(false); // 8 символов
  });

  it("ловит типовые слабые шаблоны любой длины", () => {
    expect(isPasswordWeak("my-password-2026")).toBe(true);
    expect(isPasswordWeak("qwertyuiop123")).toBe(true);
    expect(isPasswordWeak("admin-console-42")).toBe(true);
    expect(isPasswordWeak("prefix12345suffix")).toBe(true);
  });

  it("пустые значения не считаются слабыми паролями", () => {
    expect(isPasswordWeak("")).toBe(false);
    expect(isPasswordWeak("   ")).toBe(false);
    expect(isPasswordWeak(null)).toBe(false);
    expect(isPasswordWeak(undefined)).toBe(false);
  });
});
