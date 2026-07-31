// @vitest-environment jsdom
import { describe, it, expect } from "vitest";
import { generateSecret } from "./generateSecret";

describe("generateSecret", () => {
  it("возвращает значение точной длины", () => {
    for (const len of [8, 32, 64, 128]) {
      expect(generateSecret(len, "alnum").length).toBe(len);
    }
  });

  it("уважает алфавит charset", () => {
    expect(/^[0-9a-f]+$/.test(generateSecret(64, "hex"))).toBe(true);
    expect(/^[A-Za-z0-9]+$/.test(generateSecret(64, "alnum"))).toBe(true);
    expect(/^[A-Za-z0-9\-_]+$/.test(generateSecret(64, "base64url"))).toBe(true);
  });

  it("два вызова дают разные значения (не константа)", () => {
    expect(generateSecret(32, "alnumSymbols")).not.toBe(
      generateSecret(32, "alnumSymbols"),
    );
  });

  it("покрывает весь алфавит без грубых пропусков (rejection sampling работает)", () => {
    // на большой выборке hex должны встретиться все 16 символов
    const s = generateSecret(4000, "hex");
    const seen = new Set(s.split(""));
    expect(seen.size).toBe(16);
  });
});
