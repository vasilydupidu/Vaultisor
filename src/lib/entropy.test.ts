// @vitest-environment node
import { describe, it, expect } from "vitest";

import { ALPHABET_SIZE, entropyBits } from "./entropy";

describe("оценка энтропии", () => {
  /** Точные величины, которые легко проверить руками: 4 бита на hex-символ и
   *  6 на base64url. Если размер алфавита разойдётся с генератором, тест упадёт. */
  it("считает биты по размеру алфавита", () => {
    expect(entropyBits("hex", 32)).toBe(128);
    expect(entropyBits("base64url", 32)).toBe(192);
    expect(entropyBits("password", 20)).toBe(129);
    expect(entropyBits("alnum", 22)).toBe(130);
  });

  /** Округление вниз: показанная оценка не должна быть выше настоящей. */
  it("никогда не завышает оценку", () => {
    for (const kind of ["password", "alnum", "hex", "base64url"] as const) {
      for (let len = 1; len <= 64; len++) {
        const exact = Math.log2(ALPHABET_SIZE[kind]) * len;
        expect(entropyBits(kind, len)).toBeLessThanOrEqual(exact);
      }
    }
  });

  it("нулевая и отрицательная длина дают ноль", () => {
    expect(entropyBits("password", 0)).toBe(0);
    expect(entropyBits("password", -5)).toBe(0);
  });

  /** Минимум пароля в 15 символов держится именно на этом числе: ниже 89 бит
   *  опускаться не хотим, и тест фиксирует, что граница не съедет молча.
   *  Набор без спецсимволов слабее на символ — проверяем и его. */
  it("минимальный пароль даёт не меньше 89 бит в обоих наборах", () => {
    expect(entropyBits("password", 15)).toBeGreaterThanOrEqual(89);
    expect(entropyBits("alnum", 15)).toBeGreaterThanOrEqual(89);
  });

  /** Цена отказа от спецсимволов должна оставаться скромной, иначе галочка
   *  «только буквы и цифры» превратилась бы в ловушку. */
  it("отказ от спецсимволов стоит меньше 10% энтропии", () => {
    const full = entropyBits("password", 30);
    const plain = entropyBits("alnum", 30);
    expect(plain / full).toBeGreaterThan(0.9);
  });
});
