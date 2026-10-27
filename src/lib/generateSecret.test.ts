import { describe, it, expect } from "vitest";
import { MASTER_PASSPHRASE_ALPHABET, generateSecret, randomFromAlphabet } from "./generateSecret";

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

  /**
   * Равномерность распределения — то единственное, ради чего в генераторе
   * есть rejection sampling, и то единственное, что не видно ни по одному из
   * тестов выше: смещённый генератор пройдёт их все.
   *
   * Проверяем алфавиты, где смещение реально возникло бы. 256 кратно 16 и 64,
   * поэтому hex и base64url остались бы равномерными даже без отбраковки; а
   * 256 % 88 = 80 и 256 % 62 = 8 — здесь взятие остатка дало бы первым
   * символам алфавита в полтора раза больше шансов.
   */
  it.each([
    ["alnumSymbols", 88],
    ["alnum", 62],
  ] as const)("распределяет символы равномерно (%s)", (charset, alphabet) => {
    const perSymbol = 1000;
    const sample = generateSecret(alphabet * perSymbol, charset);

    const counts = new Map<string, number>();
    for (const ch of sample) counts.set(ch, (counts.get(ch) ?? 0) + 1);
    expect(counts.size).toBe(alphabet);

    // Хи-квадрат: сумма (наблюдалось - ожидалось)^2 / ожидалось.
    const expected = perSymbol;
    let chiSquare = 0;
    for (const observed of counts.values()) {
      chiSquare += (observed - expected) ** 2 / expected;
    }

    // Порог выбран с большим запасом над критическим значением для df≈87
    // (около 132 при p=0.001), чтобы тест не мигал на честной случайности.
    // Смещение от взятия остатка даёт значения на порядки больше.
    expect(chiSquare).toBeLessThan(alphabet * 2.5);
  });
});

describe("randomFromAlphabet", () => {
  // Длина алфавита не делит 256, поэтому простое `байт % N` завышало бы
  // вероятность первых (256 mod N) символов.
  const ALPHABET = MASTER_PASSPHRASE_ALPHABET;
  const N = ALPHABET.length;
  const ACCEPTED = Math.floor(256 / N) * N; // принимаются байты 0..ACCEPTED-1

  /** Детерминированный поток: подряд все значения байта 0..255, по кругу. */
  const sequentialFill = () => {
    let next = 0;
    return (buf: Uint8Array) => {
      for (let i = 0; i < buf.length; i++) buf[i] = next++ & 0xff;
    };
  };

  it("алфавит не делит 256 (иначе тест ничего не проверяет)", () => {
    expect(256 % N).not.toBe(0);
  });

  it("равномерен на полных проходах по значениям байта", () => {
    // За один проход по 0..255 принимается ровно ACCEPTED байт, то есть
    // каждый символ встречается floor(256 / N) раз; без отбраковки первые
    // (256 mod N) символов встречались бы на раз чаще.
    const perChar = Math.floor(256 / N);
    const passes = 5;
    const out = randomFromAlphabet(ALPHABET, ACCEPTED * passes, sequentialFill());
    const counts = new Map<string, number>();
    for (const ch of out) counts.set(ch, (counts.get(ch) ?? 0) + 1);
    expect(counts.size).toBe(N);
    for (const ch of ALPHABET) expect(counts.get(ch)).toBe(perChar * passes);
  });

  it("отбрасывает байты от наибольшего кратного длины алфавита и добирает новые", () => {
    // Сначала только отбракованные ACCEPTED..255, затем 0, 1, 2.
    const stream = [
      ...Array.from({ length: 256 - ACCEPTED }, (_, i) => ACCEPTED + i),
      0,
      1,
      2,
    ];
    let pos = 0;
    const fill = (buf: Uint8Array) => {
      for (let i = 0; i < buf.length; i++) buf[i] = stream[pos++ % stream.length]!;
    };
    expect(randomFromAlphabet(ALPHABET, 3, fill)).toBe(ALPHABET.slice(0, 3));
  });

  it("точная длина и только символы алфавита на настоящем CSPRNG", () => {
    const out = randomFromAlphabet(ALPHABET, 500);
    expect(out.length).toBe(500);
    for (const ch of out) expect(ALPHABET.includes(ch)).toBe(true);
  });
});
