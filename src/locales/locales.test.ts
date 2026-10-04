import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";

import ru from "./ru.json";
import en from "./en.json";

const SOURCE_DIRS = ["src"];
const KEY_PATTERNS = [
  /\bt\(\s*['"]([A-Za-z0-9_.]+)['"]/g,
  /i18nKey=["']([A-Za-z0-9_.]+)["']/g,
  // Ключи, разложенные в данные (`titleKey: "welcome.x"`) и попадающие в
  // t() позже. Без этого обратная проверка объявила бы их осиротевшими.
  /\w*[Kk]ey:\s*["']([A-Za-z0-9_.]+)["']/g,
];

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...sourceFiles(full));
    } else if (/\.tsx?$/.test(entry.name) && !/\.test\.tsx?$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

function usedKeys(): Set<string> {
  const keys = new Set<string>();
  for (const dir of SOURCE_DIRS) {
    for (const file of sourceFiles(dir)) {
      const text = fs.readFileSync(file, "utf8");
      for (const pattern of KEY_PATTERNS) {
        for (const match of text.matchAll(pattern)) {
          // Ключи перевода всегда содержат точку-разделитель пространства имён;
          // односложные совпадения — это setState("pin") и подобное.
          if (match[1]!.includes(".")) keys.add(match[1]!);
        }
      }
    }
  }
  return keys;
}

describe("локализация", () => {
  /** AUDIT 3.1.1: наборы ключей разошлись бы молча при добавлении строки. */
  it("наборы ключей ru и en совпадают", () => {
    const ruKeys = Object.keys(ru).sort();
    const enKeys = Object.keys(en).sort();
    expect(enKeys.filter((k) => !ruKeys.includes(k))).toEqual([]);
    expect(ruKeys.filter((k) => !enKeys.includes(k))).toEqual([]);
  });

  /**
   * Словари намеренно плоские: ключ вида `a.b` — это строка целиком, а не
   * вложенный объект. AUDIT 3.1.1: смешение двух форм уже приводило к тому,
   * что один и тот же ключ существовал дважды.
   */
  it("все значения — строки, вложенных объектов нет", () => {
    for (const [key, value] of Object.entries(ru as Record<string, unknown>)) {
      expect(typeof value, `ru.${key} должен быть строкой`).toBe("string");
    }
    for (const [key, value] of Object.entries(en as Record<string, unknown>)) {
      expect(typeof value, `en.${key} должен быть строкой`).toBe("string");
    }
  });

  it("плейсхолдеры интерполяции совпадают между языками", () => {
    const placeholders = (value: string) =>
      [...value.matchAll(/\{\{(\w+)\}\}/g)].map((m) => m[1]).sort();
    for (const [key, ruValue] of Object.entries(ru as Record<string, string>)) {
      const enValue = (en as Record<string, string>)[key];
      expect(placeholders(ruValue), `плейсхолдеры расходятся в ключе ${key}`).toEqual(
        placeholders(enValue ?? ""),
      );
    }
  });

  it("все ключи, используемые в коде, существуют в обоих словарях", () => {
    const missing = [...usedKeys()].filter(
      (key) => !(key in (ru as Record<string, unknown>)),
    );
    expect(missing, `ключи отсутствуют в словарях: ${missing.join(", ")}`).toEqual([]);
  });

  /**
   * Обратная проверка: строка, которую больше никто не показывает, — это
   * мёртвый код, который расходится с интерфейсом при каждой правке.
   * Ключи, собираемые динамически, перечислены явно.
   */
  it("в словарях нет осиротевших ключей", () => {
    const DYNAMIC_PREFIXES = ["fieldTypes.", "generatorScreen.kind_"];
    const used = usedKeys();
    const orphans = Object.keys(ru).filter(
      (key) =>
        !used.has(key) && !DYNAMIC_PREFIXES.some((prefix) => key.startsWith(prefix)),
    );
    expect(orphans, `ключи больше не используются: ${orphans.join(", ")}`).toEqual([]);
  });

  it("в словарях нет пустых значений", () => {
    for (const [key, value] of Object.entries(ru as Record<string, string>)) {
      expect(value.trim(), `пустое значение ru.${key}`).not.toBe("");
    }
    for (const [key, value] of Object.entries(en as Record<string, string>)) {
      expect(value.trim(), `пустое значение en.${key}`).not.toBe("");
    }
  });
});
