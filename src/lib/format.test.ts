import { describe, it, expect, vi, afterEach } from "vitest";

// vi.mock поднимается наверх файла, поэтому фабрика не должна ссылаться на
// переменные модуля — состояние держим прямо внутри неё.
vi.mock("@/lib/i18n", () => {
  const state = {
    language: "ru",
    t: (key: string, vars?: Record<string, unknown>) =>
      vars ? `${key}:${Object.values(vars)[0]}` : key,
  };
  return { default: state };
});

import i18n from "@/lib/i18n";
import { formatDateTime, formatRelativeTime } from "./format";

const mocked = i18n as unknown as { language: string };

describe("formatRelativeTime", () => {
  afterEach(() => {
    mocked.language = "ru";
  });

  const at = (secondsAgo: number) =>
    new Date(Date.now() - secondsAgo * 1000).toISOString();

  it("границы интервалов", () => {
    expect(formatRelativeTime(at(0))).toBe("format.justNow");
    expect(formatRelativeTime(at(59))).toBe("format.justNow");
    expect(formatRelativeTime(at(60))).toBe("format.minutesAgo:1");
    expect(formatRelativeTime(at(3599))).toBe("format.minutesAgo:59");
    expect(formatRelativeTime(at(3600))).toBe("format.hoursAgo:1");
    expect(formatRelativeTime(at(86399))).toBe("format.hoursAgo:23");
    expect(formatRelativeTime(at(86400))).toBe("format.daysAgo:1");
    expect(formatRelativeTime(at(86400 * 6))).toBe("format.daysAgo:6");
  });

  it("старше недели — абсолютная дата", () => {
    const value = formatRelativeTime(at(86400 * 30));
    expect(value).not.toContain("format.");
    expect(value).toMatch(/\d/);
  });

  it("будущее время не даёт отрицательных интервалов", () => {
    const future = new Date(Date.now() + 60_000).toISOString();
    expect(formatRelativeTime(future)).toBe("format.justNow");
  });
});

describe("formatDateTime", () => {
  afterEach(() => {
    mocked.language = "ru";
  });

  /** Раньше дата всегда выводилась в ru-RU. */
  it("следует активному языку интерфейса", () => {
    const iso = "2026-03-04T15:06:07.000Z";
    mocked.language = "ru";
    const ru = formatDateTime(iso);
    mocked.language = "en";
    const en = formatDateTime(iso);
    expect(ru).not.toBe(en);
    // ru-RU ставит день первым, en-US — месяц.
    expect(ru.startsWith("04") || ru.startsWith("4")).toBe(true);
    expect(en.startsWith("3")).toBe(true);
  });
});
