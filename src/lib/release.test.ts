// @vitest-environment node
//
// Релизный чеклист как проверка, а не как пункт в документе.
//
// Шаг 2 процесса в docs/SDLC.md требует обновлять changelog в README и таблицу
// поддерживаемых версий в SECURITY.md. Пункт пропускался дважды подряд, потому
// что ничем не проверялся: сборка и тесты проходили, а документация тихо
// отставала от версии. Теперь отстать молча нельзя.

import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(__dirname, "..", "..");
const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8")) as {
  version: string;
};
const version: string = pkg.version;
/** Мажор.минор — changelog ведётся по ним, патчи отдельной секции не получают. */
const minor = version.split(".").slice(0, 2).join(".");

describe("релизный чеклист", () => {
  it("версия одинакова в package.json, Cargo.toml и tauri.conf.json", () => {
    const cargo = fs.readFileSync(path.join(root, "src-tauri", "Cargo.toml"), "utf8");
    const cargoVersion = /^version = "([^"]+)"/m.exec(cargo)?.[1];
    const tauri = JSON.parse(
      fs.readFileSync(path.join(root, "src-tauri", "tauri.conf.json"), "utf8"),
    ) as { version: string };

    expect(cargoVersion, "src-tauri/Cargo.toml разошёлся с package.json").toBe(version);
    expect(tauri.version, "tauri.conf.json разошёлся с package.json").toBe(version);
  });

  it("changelog в README описывает текущую минорную версию", () => {
    const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");
    expect(
      readme.includes(`версии ${minor}`) || readme.includes(`v${minor}`),
      `README не описывает ${minor} — обновите changelog в обеих языковых секциях`,
    ).toBe(true);
  });

  it("заметки к релизу описывают текущую версию", () => {
    const notes = fs.readFileSync(path.join(root, ".github", "release_notes.md"), "utf8");
    expect(
      notes.includes(`v${version}`),
      `.github/release_notes.md не описывает v${version} — релиз вышел бы со старыми заметками`,
    ).toBe(true);
  });

  it("toolchain Rust зафиксирован", () => {
    const toolchain = fs.readFileSync(path.join(root, "rust-toolchain.toml"), "utf8");
    expect(toolchain).toMatch(/^channel = "\d+\.\d+\.\d+"$/m);
  });

  it("SECURITY.md объявляет текущую ветку поддерживаемой", () => {
    const security = fs.readFileSync(path.join(root, "SECURITY.md"), "utf8");
    expect(
      security.includes(`${minor}.x`),
      `SECURITY.md не упоминает ${minor}.x — обновите таблицу поддерживаемых версий`,
    ).toBe(true);
  });
});
