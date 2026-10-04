# Vaultisor Release Guide 🚀

Этот документ описывает процесс сборки, версионирования и публикации релизов Vaultisor на GitHub.

---

## 🚀 Как выпустить новый релиз (Автоматически)

Для выпуска новой версии достаточно выполнить 3 простых шага:

### Шаг 1. Обновить версию и документы
Версия (например, `5.1.0`) указывается в `package.json`, `src-tauri/Cargo.toml`
и `src-tauri/tauri.conf.json`, затем синхронизируются `package-lock.json` и
`Cargo.lock`. Там же обновляются changelog в `README.md`, таблица в
`SECURITY.md` и `.github/release_notes.md` — `src/lib/release.test.ts` не даст
забыть ни одно из этого.

### Шаг 2. Проверки и коммит
Гейты из [`docs/SDLC.md`](./SDLC.md), раздел 3, плюс `actionlint` и
`zizmor --persona pedantic .github/workflows`.

### Шаг 3. Тег релиза
```bash
git tag -a v5.1.0 -m "Vaultisor v5.1.0"
git push origin v5.1.0
```

Тег обязан совпадать с версией в `package.json`, иначе `build` остановится.
Дальше `release.yml`: `checks` → `build` (неизменяемый артефакт) → `attest`
(только для публичного репозитория) → `publish` (проверка хэша и публикация
того же артефакта на [GitHub Releases](https://github.com/vasilydupidu/Vaultisor/releases)).
Устройство pipeline — в [`docs/SDLC.md`](./SDLC.md), раздел 5.

Публичный Windows-бинарник выпускается без Authenticode-подписи. Перед запуском
проверяйте SHA-256 по файлу `SHA256SUMS.txt`; сведения о сборке (коммит,
версии rustc и Node) — в `build-info.json`.

### Гейты перед публикацией

Полный перечень блокирующих проверок и их соответствие CI — в
[`docs/SDLC.md`](./SDLC.md), раздел 3. Локально одной командой:

```bash
npm run lint && npm test && npm run build && cargo fmt --all -- --check && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo test --workspace --all-features -- --test-threads=2
```

Плюс цепочка поставки: `cargo deny check advisories licenses sources` и
`npm audit --audit-level=moderate`.

### Форматы резервных копий

Бэкап VLT2 строится через SQLite online-backup API и содержит согласованные
snapshots meta/records/web. Файл копии записывается атомарно (временный файл,
fsync, замена), и его имя несёт идентификатор запроса: повтор после потерянного
ответа не создаёт вторую копию. VLT4 — тот же VLT2 внутри AEAD-контейнера на ключе,
произведённом Argon2id из пароля; параметры KDF лежат в заголовке файла, поэтому
смена констант сборки не делает старые копии нечитаемыми.

При санитизации из снимка удаляются локальная доля Шамира, обёртки FIDO2 и
платформенный credential Windows Hello, после чего `meta_mac` пересчитывается.
Restore в открытое хранилище заменяет только `vault.records.db` и
`vault.web.db`: PIN, Hello, FIDO2, восстановление и задержки PIN остаются
текущими. Импорт на чистую установку того же устройства открывается PIN
(если цел TPM-ключ), на другом устройстве — только восстановлением по долям.

Recovery export не принимает произвольный путь из webview: native save dialog передаёт backend одноразовую короткоживущую capability. Файл создаётся эксклюзивно и существующий destination не перезаписывается.

---

## 🎨 Обновление Иконки Приложения

При изменении или обновлении логотипа приложения:
1. Сохраните квадратный PNG (например, `1024x1024`).
2. Выполните команду пересборки всех разрешениях иконки (`.ico`, `.png`, `.icns`):
```bash
npx tauri icon path/to/icon.png
```

---

## 🔑 Стандарт формата долей Шамира (Shamir Recovery Shares)

Доли восстановления Шамира при экспорте в `.txt` сохраняются в готовом однострочном формате:
```text
vaultisor-share-v1
3|20cb4271e2e517af5138ea0494370fecd2ba9db5712351c8ffefa27595d15939
```
Это позволяет пользователю выделить и скопировать долю `3|20cb...` в 1 клик.
