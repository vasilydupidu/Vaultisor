# Vaultisor 🛡️

[**Русский**](#-русский) | [**English**](#-english)

---

## 🇷🇺 Русский

**Vaultisor** — портативное Windows-приложение для локального хранения
технических секретов: API-ключей, токенов, ключей доступа к серверам и
паролей сайтов. Работает без сети, облака, учётных записей и телеметрии.
Данные привязаны к устройству (TPM 2.0) и учётной записи Windows (DPAPI).

Текущая версия — **5.1.0**. Требования: Windows 10 1903+ или Windows 11,
TPM 2.0 (без TPM — режим мастер-пароля от 15 символов).

### 🔐 Вход и защита

- **PIN Vaultisor — всегда.** От 11 цифр (или буквенно-цифровой от 11
  символов). Мастер-ключ обёрнут Argon2id (512 МиБ, t=6, p=2) от PIN и
  Device Secret из TPM. Хэша PIN нет: PIN проверяется только разворотом
  мастер-ключа, поэтому украденный файл не даёт офлайн-перебора.
- **Windows Hello — второй фактор поверх PIN** (политика И). После PIN
  требуется подпись платформенного WebAuthn-ключа; Hello без PIN мастер-ключ
  не даёт, системный PIN Windows Vaultisor не открывает.
- **FIDO2-ключи** (Рутокен MFA, YubiKey и др.) через системный `webauthn.dll`:
  - режим **ПИН + Touch** — токен требует свой ПИН (два фактора);
  - режим **Touch-only** — одно касание (один фактор владения, выбирается
    осознанно);
  - ключ **привязан к устройству**: мастер-ключ открывается только вместе с
    Device Secret из TPM этого компьютера и DPAPI этой учётной записи —
    скопированное хранилище с тем же токеном на другом ПК не откроется;
  - каждый ответ токена проверяется полностью: rpIdHash, флаги UP/UV,
    clientData, подпись ES256 открытым ключом из регистрации;
  - модель ключа определяется по AAGUID (реестр FIDO Alliance MDS3).
- **Нарастающая задержка вместо блокировки.** После 5 неверных PIN —
  30 с, затем 1, 5, 15 минут и час. Безвозвратной блокировки нет; ни откат
  часов, ни подмена файлов, ни импорт копии задержку не снимают.
- **Подтверждение PIN для изменений безопасности.** Смена PIN, Windows Hello,
  подтверждение копирования, привязка и отвязка FIDO2, восстановление,
  restore и папка резервных копий требуют свежего ввода PIN (и
  Hello, если включён). Открытой сессии недостаточно.
- **Защита от отката и подмены.** Метаданные подписаны HMAC; внешний
  checkpoint в профиле пользователя фиксирует их версию, задержки PIN,
  ревизии и SHA-256 баз. Подменённые старыми копиями базы — целиком или
  отдельными страницами — обнаруживаются при входе.
- **Буфер обмена.** Секрет не попадает в историю буфера и облачный буфер
  Windows, очищается по таймеру (до 2 минут) и при блокировке.
- **Автоблокировка** по простою (до часа), при блокировке сеанса Windows,
  сне и смене пользователя.

### 🗄️ Хранение данных

- **«Секреты проектов»** (`vault.records.db`) и **«Пароли сайтов»**
  (`vault.web.db`) — отдельные базы SQLCipher 4. Каждое значение поля
  дополнительно зашифровано AES-256-GCM на своём ключе HKDF с привязкой к
  записи и полю.
- **Проверка стойкости**: повторно используемые, короткие и простые пароли
  подсвечиваются.
- **История паролей**: прежние значения сохраняются при изменении записи.
- **Генератор секретов**: пароль, буквы и цифры, hex, base64url; показывает
  энтропию в битах; выдачи хранятся зашифрованными и удаляются через сутки.
- **Импорт из Chrome, Edge, Opera** (CSV) одной транзакцией; повторный импорт
  того же файла не создаёт дубликатов.
- **Интерфейс** на русском и английском.

### 🧩 Восстановление и резервные копии

- **Восстановление по схеме Шамира 2-из-3.** Части B (файл) и C (файл или
  копия) хранит пользователь, часть A — на устройстве под DPAPI. Доли
  восстанавливают ключ конверта, а не сам мастер-ключ; новое поколение
  отзывает прежнее. Поколение считается действующим только после явного
  подтверждения, что обе части сохранены: если комплект не дошёл до
  пользователя, при следующем входе будет выдан новый.
- **Восстановление по долям** заново создаёт ключи устройства (TPM-ключ,
  энтропию DPAPI, ключ целостности) одной операцией и задаёт новый PIN;
  Windows Hello и FIDO2 после него привязываются заново.
- **Резервные копии** (`.vault`) — вручную или по расписанию в выбранную
  папку, хранятся последние три. Копия записывается атомарно; открыть её
  можно только этим хранилищем или восстановлением по долям.
- **Restore** в открытое хранилище возвращает только данные: PIN, Hello,
  FIDO2, восстановление и задержки PIN остаются текущими.
- **Импорт** на чистую установку: на том же устройстве — вход по PIN, на
  другом — только восстановлением по долям.
- **Надёжность.** Каждая операция, меняющая хранилище, проверена отказом на
  каждом шаге записи (ошибка и смерть процесса): после любого сбоя хранилище
  целиком в старом или целиком в новом состоянии.

### ⚠️ Особенности Windows

- **Вход по FIDO2 начинается с экрана выбора** «Ключ безопасности /
  Устройство iPhone, iPad или Android» — это диалог Windows 11. Выберите
  «Ключ безопасности» и только потом коснитесь токена.
- **YubiKey с включённым OTP** при коротком касании печатает код как
  клавиатура и может отменить диалог Windows. OTP можно выключить в
  YubiKey Manager.
- **Ключ Windows Hello** виден в «Параметры → Учётные записи → Ключи
  доступа» как `vaultisor.app`. Если удалить его там, вход возможен только
  восстановлением по долям. Отключайте Hello в настройках Vaultisor.
- **Перенос папки `vault`** на другой ПК или в другую учётную запись
  открывается только восстановлением по долям — это свойство привязки к
  устройству, а не сбой.

### 🚀 Что нового в версии 5.1.0

> Хранилища 5.0.x не открываются: схема метаданных и формат checkpoint'а
> изменены, миграции нет — 5.1.0 создаёт хранилище заново.

Консолидация безопасности и надёжности: атомарность всех операций,
проверенная отказами; подтверждение PIN для изменений безопасности;
нарастающая задержка вместо блокировки; FIDO2 с привязкой к устройству и
полной проверкой ответов; защита баз от отката и подмены страниц;
переработанные восстановление, restore и импорт; релизный pipeline
«сборка → неизменяемый артефакт → публикация».

### 🛠️ Технологии

- **Backend**: Rust (toolchain зафиксирован в `rust-toolchain.toml`), Tauri 2,
  SQLCipher 4, AES-256-GCM, Argon2id, HKDF-SHA256, P-256 (ES256), Windows
  CNG / TPM Platform KSP, DPAPI, `webauthn.dll`.
- **Frontend**: React 18, TypeScript, Vite, Tailwind CSS 4, i18next.

### 📦 Сборка из исходников

Нужны Node.js 22, Rust (`rustup`), Strawberry Perl и NASM (для встроенного
OpenSSL SQLCipher).

```powershell
git clone https://github.com/vasilydupidu/Vaultisor.git
cd Vaultisor
npm ci
npm test
cargo test --workspace
powershell -ExecutionPolicy Bypass -File .\build.ps1 -SkipDeps
```

Результат — `release\Vaultisor-<версия>.exe`, один портативный файл; папка
`vault` создаётся рядом с ним. Бинарник не подписан Authenticode — сверяйте
SHA-256 из `SHA256SUMS.txt` релиза.

Политика безопасности и модель угроз — [SECURITY.md](SECURITY.md); процесс
разработки и релиза — [docs/SDLC.md](docs/SDLC.md), [docs/RELEASE.md](docs/RELEASE.md).

---

## 🇬🇧 English

**Vaultisor** is a portable Windows application for storing technical
secrets locally: API keys, tokens, server credentials and website passwords.
It works with no network, no cloud, no accounts and no telemetry. Data is
bound to the device (TPM 2.0) and to the Windows account (DPAPI).

Current version: **5.1.0**. Requires Windows 10 1903+ or Windows 11 with
TPM 2.0 (without a TPM, a master password of 15+ characters is used).

### 🔐 Sign-in and protection

- **The Vaultisor PIN is always required.** 11+ digits (or 11+ alphanumeric
  characters). The master key is wrapped with Argon2id (512 MiB, t=6, p=2)
  from the PIN and a Device Secret held by the TPM. No PIN hash exists: the
  PIN is checked only by unwrapping the master key, so a stolen file gives
  no offline guessing.
- **Windows Hello is a second factor on top of the PIN** (an AND policy).
  After the PIN, a platform WebAuthn signature is required; Hello alone never
  yields the master key, and the Windows PIN does not open Vaultisor.
- **FIDO2 keys** (Rutoken MFA, YubiKey and others) via the system `webauthn.dll`:
  - **PIN + Touch** mode — the token requires its own PIN (two factors);
  - **Touch-only** mode — a single touch (one possession factor, chosen
    deliberately);
  - keys are **bound to the device**: the master key opens only together with
    this computer's TPM Device Secret and this account's DPAPI — a copied
    vault with the same token does not open on another PC;
  - every authenticator response is fully verified: rpIdHash, UP/UV flags,
    clientData and the ES256 signature against the registered public key;
  - the key model is identified by AAGUID (FIDO Alliance MDS3 registry).
- **A growing delay instead of lockout.** After 5 wrong PINs: 30 s, then 1,
  5, 15 minutes and an hour. There is no permanent lockout; rolling back the
  clock, swapping files or importing a backup does not clear the delay.
- **PIN confirmation for security changes.** Changing the PIN, Windows Hello,
  copy confirmation, binding or unbinding FIDO2, recovery, restore and the
  backup folder all require a fresh PIN (plus Hello when enabled). An open
  session is not enough.
- **Rollback and tampering detection.** Metadata is HMAC-signed; an external
  checkpoint in the user profile records its version, the PIN delay, and the
  revisions and SHA-256 of both databases. Databases replaced with older
  copies — whole files or individual pages — are detected at sign-in.
- **Clipboard.** Secrets stay out of Windows clipboard history and cloud
  clipboard, and are cleared on a timer (up to 2 minutes) and on lock.
- **Auto-lock** on inactivity (up to an hour), Windows session lock, sleep
  and user switch.

### 🗄️ Data

- **Project secrets** (`vault.records.db`) and **website passwords**
  (`vault.web.db`) are separate SQLCipher 4 databases. Each field value is
  additionally encrypted with AES-256-GCM under its own HKDF key bound to the
  record and the field.
- **Password health check** highlights reused, short and simple passwords.
- **Password history** keeps previous values when a record changes.
- **Secret generator**: password, letters and digits, hex, base64url; shows
  entropy in bits; generated values are stored encrypted and removed after a day.
- **Import from Chrome, Edge, Opera** (CSV) in one transaction; importing the
  same file again creates no duplicates.
- **Interface** in Russian and English.

### 🧩 Recovery and backups

- **Shamir 2-of-3 recovery.** The user keeps parts B (a file) and C (a file
  or a copy); part A stays on the device under DPAPI. The shares reconstruct
  an envelope key, not the master key itself; a new generation revokes the
  previous one. A generation becomes active only after the user confirms that
  both parts were saved: if a set never reached the user, a new one is issued
  at the next sign-in.
- **Share recovery** re-creates the device keys (TPM key, DPAPI entropy,
  integrity key) in one operation and sets a new PIN; Windows Hello and FIDO2
  are bound again afterwards.
- **Backups** (`.vault`) — manual or scheduled into a chosen folder, the last
  three are kept. A backup is written atomically and opens only with this vault
  or through share recovery.
- **Restore** into an open vault brings back data only: the PIN, Hello,
  FIDO2, recovery and PIN delay stay as they are.
- **Import** onto a clean install: on the same device it opens with the PIN,
  on another device only through share recovery.
- **Reliability.** Every operation that changes the vault is tested with a
  failure at every write step (both an error and process death): after any
  failure the vault is entirely in the old or entirely in the new state.

### ⚠️ Windows notes

- **FIDO2 sign-in starts with a chooser** — "Security key / iPhone, iPad or
  Android device" — which is Windows 11's own dialog. Choose "Security key"
  first and only then touch the token.
- **A YubiKey with OTP enabled** types a code like a keyboard on a short touch
  and may cancel the Windows dialog. OTP can be turned off in YubiKey Manager.
- **The Windows Hello key** is listed under Settings → Accounts → Passkeys as
  `vaultisor.app`. Deleting it there leaves share recovery as the only way in.
  Turn Hello off in Vaultisor's settings instead.
- **Moving the `vault` folder** to another PC or Windows account opens it only
  through share recovery — this is device binding, not a fault.

### 🚀 What's new in v5.1.0

> Vaults from 5.0.x do not open: the metadata schema and checkpoint format
> changed, with no migration — 5.1.0 creates the vault from scratch.

A security and reliability consolidation: atomicity of every operation,
verified by fault injection; PIN confirmation for security changes; a growing
delay instead of lockout; device-bound FIDO2 with full response verification;
rollback and page-tampering detection for the databases; reworked recovery,
restore and import; a "build → immutable artifact → publish" release pipeline.

### 🛠️ Tech stack

- **Backend**: Rust (toolchain pinned in `rust-toolchain.toml`), Tauri 2,
  SQLCipher 4, AES-256-GCM, Argon2id, HKDF-SHA256, P-256 (ES256), Windows
  CNG / TPM Platform KSP, DPAPI, `webauthn.dll`.
- **Frontend**: React 18, TypeScript, Vite, Tailwind CSS 4, i18next.

### 📦 Building from source

Requires Node.js 22, Rust (`rustup`), Strawberry Perl and NASM (for
SQLCipher's vendored OpenSSL).

```powershell
git clone https://github.com/vasilydupidu/Vaultisor.git
cd Vaultisor
npm ci
npm test
cargo test --workspace
powershell -ExecutionPolicy Bypass -File .\build.ps1 -SkipDeps
```

The result is `release\Vaultisor-<version>.exe`, a single portable file; the
`vault` folder is created next to it. The binary is not Authenticode-signed —
verify its SHA-256 against `SHA256SUMS.txt` from the release.

Security policy and threat model: [SECURITY.md](SECURITY.md); development and
release process: [docs/SDLC.md](docs/SDLC.md), [docs/RELEASE.md](docs/RELEASE.md).

---

## 📜 License

Distributed under the **GNU General Public License v3.0 only (GPL-3.0-only)**.
See [LICENSE](LICENSE) for details.
