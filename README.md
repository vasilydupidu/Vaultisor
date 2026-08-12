# Vaultisor 🛡️

[**Русский**](#-русский) | [**English**](#-english)

---

## 🇷🇺 Русский

**Vaultisor** — это защищённое автономное (Air-Gapped) Windows-приложение для локального хранения технических секретов, API-ключей, сертификатов и паролей сайтов. Приложение полностью изолировано от сети, работает без облачных серверов и обеспечивает аппаратно-связанную защиту данных.

### 🌟 Ключевые возможности

- 🔒 **Zero-Trust & Air-Gapped**: Приложение 100% автономно, не отправляет данные в интернет, не содержит телеметрии и не требует регистрации.
- 🔑 **Аппаратные ключи FIDO2 / WebAuthn (Рутокен MFA, YubiKey и др.)**:
  - **Нативная интеграция**: Работает через системную библиотеку Windows `webauthn.dll` (Windows 10 1903+ / Windows 11).
  - **Два режима аутентификации**:
    - 🛡️ **ПИН + Touch** (*Resident Key / User Verification Required*) — максимальная двухфакторная безопасность: ввод ПИН-кода аппаратного ключа и касание контактной площадки.
    - 👆 **Touch-only** (*Passwordless 2FA / User Verification Discouraged*) — сверхбыстрая разблокировка хранилища по одному касанию аппаратного токена без ввода ПИН-кода.
  - **Автоматическое определение модели (AAGUID)**: Извлечение AAGUID из `authenticatorData` и точная идентификация ключей (Рутокен MFA, YubiKey 5 NFC/Nano/Bio, Security Key by Yubico и др.).
  - **Мульти-ключевой менеджмент**: Привязка нескольких независимых FIDO2-токенов к одному хранилищу, наглядные бейджи моделей и подтверждение удаления.
- 🔐 **Аппаратная привязка TPM 2.0 & Windows Hello**: Мастер-ключ шифруется через Windows DPAPI + TPM 2.0 с возможностью разблокировки через биометрию (палец / лицо) или PIN-код Windows Hello.
- 🩺 **Анализ стойкости и подсветка слабых паролей (Health Check)**:
  - Автоматический аудит и выявление дублирующихся (повторно используемых), коротких и простых паролей.
  - Наглядная цветовая индикация уровня безопасности и предупреждения в реальном времени.
- 📜 **История паролей**:
  - Автоматическое сохранение предыдущих ревизий паролей при редактировании записей.
  - Безопасный просмотр истории изменений и копирование старых значений.
- 🗄️ **Раздельное хранение с зашифрованными SQLite (SQLCipher)**:
  - **«Секреты проектов»** (`records.db`): Серверные доступы, API-ключи, private keys.
  - **«Пароли сайтов»** (`web.db`): Учётные записи веб-сервисов с мгновенным поиском и авто-группировкой по доменам (`openai.com`, `google.com`).
- ⚡ **Импорт паролей из Chromium**: Быстрый и удобный импорт паролей из Chrome, Opera, Edge с авто-очисткой исходного CSV с диска (затирание случайными байтами).
- 🛡️ **Пост-квантовая гибридная защита (ML-KEM-1024 / Kyber)**: Поля записей дополнительно защищены гибридным шифрованием, устойчивым к атакам квантовых компьютеров.
- 🧩 **Восстановление через разделение секрета Шамира (Shamir Secret Sharing)**: Мастер-ключ можно разделить на N частей (например, 2 из 3) для безопасного восстановления без мастер-пароля.
- 🌐 **Мультиязычный интерфейс (RU / EN)**: Полная локализация интерфейса с переключением на лету и сохранением выбора в зашифрованных настройках.

### 🛠️ Технологический стек

- **Core / Backend**: Rust 2021, Tauri v2, SQLCipher (AES-256-GCM), Argon2id KDF, Windows CNG / DPAPI / `webauthn.dll`.
- **Frontend**: React 18, TypeScript, Vite, Tailwind CSS, Lucide Icons, i18next.

### 📦 Сборка из исходников

```powershell
# Клонирование репозитория
git clone https://github.com/vasilydupidu/Vaultisor.git
cd Vaultisor

# Установка фронтенд-зависимостей
npm install

# Прогон тестов
npm test
cargo test --workspace

# Сборка портативного .exe бинарника
powershell -ExecutionPolicy Bypass -File .\build.ps1 -SkipDeps
```
Исполняемый файл появится в каталоге `release/Vaultisor-2.7.0.exe`.

---

## 🇬🇧 English

**Vaultisor** is a secure, air-gapped Windows application designed for local storage of technical secrets, API keys, certificates, and web credentials. The application is completely isolated from the network, operates with zero cloud dependencies, and provides hardware-bound data security.

### 🌟 Key Features

- 🔒 **Zero-Trust & Air-Gapped**: 100% offline application. Zero telemetry, zero cloud calls, zero user tracking.
- 🔑 **FIDO2 / WebAuthn Hardware Security Keys (Rutoken MFA, YubiKey, etc.)**:
  - **Native Windows Integration**: Built on top of Windows native `webauthn.dll` API (Windows 10 1903+ / Windows 11).
  - **Flexible Authentication Modes**:
    - 🛡️ **PIN + Touch** (*Resident Key / User Verification Required*) — maximum security requiring hardware PIN entry followed by token contact.
    - 👆 **Touch-only** (*Passwordless 2FA / User Verification Discouraged*) — ultra-fast vault unlock triggered solely by touching the hardware key without PIN.
  - **Automatic Device Model Identification (AAGUID)**: Extracts 16-byte AAGUID from `authenticatorData` to map exact key model names (Rutoken MFA, YubiKey 5 NFC/Nano/Bio, Security Key by Yubico, etc.).
  - **Multi-Key Management**: Register and manage multiple physical security keys with model badges and safe deletion confirmation dialogs.
- 🔐 **TPM 2.0 & Windows Hello Hardware Binding**: Master key is encrypted via Windows DPAPI + TPM 2.0 with optional Windows Hello biometric (fingerprint/face) or PIN authentication.
- 🩺 **Password Health Check & Weak Password Highlighting**:
  - Automated real-time security audit highlighting duplicate (reused), short, or simple passwords.
  - Color-coded security metrics and visual warning indicators.
- 📜 **Password History**:
  - Automatic versioning of previous password revisions whenever a credential is updated.
  - Dedicated history view for inspecting and copying historical values.
- 🗄️ **Dual Partitioned Vaults (SQLCipher AES-256-GCM)**:
  - **Project Secrets** (`records.db`): Server credentials, API keys, private certificates.
  - **Web Passwords** (`web.db`): Site logins with instant search and clean root domain grouping (`openai.com`, `google.com`).
- ⚡ **Chromium Password Import**: Native import from Chrome, Opera, and Edge CSV exports with secure file shredding (overwriting CSV with random bytes before deletion).
- 🛡️ **Post-Quantum Hybrid Protection (ML-KEM-1024 / Kyber)**: Record fields feature post-quantum hybrid encryption to resist future quantum computing threats.
- 🧩 **Shamir Secret Sharing Recovery**: Split master key recovery into N shares (e.g. 2-of-3 quorum) for emergency vault recovery.
- 🌐 **Multilingual UI (RU / EN)**: Full internationalization with instant language switching and encrypted preference storage.

### 🛠️ Tech Stack

- **Core / Backend**: Rust 2021, Tauri v2, SQLCipher (AES-256-GCM), Argon2id KDF, Windows CNG / DPAPI / `webauthn.dll`.
- **Frontend**: React 18, TypeScript, Vite, Tailwind CSS, Lucide Icons, i18next.

### 📦 Building from Source

```powershell
# Clone repository
git clone https://github.com/vasilydupidu/Vaultisor.git
cd Vaultisor

# Install frontend dependencies
npm install

# Run test suites
npm test
cargo test --workspace

# Build portable .exe binary
powershell -ExecutionPolicy Bypass -File .\build.ps1 -SkipDeps
```
The compiled executable will be saved at `release/Vaultisor-2.7.0.exe`.

---

## 📜 License

Distributed under the **GNU General Public License v3.0 (GPL-3.0)**. See [LICENSE](LICENSE) for details.