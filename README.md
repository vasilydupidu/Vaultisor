# Vaultisor 🛡️

[**Русский**](#-русский) | [**English**](#-english)

---

## 🇷🇺 Русский

**Vaultisor** — это защищённое автономное (Air-Gapped) Windows-приложение для локального хранения технических секретов, API-ключей, сертификатов и паролей сайтов. Приложение полностью изолировано от сети, работает без облачных серверов и обеспечивает аппаратно-связанную защиту данных.

### 🌟 Ключевые возможности

- 🔒 **Zero-Trust & Air-Gapped**: Приложение 100% автономно, не отправляет данные в интернет, не содержит аналитики и не требует регистрации.
- 🔑 **Аппаратные ключи FIDO2 / WebAuthn (Рутокен MFA, YubiKey и др.)**:
  - **Универсальная поддержка FIDO2**: Работа через нативный системный API `webauthn.dll` (Windows 10/11).
  - **Два режима аутентификации**:
    - 🛡️ **ПИН + Touch** (*Resident Key / User Verification Required*) — максимальная безопасность с вводом аппаратного ПИН-кода и касанием токена.
    - 👆 **Touch-only** (*Passwordless 2FA / User Verification Discouraged*) — сверхбыстрый разблокировка по одному касанию аппаратного ключа без ввода ПИН-кода.
  - **Автоматическая идентификация по AAGUID**: Распознавание моделей ключей (Рутокен MFA, YubiKey 5 NFC/Nano/Bio, Security Key by Yubico и др.).
  - **Мульти-ключи**: Привязка нескольких ключей с удобным управлением, отображением формата/модели и подтверждением удаления.
- 🔐 **Аппаратная привязка TPM 2.0 & Windows Hello**: Мастер-ключ шифруется через Windows DPAPI + TPM 2.0 с возможностью подтверждения через биометрию или PIN-код Windows Hello.
- 🩺 **Анализ стойкости и подсветка слабых паролей (Health Check)**:
  - Автоматическое выявление дублирующихся (повторно используемых), коротких и простых паролей.
  - Наглядная цветовая индикация уровня безопасности и предупреждения в реальном времени.
- 📜 **История паролей**:
  - Запоминание прошлых паролей для каждой записи.
  - Безопасный просмотр истории изменений и копирование предыдущих версий.
- 🗄️ **Раздельное хранение с зашифрованными SQLite (SQLCipher)**:
  - **«Секреты проектов»** (`records.db`): Серверные доступы, API-ключи, private keys.
  - **«Пароли сайтов»** (`web.db`): Учётные записи веб-сервисов с мгновенным поиском и авто-группировкой по доменам (`openai.com`, `google.com`).
- ⚡ **Импорт паролей из Chromium**: Быстрый и удобный импорт паролей из Chrome, Opera, Edge с авто-очисткой исходного CSV с диска (затирание случайными байтами).
- 🛡️ **Пост-квантовая гибридная защита (ML-KEM-1024 / Kyber)**: Поля записей дополнительно защищены гибридным шифрованием, устойчивым к атакам квантовых компьютеров.
- 🧩 **Восстановление через разделение секрета Шамира (Shamir Secret Sharing)**: Мастер-ключ можно разделить на N частей (например, 2 из 3) для безопасного восстановления без мастер-пароля.
- 🌐 **Мультиязычный интерфейс (RU / EN)**: Переключение языка «на лету» с сохранением настроек.

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
- 🔑 **FIDO2 / WebAuthn Hardware Keys (Rutoken MFA, YubiKey, etc.)**:
  - **Universal FIDO2 Support**: Native Windows `webauthn.dll` integration (Windows 10/11).
  - **Flexible Authentication Modes**:
    - 🛡️ **PIN + Touch** (*Resident Key / User Verification Required*) — maximum security requiring hardware PIN code entry followed by token contact.
    - 👆 **Touch-only** (*Passwordless 2FA / User Verification Discouraged*) — ultra-fast unlock triggered solely by touching the hardware key.
  - **Automatic Device Recognition (AAGUID)**: Identifies hardware models out of the box (Rutoken MFA, YubiKey 5 Series, YubiKey Bio, Security Key by Yubico, etc.).
  - **Multi-Key Management**: Bind and manage multiple hardware security keys with clear model indicators and safe deletion dialogs.
- 🔐 **TPM 2.0 & Windows Hello Hardware Binding**: Master key is encrypted via Windows DPAPI + TPM 2.0 with optional Windows Hello biometric/PIN authentication.
- 🩺 **Password Health Check & Weak Password Highlighting**:
  - Real-time audit highlighting duplicate (re-used), weak, or outdated credentials.
  - Color-coded security indicators and warning alerts.
- 📜 **Password History**:
  - Automatic tracking of previous password revisions per record.
  - Secure inspection and copying of historic password values.
- 🗄️ **Dual Partitioned Vaults (SQLCipher AES-256-GCM)**:
  - **Project Secrets** (`records.db`): Server credentials, API keys, private certificates.
  - **Web Passwords** (`web.db`): Site logins with instant search and clean root domain grouping (`openai.com`, `google.com`).
- ⚡ **Chromium Password Import**: Native import from Chrome, Opera, and Edge CSV exports with secure file shredding (overwriting CSV with random bytes before deletion).
- 🛡️ **Post-Quantum Hybrid Protection (ML-KEM-1024 / Kyber)**: Record fields feature post-quantum hybrid encryption to resist future quantum computing threats.
- 🧩 **Shamir Secret Sharing Recovery**: Split master key recovery into N shares (e.g. 2-of-3 quorum) for emergency vault recovery.
- 🌐 **Multilingual UI (RU / EN)**: Dynamic, instant language switching.

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