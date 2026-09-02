## Vaultisor v2.8.0 🛡️

[**Русский**](#-что-нового-в-версии-280) | [**English**](#-whats-new-in-v280)

---

### 🇷🇺 Что нового в версии 2.8.0 (Security & Bug Fixes):

- 🛡️ **Аппаратная привязка FIDO2 (PRF Extension)**:
  - Реализован вывод аппаратного ключа шифрования (KEK) через HMAC-Secret / PRF Extension протокола CTAP2/WebAuthn.
  - Автоматическая бесшовная миграция существующих ключей на аппаратный KEK (v2) при первой разблокировке.

- 🔒 **Защита резервных копий (Backup Sanitization)**:
  - Автоматическая санитизация `meta.db` перед формированием бандлов `.vault`: полное удаление хэшей PIN (`pin_hash`), исключающее оффлайн-перебор украденных копий.

- 🔑 **Уникальная энтропия DPAPI для каждого хранилища**:
  - Генерация криптографически стойкой индивидуальной 32-байтной энтропии на каждое хранилище вместо статического значения.

- 🧩 **Усиление криптографических примитивов**:
  - Стандартизированный HKDF (RFC 5869) из библиотеки RustCrypto.
  - Расширенное тестирование и валидация схемы разделения секрета Шамира (Shamir Secret Sharing).

---

### 🇬🇧 What's new in v2.8.0 (Security & Bug Fixes):

- 🛡️ **FIDO2 Hardware Key Derivation (PRF Extension)**:
  - Implemented hardware-bound Key Encryption Key (KEK) derivation via WebAuthn / CTAP2 HMAC-Secret (PRF Extension).
  - Seamless on-the-fly migration of legacy keys to hardware-bound KEK (v2) on successful unlock.

- 🔒 **Backup Sanitization**:
  - Automated `meta.db` sanitization prior to `.vault` bundle packaging: completely strips PIN hashes (`pin_hash`) to eliminate offline bruteforce risks.

- 🔑 **Per-Vault DPAPI Entropy**:
  - Upgraded from static DPAPI entropy to per-vault 32-byte CSPRNG random entropy for all DPAPI-protected blobs.

- 🧩 **Cryptographic Hardening**:
  - Standardized RFC 5869 HKDF implementation via RustCrypto.
  - Expanded comprehensive test suite for Shamir Secret Sharing edge cases and corruption detection.
