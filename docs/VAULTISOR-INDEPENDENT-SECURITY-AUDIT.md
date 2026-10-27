> **Исторический документ: аудит версии 5.0.x. Актуальный статус находок — docs/VAULTISOR-5.2.0-SECURITY-CONSOLIDATION.md; описанные здесь схемы (локальная доля A, экспорт, VLT4) в текущей версии удалены.**

# Vaultisor — независимый аудит безопасности

> Аудит проведён «с чистого листа»: выводы опираются только на исходный код,
> конфигурацию сборки и результаты запуска тестов. README, SECURITY.md,
> changelog, комментарии `AUDIT …` в коде и предыдущие отчёты рассматривались
> как **утверждения, подлежащие проверке**, а не как доказательства.

---

## 1. Executive Summary

| Параметр | Значение |
|---|---|
| Продукт | Vaultisor — портативное офлайн-хранилище технических секретов для Windows |
| Версия | **5.0.6**, коммит `ec45e15` (ветка `main`) |
| Дата | 22.09.2026 |
| Объём | весь backend (`src-tauri/src`, `core-shared/src`, ~15 000 строк Rust), критичные пути frontend (`src/`), конфигурация Tauri, CI/CD (`.github/workflows`), `build.ps1`, зависимости (`Cargo.lock`, `package.json`), документация |
| Метод | ручной построчный code review всех модулей backend; трассировка жизненного цикла каждого секрета; построение матрицы аутентификации; моделирование прерывания на каждом шаге персистентности; прогон `cargo deny`, `cargo audit`; **две находки подтверждены исполняемыми пробными тестами** (после прогона удалены из дерева); второй adversarial-проход по каждому HIGH |
| Ограничения | динамическое тестирование на железе (TPM, Windows Hello, YubiKey/Рутокен) не проводилось — поведение Windows API оценено по документации и коду; фаззинг не проводился; поведение CTAP2 hmac-secret разных поколений токенов оценено по спецификации; WebView2 и сам Tauri не аудировались |

**Итог по находкам**

| Уровень | Количество |
|---|---|
| CRITICAL | 0 |
| HIGH | 5 |
| MEDIUM | 9 |
| LOW | 14 |
| INFO | 6 |

**Главное в пяти пунктах**

1. **Криптографическое ядро спроектировано хорошо.** Мастер-ключ нигде не лежит в открытом виде, PIN проверяется только AEAD-разворотом (оракула перебора нет), поля записей шифруются на per-value HKDF-субключах с привязкой через AAD, восстановление идёт через KEK-конверт с поколением в AAD, метаданные защищены HMAC с однозначным кодированием и двумя якорями против отката. Грубых криптографических ошибок не найдено.
2. **Основные проблемы — не в примитивах, а в композиции и жизненном цикле состояния.** Два пути ведут к **потере данных обычным действием**: откат неудачного `vault_create` стирает *существующее* хранилище (H-01), а смена типа поля в редакторе без повторного ввода значения навсегда делает значение нерасшифровываемым (H-02, воспроизведено).
3. **Граница «разблокированная сессия» не различает чтение и изменение политики безопасности.** Отключить подтверждение Hello для копирования/просмотра, привязать собственный touch-only FIDO2-ключ, перевыпустить доли Шамира можно без повторной аутентификации (H-03): step-up защиту отключает тот, против кого она поставлена.
4. **FIDO2-путь не привязан к устройству.** Конверт мастер-ключа под FIDO2-PRF хранится без DPAPI-слоя, поэтому копия `vault.meta.db` + touch-only токен дают мастер-ключ на любой машине — вопреки утверждениям SECURITY.md о привязке файлов к устройству (H-04).
5. **Много fail-closed состояний, а единственный выход из них — восстановление, которое можно отключить.** `TOO_MANY_ATTEMPTS` (без backoff, достижим за пару минут любым человеком у ПК), `META_TAMPERED` (удалён или повреждён якорь), удалённый ключ Hello — всё сходится к Shamir; при выключенном восстановлении это необратимая потеря (H-05). Сам путь восстановления не атомарен (M-01).

---

## 2. Архитектура

### 2.1 Карта компонентов (восстановлена по коду)

```
+----------------- Процесс Vaultisor (single-instance) ------------------------------------------+
|                                                                                                 |
|  WebView2 (React 18 / TS) --- Tauri IPC (invoke) ---> 59 команд #[tauri::command] (lib.rs:154) |
|   * CSP: script-src 'self'; сети нет; devtools выкл.        |                                   |
|   * capabilities: только core:* (плагины fs/dialog           v                                   |
|     зарегистрированы, но прав у webview не имеют)   AppState (state.rs)                         |
|                                                      +- session: Locked | Unlocked{MK,           |
|                                                      |    integrity_key, records_db, web_db, ...}|
|                                                      +- auth_flow: tokio::Mutex (вход/recovery)  |
|                                                      +- file_grants, pending_* (одноразовые)     |
|                                                      +- settings (кэш)                           |
|                                                                                                 |
|  crypto/ + core-shared        storage/                        windows_api/                      |
|  * AES-256-GCM, Argon2id,     * meta_db  (SQLite, ОТКРЫТЫЙ)   * dpapi (CurrentUser + entropy)   |
|    HKDF, Shamir GF(256),      * records_db / web_db (SQLCipher)* cng_hello (TPM RSA-2048, PCP)  |
|    CryptProtectMemory         * integrity (HMAC мета)         * key_credential (Hello WebAuthn) |
|  * master, device_secret      * restore (журнал транзакции)   * webauthn_ffi (один биндинг)     |
|                               * machine_checkpoint            * clipboard, session watcher      |
+-------------------------------------------------------------------------------------------------+
Файлы: <exe>/vault/{vault.meta.db, vault.records.db, vault.web.db, vault.meta.rollback-guard,
       backup.json, .restore-transaction/}
       %LOCALAPPDATA%/Vaultisor/SecurityCheckpoints/<sha256(created_at)>.checkpoint
```

### 2.2 Хранилища данных

| Файл | Шифрование | Содержит | Целостность |
|---|---|---|---|
| `vault.meta.db` | **нет** (обычный SQLite) | обёртку MK (DPAPI → AES-GCM → Argon2id), `integrity_key` (DPAPI), DS-blob, recovery-конверт, FIDO2-конверты (**без DPAPI**), публичный ключ Hello, настройки, счётчик попыток | HMAC-SHA256 по всем полям + дайджест `fido2_keys` (кроме `recovery_local`); `security_epoch`; локальный и внешний якорь |
| `vault.records.db` | SQLCipher 4 (ключ = HKDF(MK)) | записи, поля (значения — дополнительно AES-GCM), история паролей, выдачи генератора | постраничный HMAC SQLCipher; **без версии/якоря** |
| `vault.web.db` | SQLCipher 4 (отдельный HKDF-ключ) | «пароли сайтов» (импорт CSV) | как выше |
| `*.rollback-guard`, `*.checkpoint` | checkpoint — DPAPI | `epoch ‖ meta_mac ‖ HMAC` | HMAC на `integrity_key` |
| `backup.json` | нет | каталог и частота бэкапов | HMAC на `integrity_key` |

### 2.3 Пути получения мастер-ключа (MK)

1. **PIN / мастер-пароль** → `vault_unlock` (`commands/vault/unlock.rs:25`).
2. **FIDO2 (PRF/hmac-secret)** → `vault_unlock_with_fido2` (`commands/vault/lifecycle.rs:61`) — **самостоятельный путь**, без PIN и без Hello.
3. **Shamir 2-из-3** → `recovery_restore` (`commands/recovery.rs:192`); на том же ПК достаточно **одной** доли пользователя: доля A подгружается из DPAPI (`recovery.rs:228`).
4. **Смена PIN** → `vault_change_pin` (`lifecycle.rs:194`) — фактически ещё один вход по PIN, открывающий сессию (`lifecycle.rs:271`).
5. Windows Hello — **не путь к MK**, а проверка подписи WebAuthn после PIN: политика, а не ключевой материал.

### 2.4 Модель релиза и обновлений

Портативный `.exe` без инсталлятора и автообновления. Сборка — GitHub Actions по тегу `v*` (`release.yml`) либо локально `build.ps1`. Бинарь **не подписан** Authenticode; целостность — `SHA256SUMS.txt`, созданный в том же job, что и сборка. Provenance/attestation нет.

### 2.5 Границы доверия

| Граница | Что на ней проверяется |
|---|---|
| WebView ↔ backend (IPC) | состояние сессии, автоблокировка по простою, одноразовые файловые полномочия, step-up Hello (выборочно) |
| Процесс ↔ ОС (DPAPI/CNG/WebAuthn) | пользователь Windows (DPAPI), неэкспортируемость TPM-ключа, UV/UP платформенного аутентификатора |
| `vault/` ↔ `%LOCALAPPDATA%` | anti-rollback (внешний checkpoint) |
| Процесс ↔ внешние файлы (бэкапы, CSV, доли) | формат, MAC, AEAD, `quick_check` |
| Исходники ↔ бинарь (CI) | пины Actions по SHA, cargo-deny/audit, npm audit |

### 2.6 Документация против кода (кратко; подробно — §17)

- README (раздел 4.0.0): «**PIN обязателен всегда.** Windows Hello и FIDO2 стали вторым фактором поверх PIN» — неверно для FIDO2: `vault_unlock_with_fido2` открывает хранилище без PIN и без Hello. SECURITY.md («Не защищает», п.4) это признаёт — документы противоречат друг другу.
- SECURITY.md п.1 и п.3: «Без TPM этого устройства и без PIN файлы бесполезны», «DPAPI и Device Secret привязывают данные к паре пользователь + устройство» — неверно при привязанном FIDO2-ключе (H-04).
- SECURITY.md: «Целостность метаданных — домен **v9**»; в коде `vaultisor:meta-integrity:v1`.
- SECURITY.md «Защищает», п.4 «откат к старому снимку» — защищены только метаданные; откат `records.db`/`web.db` не обнаруживается (M-05).
- README и UI: touch-only назван «**Passwordless 2FA**» — это один фактор владения.
- `.github/release_notes.md` описывает **v3.1.0**, но публикуется телом каждого релиза.

---

## 3. Модель угроз

| # | Противник | Возможности | Что защищает Vaultisor | Оценка |
|---|---|---|---|---|
| A | **Украденные файлы** (`vault/`, бэкап `.vault`, конфиг) | чтение файлов на своей машине | DPAPI (нужен пароль Windows владельца) + DS в TPM + Argon2id(PIN); SQLCipher + AES-GCM на полях | **сильная**, кроме привязанного touch-only FIDO2 (H-04) и утечки пары долей B+C |
| B | **Украденный ПК** (выключен) | диск, TPM этого же ПК, своя ОС | как A; TPM привязывает DS к машине | зависит от BitLocker и пароля Windows: TPM-ключ PCP не привязан к личности Windows (I-02) |
| C | **Same-user malware** | DPAPI, `NCryptSignHash`, файлы, инъекция в процесс | Argon2id 512 МиБ на попытку PIN; MK в `CryptProtectMemory` | **слабая** (признано в SECURITY.md): офлайн-перебор PIN без счётчика; инъекция снимает всё |
| D | **Скомпрометированный webview** (например, через npm-зависимость фронтенда) | произвольные `invoke` с любыми аргументами | сессионные проверки, файловые полномочия через нативный диалог, step-up | **средняя**: деструктивный `vault_create` без авторизации (H-01), изменение политики без re-auth (H-03), вход без Hello через `vault_change_pin` (M-08) |
| E | **Компрометация памяти** (дамп, pagefile, hiberfil) | чтение памяти процесса | MK под `CryptProtectMemory(SAME_PROCESS)` | **частичная**: SQLCipher-ключ, `integrity_key`, расшифрованные значения — открыто; health check расшифровывает все секреты на каждый `record_list` (L-12) |
| F | **Атакующий бэкапы** | подмена, откат, порча `.vault` | MAC мета под текущим `integrity_key`, `checkpoint_id`, проверка страниц SQLCipher, `quick_check` | **хорошая** по подлинности; слабые места — неограниченные параметры Argon2 в VLT4 (L-01), устаревший SQLite для недоверенных файлов (L-02), «авторизованный» откат политики (M-02) |
| G | **Rollback-атакующий** | замена файлов старыми валидными версиями | epoch + локальный якорь + внешний DPAPI-checkpoint | **хорошая для мета**, **нет** для `records.db`/`web.db` (M-05); якорь пишется неатомарно (M-06) |
| H | **Supply chain** | зависимость, CI, релиз | пины Actions по SHA, cargo-deny, cargo-audit, npm audit, Dependabot | **средняя**: `contents: write` в одном job с `npm install`, нет provenance и подписи, SCA не видит C-код SQLCipher/SQLite (M-09, L-02) |
| I | **Утрата фактора** (токен, учётка Windows, доли, устройство) | владение утерянным фактором | отвязка ключа, регенерация долей, recovery | **средняя**: MK не ротируется — старые доли и PIN работают с историческими копиями (M-04); touch-only токен = доступ (H-04) |
| J | **Человек у разблокированного ПК** («обеденный перерыв») | UI Vaultisor без знания секретов | автоблокировка, Win+L-watcher, step-up Hello | **слабая**: step-up отключается в настройках, бэкдор через свой FIDO2-ключ или перевыпуск долей (H-03); 10 неверных PIN — необратимая блокировка при выключенном восстановлении (H-05) |
| K | **Держатель портативного носителя** | запись в каталог `vault/` на флешке, но не в профиль пользователя | внешний checkpoint | может откатить `records.db` (M-05), подложить журнал восстановления (только DoS), удалить файлы |

---

## 4. Иерархия ключей

```
                         PIN / мастер-пароль (знание)
                                   |
   TPM 2.0 (Platform KSP) --silent NCryptSignHash(SHA256("vaultisor:device-secret-kek-challenge:v1"))
   RSA-2048, неэкспортир.          |  (детерминированная PKCS#1 v1.5 подпись)
                                   v
                     HKDF(sig, "ds-kek-salt:v1", "ds-kek:v1") = DS-KEK
                                   |
                     AES-GCM(DS-KEK, DS[32 random], AAD "device-secret:v1") --> meta.device_secret_tpm_blob
                                   |
       Argon2id(PIN || DS, salt16, m=512MiB, t=6, p=2) = PIN-KEK        (без TPM: Argon2id(PIN))
                                   |
            AES-GCM(PIN-KEK, MK, AAD "master-wrap:v2")  --> WrappedKey(salt|nonce|ct)
                                   |
            DPAPI(CurrentUser, entropy = random32 per vault) --> meta.wrapped_master_key

 MK (32 байта OsRng, НИКОГДА не ротируется)
  |-- HKDF(MK, "sqlcipher-salt:v1", "sqlcipher-records:v1") --> ключ SQLCipher records.db
  |-- HKDF(MK, "sqlcipher-salt:v1", "sqlcipher-web:v1")     --> ключ SQLCipher web.db
  |-- HKDF(MK, salt16 random, "field-aead:v2") --> AES-GCM(value, AAD "field:<rec>:<field>:<type>")
  |       (то же для истории: AAD "history:<rec>:<hist>", генератора: "generated:<id>")
  |
  |<-- FIDO2: HKDF(PRF=hmac-secret(salt const), "fido2-prf-kek-salt:v1", "fido2-prf-kek:v1")
  |          AES-GCM(KEK, MK, AAD "fido2-wrap:v2") --> meta.fido2_keys.fido2_wrapped_key  (БЕЗ DPAPI!)
  |
  |<-- Recovery: RK = random32 на поколение; AES-GCM(RK, MK, AAD "recovery-master-wrap:v2:<gen>")
  |          --> meta.recovery_wrapped_master;  RK --Shamir 2/3--> A (DPAPI, meta.recovery_local)
  |                                                              B (файл .vss), C (бумага)
 integrity_key (32 random, отдельно от MK) -- DPAPI --> meta.integrity_key_dpapi
  |-- HMAC(meta: все поля + digest(fido2_keys), домен "meta-integrity:v1")  --> meta.meta_mac
  |-- HMAC("meta-rollback-guard:v1" | epoch | meta_mac) --> локальный якорь + DPAPI-checkpoint
  |-- HMAC("backup-config:v1" | json) --> backup.json
 Windows Hello: платформенный WebAuthn ES256-ключ; public key в meta (под MAC) — только проверка подписи
 Бэкап VLT4: Argon2id(password, salt16, параметры ИЗ ЗАГОЛОВКА) --> AES-GCM(AAD "backup-v3")
```

### 4.1 Жизненный цикл секретов

| Секрет | Создание | Хранение | Время жизни в RAM | Ротация | Отзыв | Уничтожение |
|---|---|---|---|---|---|---|
| MK | `generate_master_key` (OsRng) | только обёртки | сессия, `CryptProtectMemory`; копии на стеке в `with_decrypted` зануляются | **нет** | **нет** (M-04) | при `lock()` — Drop + zeroize |
| PIN | ввод пользователя | нигде | `String` из IPC (не зануляется), копия в `Zeroizing` для Argon2 | `vault_change_pin` | старая обёртка остаётся в бэкапах (M-04) | — |
| DS | `vault_create`/`recovery_restore` | AES-GCM под TPM-KEK | на время unwrap, `Zeroizing` | при recovery (новый TPM-ключ) | старый TPM-ключ удаляется при recovery | `NCryptDeleteKey` |
| integrity_key | `vault_create`/`recovery_restore` | DPAPI | вся сессия, `Zeroizing` открыто | при recovery | — | Drop |
| SQLCipher-ключи | HKDF(MK) при открытии | нет | вся сессия внутри SQLCipher/OpenSSL (не защищён) | вместе с MK — никогда | — | закрытие соединения |
| RK (recovery) | на поколение | Shamir-доли + конверт | во время split/combine | `recovery_regenerate` | конверт заменяется, но старые конверты живут в копиях мета (M-04) | — |
| FIDO2 PRF / KEK | assertion | конверт в meta | на время unwrap | нет | удаление строки `fido2_keys` | zeroize |
| Share A | split | DPAPI в `recovery_local` (вне MAC) | при recovery | с поколением | `clear_recovery` | удаление строки (`secure_delete=ON`) |
| Shares B/C | split | у пользователя | **в JS webview** при онбординге/регенерации (неизбежно) | с поколением | только логически (M-04) | — |
| Значения полей | ввод/импорт | AES-GCM + SQLCipher | reveal → `String` в webview; health check — массово (L-12) | история до 10 версий | удаление | `secure_delete=ON` |

---

## 5. Матрица аутентификации

| Путь | Необходимые условия | Что открывает | Независимый фактор? |
|---|---|---|---|
| PIN (TPM-режим) | знание PIN; сессия Windows владельца (DPAPI); этот TPM (DS, **без жеста**); MAC и якоря целы; счётчик < лимита | MK, сессия | Знание + привязка к устройству. TPM даёт привязку, а не присутствие пользователя |
| Мастер-пароль (без TPM) | знание пароля ≥ 15 символов; DPAPI | MK, сессия | Знание + DPAPI |
| PIN + Windows Hello | как PIN, **плюс** WebAuthn-assertion платформенного ключа (UV+UP, ES256 проверяется) | MK выводится **до** Hello; Hello только разрешает открыть сессию | Против человека у UI — да. Против кода под пользователем — нет (обход офлайн). Обходится `vault_change_pin` (M-08) и FIDO2-путём |
| FIDO2 touch-only | владение токеном + касание; в приложении — DPAPI для проверки MAC; **офлайн DPAPI не нужен** | MK, сессия; офлайн на любой машине (H-04) | Один фактор владения. Заменяет PIN и Hello |
| FIDO2 ПИН + Touch | токен + ПИН токена (аппаратный счётчик попыток токена) | MK, сессия; офлайн на любой машине с ПИН токена | Два фактора, но **вместо** PIN Vaultisor и Hello |
| Recovery A + B (или A + C) на том же ПК | сессия Windows владельца (DPAPI для A) + **одна** доля пользователя | MK; новый PIN; Hello и step-up выключаются; счётчик сбрасывается | Устройство + одна доля. Обходит PIN, счётчик, Hello |
| Recovery B + C | две доли + `vault.meta.db` (конверт) любой эпохи того же поколения | MK на любой машине | Владение двумя долями |
| Бэкап (VLT2) + B + C | файл бэкапа + две доли | MK на любой машине | как выше |
| Бэкап + PIN на том же ПК | только через `vault_restore` из **живой разблокированной** сессии; `vault_import` даёт `META_TAMPERED` (M-03) | — | — |
| `vault_change_pin` (IPC) | знание PIN; не требует сессии | открывает сессию **без Hello** | Обход Hello (M-08) |
| Step-up «подтверждение копирования/просмотра» | Hello в пределах 60 с | reveal/copy/history/update | Отключается в настройках без Hello (H-03); не покрывает `generator_copy` (L-05) |
| Same-user офлайн | DPAPI + тихая подпись TPM + перебор Argon2 | MK | Знания PIN не требуется при достаточных ресурсах (I-02) |

**OR вместо ожидаемого AND.** Документация утверждает AND (PIN ∧ Hello). Фактическая политика:
`(PIN ∧ DPAPI ∧ TPM ∧ [Hello, если включён]) ∨ FIDO2_key ∨ (DPAPI ∧ одна доля) ∨ (две доли) ∨ (PIN через vault_change_pin, без Hello)`.

---

## 6. Сводка находок

| ID | Severity | Компонент | Находка | Confidence |
|---|---|---|---|---|
| H-01 | HIGH | `commands/vault/create.rs` | Любая ошибка `vault_create` запускает откат, который удаляет **существующее** хранилище, его TPM-ключ и ключ Hello | HIGH |
| H-02 | HIGH | `storage/records/crud.rs` | Смена типа существующего поля без повторного ввода значения навсегда ломает AAD — значение теряется (воспроизведено) | HIGH |
| H-03 | HIGH | `commands/settings.rs`, `recovery.rs` | Изменения политики безопасности из разблокированной сессии без повторной аутентификации: отключение step-up/Hello, привязка своего FIDO2-ключа, перевыпуск долей, отключение recovery | HIGH |
| H-04 | HIGH | FIDO2-путь (`settings.rs:420`, `lifecycle.rs:61`) | FIDO2-конверт MK не привязан к устройству и учётке; touch-only токен + копия мета = MK на любой машине; документация утверждает обратное | MEDIUM |
| H-05 | HIGH | `unlock.rs`, `lifecycle.rs`, онбординг | Fail-closed состояния без выхода, кроме Shamir, при отключаемом восстановлении; `TOO_MANY_ATTEMPTS` без backoff достижим любым человеком у ПК | HIGH |
| M-01 | MEDIUM | `commands/recovery.rs` | Восстановление — ~9 независимых транзакций; сбой после отзыва конверта и до сохранения DS делает хранилище неоткрываемым по PIN | HIGH |
| M-02 | MEDIUM | `commands/vault/io.rs`, `backup.rs` | «Авторизованный» restore молча откатывает политику: старый PIN, отозванное поколение долей, выключенный Hello и step-up, удалённые FIDO2-ключи | HIGH |
| M-03 | MEDIUM | импорт бэкапа | После потери живого хранилища бэкап открывается только при наличии **обеих** долей B и C — даже на том же ПК с верным PIN | HIGH |
| M-04 | MEDIUM | криптомодель | MK не ротируется: отзыв долей и смена PIN не действуют на исторические копии мета/бэкапов | HIGH |
| M-05 | MEDIUM | `records_db.rs` | Откат и сращивание страниц `records.db`/`web.db` не обнаруживаются | HIGH |
| M-06 | MEDIUM | `meta_db/crud.rs:279` | Локальный rollback-якорь пишется неатомарно (truncate + write) — сбой питания даёт `META_TAMPERED` | HIGH |
| M-07 | MEDIUM | `commands/import.rs` | Импорт CSV молча пропускает записи (URL > 256 символов), после чего предлагает «затереть» исходный CSV (воспроизведено) | HIGH |
| M-08 | MEDIUM | `lifecycle.rs:194` | `vault_change_pin` работает без сессии и открывает сессию в обход Windows Hello | HIGH |
| M-09 | MEDIUM | `.github/workflows` | Релизный job: `contents: write` рядом с `npm install`, нет provenance; `npm install` вместо `npm ci`; нет top-level `permissions`; устаревшие release notes | HIGH |
| L-01 | LOW | `io.rs:276` | Параметры Argon2 из заголовка VLT4 не ограничены — зависание/аварийное завершение | HIGH |
| L-02 | LOW | зависимости | SQLCipher 4.5.7 / SQLite 3.45.3 устарели; недоверенные БД открываются с `trusted_schema` по умолчанию; SCA не видит C-код | MEDIUM |
| L-03 | LOW | `state.rs`, `recovery.rs:552` | Автоблокировка ленивая (нет таймера в backend); `recovery_disable` продлевает простой до проверки | HIGH |
| L-04 | LOW | `windows_api/session.rs` | `WM_POWERBROADCAST`/`WM_ENDSESSION` не доходят до message-only окна — блокировка по сну не срабатывает | MEDIUM |
| L-05 | LOW | `generator.rs:124` | `generator_copy` не проходит step-up Hello | HIGH |
| L-06 | LOW | `windows_api/clipboard.rs` | Fail-open: при ошибке маркера исключения секрет остаётся в буфере без маркеров и без автоочистки | HIGH |
| L-07 | LOW | `recovery.rs` | `recovery_restore` не закрывает живую сессию — рассинхрон `integrity_key` | HIGH |
| L-08 | LOW | `unlock.rs`, `lifecycle.rs` | Непроверенное чтение мета до проверки MAC (TOCTOU) | MEDIUM |
| L-09 | LOW | разное | Мёртвый код и лишние зависимости | HIGH |
| L-10 | LOW | `auth/fido2.rs` | Заявление «UV из подписанных authData» не подкреплено: подпись не проверяется, `public_key` хранит весь authData | HIGH |
| L-11 | LOW | FFI | Ссылки на версионированные структуры ответа крупнее выделенных ОС (UB на старых сборках Windows) | MEDIUM |
| L-12 | LOW | память | Массовая расшифровка в health check; незануляемые строки PIN/CSV; argon2 без `zeroize` | HIGH |
| L-13 | LOW | `backup.rs`, `records_db.rs` | Ретенция 3 копии + автобэкап при входе + тихое создание пустой `web.db` | MEDIUM |
| L-14 | LOW | документация, UI | Завышенные и противоречивые заявления (см. §17) | HIGH |
| I-01 | INFO | Windows Hello | Второй фактор Hello — политика, не ключевой материал | HIGH |
| I-02 | INFO | TPM / DS | TPM-ключ подписывает без жеста; не привязан к личности Windows; 11-значный PIN перебираем крупным противником | MEDIUM |
| I-03 | INFO | WebAuthn | RP ID `vaultisor.app` — нужен домен под контролем владельца | MEDIUM |
| I-04 | INFO | Recovery | Устройство + одна доля = полный захват хранилища | HIGH |
| I-05 | INFO | RAM | `panic = "abort"` пропускает Drop-зануление; `EncryptedMemoryBuffer` молча хранит plaintext при сбое API | HIGH |
| I-06 | INFO | зависимости | Транзитивные unmaintained-крейты (`proc-macro-error`, `unic-*`), `glib` unsound — вне целевой платформы | HIGH |

---

## 7. Детальные находки

### H-01 / Откат неудачного `vault_create` удаляет существующее хранилище

**Severity:** HIGH
**Component:** `src-tauri/src/commands/vault/create.rs`

**Evidence**
- `vault_create` (строка 34): при **любой** ошибке `vault_create_inner` безусловно вызывается `rollback_partial_vault(&state)` (строка 47).
- `rollback_partial_vault` (строка 57) открывает `vault.meta.db`, удаляет TPM-ключ Device Secret (`cng_hello::delete`, строка 72) и ключ Hello (`delete_best_effort`), затем удаляет `vault.meta.db`, `vault.records.db`, `vault.web.db` (строка 78), rollback-якорь и внешний checkpoint.
- Проверки, которые дают ошибку **до** или **вместо** создания: `validate_secret_format` (строка 98) и `if db.vault_initialized()` → `BadInput("Хранилище уже создано")` (строка 101).

**Description.** Откат не отличает «мы начали создавать и упали» от «мы отказались создавать, потому что хранилище уже есть». Ошибка валидации PIN или сама проверка «хранилище уже существует» приводят к удалению чужого — то есть уже существующего — хранилища вместе с его аппаратными ключами.

**Attack scenario**
1. Хранилище существует и заперто (соединения с БД закрыты, файлы удаляемы).
2. Код в webview (скомпрометированная npm-зависимость фронтенда) вызывает `invoke("vault_create", {input:{pin:"", use_windows_hello:false}})`.
3. `validate_secret_format("")` → ошибка → `rollback_partial_vault` удаляет все три БД, якоря и `NCryptDeleteKey` для TPM-ключа DS.

Бытовой сценарий без атакующего: `vault_exists` возвращает `false`, если **отсутствует `records.db`** (`system.rs:41`), при этом `vault.meta.db` и `vault.web.db` на месте. Пользователь видит онбординг, вводит PIN, `vault_create` натыкается на `vault_initialized() == true`, и откат удаляет мета (с обёрткой MK, конвертом восстановления, FIDO2-конвертами) **и `web.db`** с паролями сайтов, плюс TPM-ключ, без которого не развернуть обёртку MK ни из одного бэкапа этого ПК.

**Preconditions:** возможность вызвать IPC (скомпрометированный фронтенд) **или** отсутствие одного `records.db` при наличии остальных файлов.

**Impact:** необратимое удаление хранилища и аппаратного ключа DS; бэкапы после этого открываются только парой долей B+C (см. M-03).

**Why existing protections do not stop it.** Команда не требует сессии (по смыслу онбординга); `auth_flow` только сериализует вызовы; файлы при запертом хранилище не удерживаются открытыми, поэтому Windows их удаляет; доли восстановления бесполезны без удалённого `vault.meta.db`, где лежит конверт.

**Recommended remediation.** Выполнять откат только для артефактов, созданных *этим* вызовом: завести флаг «мы создали мета-БД» (или создавать всё во временном каталоге и атомарно переименовывать в `vault/` в конце). Проверку «уже существует» выполнять до любых побочных эффектов и возвращать ошибку **без** отката. `vault_exists` должна отличать «пусто» от «частично» и в частичном состоянии не вести в онбординг.

**Regression tests.** (1) Существующее хранилище + `vault_create` с неверным PIN → все файлы и TPM-ключ на месте. (2) То же с корректным PIN → ошибка «уже создано», файлы на месте. (3) Сбой на каждом шаге создания → удаляется только созданное этим вызовом. (4) `vault_exists` при отсутствии одного из файлов → отдельный статус, не онбординг.

**Confidence:** HIGH (прямое чтение кода; путь без ветвлений).

---

### H-02 / Смена типа существующего поля без повторного ввода значения уничтожает значение

**Severity:** HIGH
**Component:** `src-tauri/src/storage/records/crud.rs` (`update_record`), `src/screens/RecordEdit.tsx`

**Evidence**
- AAD значения включает тип поля: `field_aad(record_id, field_id, ft)` → `vaultisor:field:{rec}:{field}:{type}` (`records/mod.rs:114`).
- В `update_record` ветка «значение не передано» (строка 512) выполняет `UPDATE fields SET field_type = ?2, label = ?3, …` **без перешифрования** `value_blob`.
- Фронтенд: `FieldTypeBadge onChange → updateField({field_type})` (`RecordEdit.tsx:349`); при сохранении нетронутое поле уходит как `value: null` (`recordDraft.ts`, `fieldSaveValue`), включая автоматически раскрытые несекретные поля.
- **Воспроизведено** пробным тестом: создать поле `secret`, обновить с `value: None` и `field_type: Api` → `reveal_field` возвращает `Err("Ошибка криптографии: aead-failure")`.

**Description.** Шифротекст запечатан с AAD старого типа, а в строке теперь новый тип; расшифровка навсегда падает на проверке тега. Логика «null = не менять» и «тип входит в AAD» по отдельности верны, их композиция разрушительна.

**Attack scenario** (ошибка обычного использования): пользователь открывает запись, меняет бейдж типа поля «Секрет» → «API» (не раскрывая значение) и сохраняет. Значение потеряно без предупреждения; в интерфейсе при попытке показать — «ошибка расшифровки».

**Preconditions:** одно действие в штатном UI.

**Impact:** необратимая потеря значения поля (восстановимо только из бэкапа, если он старше изменения и не вытеснен ретенцией — L-13).

**Why existing protections do not stop it.** Тест `update_with_value_none_preserves_secret` проверяет только сохранение значения **при неизменном типе**. Бэкенд не проверяет, что тип меняется вместе с перешифрованием.

**Recommended remediation.** В ветке «значение не передано» при изменении `field_type` расшифровать старое значение со старым AAD и зашифровать с новым в той же транзакции; либо запретить смену типа без нового значения (ошибка `BadInput`). Проверять расшифровку перед `COMMIT`.

**Regression tests.** (1) Смена типа с `value: None` → значение читается под новым типом. (2) Смена типа с новым значением → новое значение. (3) Смена типа у повреждённого blob → ошибка без записи. (4) Frontend-тест: смена бейджа нераскрытого поля не приводит к потере.

**Confidence:** HIGH (воспроизведено исполняемым тестом).

---

### H-03 / Изменение политики безопасности без повторной аутентификации

**Severity:** HIGH
**Component:** `src-tauri/src/commands/settings.rs`, `src-tauri/src/commands/recovery.rs`, `src-tauri/src/commands/backup.rs`, `src-tauri/src/commands/vault/io.rs`

**Evidence**
- `settings_update` (`settings.rs:42`): выключение `require_auth_for_copy` и `use_windows_hello` не требует ни Hello, ни PIN (единственная проверка — `new_require_auth && !new_hello`, строка 62). UI даёт это обычным переключателем (`SettingsSecurity.tsx:162–178`).
- `register_fido2_key` (`settings.rs:339`) привязывает **любой** ключ в любом режиме, включая touch-only, без подтверждения владельцем хранилища.
- `recovery_regenerate` (`recovery.rs:503`) возвращает новые доли B и C в webview без повторной аутентификации; `recovery_disable` (`recovery.rs:551`) отзывает восстановление.
- `unbind_fido2_key`, `backup_set_config` (перенаправление автобэкапа), `vault_export` — тоже без повторной аутентификации и без step-up.
- Step-up `require_copy_view_auth` применяется только к reveal/copy/update/history (`records.rs`, `clipboard.rs`).

**Description.** «Подтверждение Windows Hello для копирования и просмотра» задумано против человека, получившего доступ к уже разблокированному хранилищу. Но тот же человек может: выключить подтверждение и читать всё; либо оставить себе постоянный доступ — привязать свой touch-only ключ или сфотографировать перевыпущенные доли B и C.

**Attack scenario**
1. Владелец отходит от ПК; хранилище разблокировано (автоблокировка по умолчанию 5 минут, Win+L не нажат).
2. Посетитель открывает «Настройки → Безопасность», выключает «Подтверждение для копирования» — и раскрывает все секреты.
3. Для долговременного доступа: «Привязать FIDO2-ключ» → свой YubiKey в режиме Touch-only (15 секунд) **или** «Перевыпустить доли» → фото B и C с экрана.
4. Позже: касание своего ключа открывает хранилище (в любой сессии этого пользователя, а с копией `vault.meta.db` — на любой машине, H-04); либо B + C + копия мета → MK. Смена PIN владельцем доступ не отзывает (M-04).

**Preconditions:** несколько десятков секунд у разблокированного хранилища; для ключа — собственный FIDO2-токен.

**Impact:** раскрытие всех секретов в обход step-up; постоянный скрытый доступ, переживающий смену PIN.

**Why existing protections do not stop it.** Проверки ограничиваются «сессия разблокирована и не простаивает». Нет re-auth для операций, меняющих набор факторов или политику. Привязка ключа требует assertion только от **нового** ключа.

**Recommended remediation.** Ввести явный класс «операции с политикой безопасности» (включение/отключение Hello и step-up, привязка/отвязка ключа, перевыпуск/отключение recovery, экспорт, смена каталога бэкапа, restore) и требовать для него свежую повторную аутентификацию в backend: PIN (Argon2) и, если включён, Hello — независимо от окна доверия 60 с. Отключение защитной настройки защищать строже, чем включение. Показывать в интерфейсе журнал изменений факторов.

**Regression tests.** Для каждой команды класса: вызов без свежей re-auth → отказ; с re-auth → успех; истечение окна → отказ; отключение `require_auth_for_copy` без Hello → отказ.

**Confidence:** HIGH.

---

### H-04 / FIDO2-путь не привязан к устройству: touch-only токен + копия мета = MK где угодно

**Severity:** HIGH
**Component:** `src-tauri/src/commands/settings.rs:420–433`, `src-tauri/src/commands/vault/lifecycle.rs:61`, `src-tauri/src/auth/fido2.rs`

**Evidence**
- При привязке: `KEK = HKDF(PRF)`, `fido2_blob = AES-GCM(KEK, MK, "vaultisor:fido2-wrap:v2")`, сохраняется **как есть** в `fido2_keys.fido2_wrapped_key` открытой SQLite (`add_fido2_key`). DPAPI-слоя, как у PIN-обёртки, нет.
- PRF — CTAP2 hmac-secret с **фиксированной** солью (`PRF_SALT`, `fido2.rs:74`) в raw-режиме (`HMAC_SECRET_VALUES_FLAG`), RP ID `vaultisor.app`; обе константы находятся в бинаре.
- `vault_unlock_with_fido2` не проверяет ни PIN, ни `use_windows_hello`.
- SECURITY.md п.1: «Без TPM этого устройства и без PIN файлы бесполезны»; п.3: «DPAPI … и Device Secret привязывают данные к паре пользователь + устройство». README 4.0.0: «PIN обязателен всегда».

**Description.** Для touch-only ключа единственное, что нужно для MK, — физический токен и файл мета-БД. Внутри приложения вход проверяет MAC (для этого нужен DPAPI), но это не криптографическая зависимость: офлайн-атакующему приложение не нужно.

**Attack scenario**
1. Портативный сценарий, заявленный как основной: каталог `vault/` на флешке, YubiKey на той же связке ключей. Связка утеряна.
2. Атакующий читает `vault.meta.db` (обычный SQLite): `credential_id`, `fido2_wrapped_key`.
3. Через libfido2/python-fido2 выполняет GetAssertion для RP `vaultisor.app`, allowList = `credential_id`, расширение hmac-secret с солью `PRF_SALT`, без UV; касается токена.
4. `HKDF(PRF) → KEK → MK → HKDF(MK) → ключ SQLCipher` → чтение всех записей; значения полей — по тем же HKDF-субключам из MK.

**Preconditions:** touch-only ключ, привязанный к хранилищу (режим предлагается в UI как «Passwordless 2FA»); копия `vault.meta.db` и `records.db`/`web.db` (флешка, каталог, синхронизированная папка); умеренная квалификация.

**Impact:** полное раскрытие хранилища вне устройства владельца, без PIN, DPAPI и TPM.

**Why existing protections do not stop it.** Защита стоит на DPAPI и TPM в PIN-пути, но FIDO2-конверт — параллельный путь к тому же MK, минуя оба слоя. Бэкапы санитизируются (FIDO2-конверты вырезаются), а живой `vault.meta.db` — нет. Для ключа ПИН + Touch атакующему нужен ПИН токена (у токена свой счётчик попыток) — этот режим такой уязвимости не имеет.

**Recommended remediation.** (а) Обернуть FIDO2-конверт тем же DPAPI-слоем с per-vault энтропией, что и PIN-обёртку (FIDO2-вход станет привязан к устройству и учётке, как утверждает документация); либо (б) явно задокументировать, что FIDO2-путь переносим, и не предлагать touch-only без предупреждения о переносимости. В любом случае исправить README («PIN обязателен всегда»), SECURITY.md п.1/п.3 и название «Passwordless 2FA».

**Regression tests.** (1) Копия мета на другой учётке/машине + корректный PRF → разворот конверта невозможен (после варианта а). (2) Тест, что `fido2_wrapped_key` в БД не является «голым» AES-GCM-blob. (3) Док-тест/линт на отсутствие утверждения «PIN обязателен всегда» при существовании FIDO2-пути.

**Confidence:** MEDIUM. Механизм прямо следует из кода; офлайн-шаг с libfido2 не выполнялся на железе, но опирается на стандартное поведение hmac-secret (Windows в raw-режиме передаёт соль токену без преобразования).

---

### H-05 / Fail-closed состояния без выхода, кроме Shamir, при отключаемом восстановлении

**Severity:** HIGH
**Component:** `commands/vault/unlock.rs:47`, `commands/vault/lifecycle.rs:78, 209`, `storage/meta_db/crud.rs` (якоря), `src/screens/onboarding/StepRecovery.tsx`

**Evidence**
- `failed_pin_attempts >= max_pin_attempts` → `TooManyAttempts` блокирует **все** входы: PIN (`unlock.rs:47`), FIDO2 (`lifecycle.rs:78`), смену PIN (`lifecycle.rs:209`). Сброс возможен только `recovery_restore`. Лимит 3–10 (`settings.rs`, `clamp(3, 10)`), ни задержки, ни backoff.
- `META_TAMPERED` при отсутствии/порче локального якоря или внешнего checkpoint (удаление `%LOCALAPPDATA%\Vaultisor`, сброс профиля, M-06) — выход тоже только через recovery.
- Удалённый в «Параметрах Windows» ключ Hello → вход невозможен, выход через recovery (SECURITY.md п.5).
- Восстановление можно выключить: на онбординге («Завершить без восстановления», «Пропустить» → `recovery_disable`) и в настройках.
- Бэкап после потери живого хранилища тоже требует B+C (M-03).

**Description.** Каждое из этих состояний по отдельности — осознанный fail-closed. Вместе с разрешённым отключением восстановления они превращаются в сценарии **необратимой** потери. Самый доступный триггер — счётчик PIN: любой человек у незаблокированного Windows-сеанса (хранилище при этом заперто) набирает 10 (или 3) произвольных 11-значных PIN.

**Attack scenario**
1. Владелец пропустил восстановление на онбординге (или атакующий из H-03 выключил его в настройках).
2. Коллега у незаблокированного ПК вводит 10 произвольных PIN (~1–2 минуты при Argon2 в несколько секунд).
3. `TOO_MANY_ATTEMPTS`: ни PIN, ни FIDO2, ни смена PIN не работают; recovery: «Для этого хранилища восстановление не настроено». Данные утрачены (кроме бэкапов, которые тоже требуют B+C — M-03).

**Preconditions:** доступ к UI при запертом хранилище; для необратимости — выключенное восстановление.

**Impact:** необратимая потеря доступа (availability).

**Why existing protections do not stop it.** Счётчик защищён MAC и якорем — сбросить его нельзя (это правильно), но и владелец не может. Предупреждения в UI при отключении восстановления не меняют последствий.

**Recommended remediation.** Заменить жёсткую блокировку на экспоненциальную задержку, привязанную к счётчику под MAC (например, 30 с, 1 мин, 5 мин… — последовательный перебор 11-значного PIN всё равно невозможен), либо оставить жёсткий лимит только при включённом восстановлении. Запретить `recovery_disable`, пока нет другого независимого пути (например, FIDO2 ПИН + Touch), или требовать для него re-auth (H-03). Для `META_TAMPERED` из-за отсутствия внешнего checkpoint предусмотреть путь «доказать владение PIN и восстановить checkpoint» с явным предупреждением о риске отката.

**Regression tests.** (1) N неверных попыток → нарастающая задержка, после неё верный PIN открывает. (2) Отключение восстановления без альтернативного фактора → отказ. (3) Удалённый внешний checkpoint + верный PIN → управляемый путь, а не тупик.

**Confidence:** HIGH.

---

### M-01 / Неатомарное восстановление: окно, в котором хранилище становится неоткрываемым по PIN

**Severity:** MEDIUM
**Component:** `src-tauri/src/commands/recovery.rs` (`recovery_restore`, строки 394–455)

**Evidence.** Последовательность независимых фиксаций: `set_integrity_key_and_seal` (397) → `update_wrapped_master` (398, новая обёртка уже под **новым** DS) → `set_dpapi_entropy` (399) → `clear_key_credential` → `update_settings` → `cng_hello::delete(старый TPM-ключ)` (413) → **`clear_recovery`** (420) → `set_failed_attempts` → **`save_device_secret`** (444) → `save_argon2_params`. Каждый вызов — отдельная транзакция + запись якорей.

**Description.** Между строками 420 и 444 в мета: `crypto_version = 2`, имя **уже удалённого** TPM-ключа, обёртка MK под новым DS, чей зашифрованный blob существует только в памяти, конверт восстановления отозван. Сбой питания, аварийное завершение или ошибка ввода-вывода (например, переполненная флешка) в этом окне оставляют хранилище без рабочего PIN-пути и без конверта.

**Attack scenario / failure scenario.** Восстановление на почти заполненном портативном носителе: `set_failed_attempts` или `save_device_secret` падает с «disk full» → ошибка пользователю; при следующем входе `TpmUnavailable`; повторное восстановление — «восстановление не настроено».

**Preconditions:** сбой в узком окне. Выход остаётся только через привязанный FIDO2-ключ (его конверт не трогается) или через импорт бэкапа с наличием **обеих** долей B и C.

**Impact:** потеря доступа (потенциально необратимая).

**Why existing protections do not stop it.** Каждая мутация сама по себе атомарна и подписана, но инвариант «обёртка MK разворачивается хотя бы одним сохранённым путём» между ними не соблюдается. `RestoreTransaction` здесь не используется.

**Recommended remediation.** Выполнить всё в одной транзакции SQLite (один `BEGIN IMMEDIATE`, одна эпоха, один MAC, один якорь); удалять старый TPM-ключ и ключ Hello только **после** `COMMIT`; новый TPM-ключ удалять при ошибке до `COMMIT`.

**Regression tests.** Fault injection: ошибка после каждого шага → хранилище открывается либо старым путём (конверт цел), либо новым PIN; никогда — ни тем, ни другим.

**Confidence:** HIGH (код), вероятность срабатывания низкая.

---

### M-02 / Restore молча откатывает политику безопасности

**Severity:** MEDIUM
**Component:** `src-tauri/src/commands/vault/io.rs:335` (`vault_restore_blocking`), `src-tauri/src/commands/backup.rs:344` (санитизация)

**Evidence.** Санитизация бэкапа удаляет `fido2_keys` и `recovery_local`, выставляет `use_windows_hello = 0`, `require_auth_for_copy = 0` (`backup.rs:364–373`), но сохраняет `wrapped_master_key` и `recovery_wrapped_master` с поколением. Restore проверяет MAC под текущим `integrity_key` и тот же `checkpoint_id`, после чего ставит якорь на **эпоху снимка** (`io.rs:416`).

**Description.** Штатный restore «вчерашней копии, чтобы вернуть удалённую запись» одновременно: возвращает PIN, действовавший на момент копии; возвращает **отозванное** поколение долей (а текущие доли перестают подходить); выключает Hello и step-up; отвязывает все FIDO2-ключи; оставляет в Windows осиротевший ключ Hello. Пользователь об этом не уведомляется.

**Attack scenario.** Пользователь перевыпустил доли после утечки старых, затем восстановил недельный автобэкап → старые (скомпрометированные) доли снова открывают хранилище; Hello выключен, хотя пользователь считает его включённым.

**Preconditions:** restore из копии, сделанной до изменения факторов.

**Impact:** тихое понижение защиты; риск блокировки, если пользователь не помнит старый PIN и уже уничтожил старые доли.

**Why existing protections do not stop it.** Anti-rollback намеренно допускает «авторизованный» откат, а санитизация проектировалась для переноса, а не для restore на месте.

**Recommended remediation.** При restore на том же устройстве переносить **текущие** факторы и поколение восстановления из живой мета поверх данных снимка (или восстанавливать только `records.db`/`web.db`). Если сохранить нельзя — показывать явный список того, что изменится, и требовать подтверждения.

**Regression tests.** Restore копии, сделанной до смены PIN/перевыпуска долей/включения Hello → действуют текущие PIN, доли, Hello.

**Confidence:** HIGH.

---

### M-03 / Бэкап бесполезен без обеих долей B и C после потери живого хранилища

**Severity:** MEDIUM
**Component:** `commands/vault/io.rs:122` (`vault_import_blocking`), `storage/meta_db/crud.rs:309` (`verify_rollback_anchor`)

**Evidence.** `vault_import` кладёт санитизированный снимок без якорей. При разблокировке `verify_rollback_anchor` требует внешний checkpoint: на новой машине его нет → `META_TAMPERED`; на той же машине он есть с эпохой ≥ эпохи снимка и другим MAC (санитизация) → `META_TAMPERED`. Доля A из снимка вырезана → восстановление требует B **и** C.

**Description.** «Бэкап + PIN» работает только через `vault_restore`, то есть при живом разблокированном хранилище. Если хранилище утрачено (диск, флешка, удалённый каталог), даже на исходном ПК с верным PIN нужны обе пользовательские доли.

**Failure scenario.** Владелец хранит только долю C на бумаге (B потеряна). Флешка с хранилищем сломалась; есть свежий автобэкап. Импорт → `META_TAMPERED` → восстановление требует двух долей → данные недоступны.

**Preconditions:** утрата живого хранилища и одной из долей B/C.

**Impact:** потеря доступа при наличии бэкапа и знании PIN.

**Why existing protections do not stop it.** Anti-rollback не отличает импорт от отката, а санитизация убирает долю A.

**Recommended remediation.** Для импорта на **том же** ПК (DPAPI и TPM-ключ снимка разворачиваются) разрешить вход по PIN с переустановкой якоря после явного подтверждения; задокументировать, что для другого ПК нужны B+C. Альтернатива — не вырезать долю A (она всё равно под DPAPI этой учётки).

**Regression tests.** Импорт на той же машине + верный PIN → управляемый вход; на другой машине → recovery B+C.

**Confidence:** HIGH.

---

### M-04 / Мастер-ключ не ротируется — отзыв долей и PIN неполный

**Severity:** MEDIUM
**Component:** криптомодель (`crypto/master.rs`, `commands/recovery.rs:21`, `lifecycle.rs:194`)

**Evidence.** MK создаётся один раз (`generate_master_key`) и никогда не меняется: `recovery_regenerate` заменяет только конверт (новый RK), `vault_change_pin` — только обёртку, отвязка FIDO2 — только строку. Любая историческая копия `vault.meta.db` или бэкап содержит конверт своего поколения и обёртку своего PIN.

**Description.** «Старые поколения отзываются после регенерации» (README) верно только относительно **текущего** файла мета. Скомпрометированные старые доли B+C вместе с любым старым бэкапом дают тот же MK, которым зашифрованы сегодняшние данные.

**Attack scenario.** Доли B и C утекли; пользователь перевыпустил доли. У атакующего есть старый автобэкап из облачной папки (или копия флешки). Старые B+C + старый конверт → MK → текущий `records.db` (ключ SQLCipher = HKDF(MK)).

**Preconditions:** скомпрометированный старый фактор + любая историческая копия мета и текущие данные.

**Impact:** отзыв факторов не защищает от противника с историческими артефактами.

**Why existing protections do not stop it.** Поколение в AAD защищает от подстановки конверта в **текущую** мета, но не от использования старого конверта для получения того же MK.

**Recommended remediation.** Операция «ротация MK»: новый MK, перешифрование БД (`PRAGMA rekey`) и значений полей, новые обёртки, новое поколение долей; предлагать её при перевыпуске долей и отвязке ключа по причине утраты. Документировать ограничение до её появления.

**Regression tests.** После ротации: старый конверт + старые доли не открывают текущие БД; старый PIN + старая обёртка — тоже.

**Confidence:** HIGH.

---

### M-05 / Откат и сращивание страниц `records.db`/`web.db` не обнаруживаются

**Severity:** MEDIUM
**Component:** `src-tauri/src/storage/records_db.rs`, anti-rollback (`meta_db/crud.rs`)

**Evidence.** Якоря и эпоха покрывают только `vault.meta.db`. В мета нет ни версии, ни хеша БД записей. SQLCipher аутентифицирует каждую страницу по отдельности (ключ и соль файла одни и те же во всех версиях), поэтому целиком старая копия файла открывается, а страницы разных версий одного файла взаимозаменяемы.

**Description.** Замена `vault.records.db` старой копией возвращает удалённые секреты и старые значения повернутых ключей без какого-либо сигнала. Сращивание страниц позволяет точечно вернуть старое значение отдельного поля (значение остаётся валидным AES-GCM под своим AAD).

**Attack scenario.** Держатель флешки (противник K) подменяет `vault.records.db` вчерашней копией: пользователь видит старый API-ключ, «ротированный» сегодня, и снова раздаёт его.

**Preconditions:** запись в каталог `vault/`, старая копия файла.

**Impact:** нарушение целостности и свежести данных.

**Why existing protections do not stop it.** SECURITY.md заявляет защиту от «отката к старому снимку», но механизм реализован только для мета.

**Recommended remediation.** Вести в records-БД монотонный счётчик ревизий (обновляется в каждой пишущей транзакции) и хранить его последнее значение в мета под MAC (или в якоре); при открытии требовать равенства. Для защиты от сращивания — хеш-дерево значимых таблиц или MAC строк с номером ревизии.

**Regression tests.** Подмена `records.db` старой копией → отказ при разблокировке; сращивание страницы поля → обнаружение.

**Confidence:** HIGH.

---

### M-06 / Локальный rollback-якорь пишется неатомарно

**Severity:** MEDIUM
**Component:** `src-tauri/src/storage/meta_db/crud.rs:279` (`write_rollback_anchor`)

**Evidence.** `OpenOptions::new().create(true).truncate(true).write(true)` → `write_all` → `sync_all` (строки 295–301). Внешний checkpoint при этом пишется через временный файл и `MoveFileExW(WRITE_THROUGH)`.

**Description.** Якорь переписывается при **каждой** защищённой мутации — в том числе при каждом неверном PIN и каждом успешном входе (`set_failed_attempts`). Сбой питания между усечением и записью оставляет файл пустым или частичным; `verify_checkpoint_data` видит длину ≠ 72 → `META_TAMPERED` → только recovery (а при выключенном — H-05).

**Failure scenario.** Ноутбук разряжается на экране входа сразу после ввода PIN.

**Preconditions:** сбой питания в миллисекундном окне; вероятность низкая, частота операций высокая.

**Impact:** блокировка хранилища.

**Why existing protections do not stop it.** `sync_all` делает запись долговечной, но не атомарной.

**Recommended remediation.** Писать якорь так же, как внешний checkpoint: временный файл → `sync_all` → `durable_replace`.

**Regression tests.** Симуляция: якорь нулевой длины/частичный после «сбоя» между шагами → при атомарной записи остаётся старый или новый валидный якорь.

**Confidence:** HIGH.

---

### M-07 / Импорт CSV молча теряет записи и затем предлагает затереть исходник

**Severity:** MEDIUM
**Component:** `src-tauri/src/commands/import.rs:318, 338`; `src/screens/settings/SettingsBackup.tsx:105–125`

**Evidence.** URL целиком кладётся в `project` (строка 318); `create_record` отвергает `project` длиннее 256 байт (`crud.rs:266`); ошибка проглатывается `if let Ok(rec_id) = created` (строка 338). Ответ содержит только число импортированных, без общего; интерфейс сразу предлагает «Удалить и затереть файл». **Воспроизведено**: запись с URL > 256 символов → `Err("project too long (max 256)")`.

**Description.** Экспорт Chrome содержит длинные URL входа (с параметрами запроса) у многих сайтов. Такие пароли не импортируются, пользователь этого не видит и уничтожает единственную копию.

**Failure scenario.** Импорт 300 паролей, из них 40 с длинными URL → «Импортировано записей: 260» → «Удалить и затереть файл» → 40 паролей утрачены.

**Preconditions:** обычный CSV-экспорт браузера.

**Impact:** потеря данных.

**Why existing protections do not stop it.** Проверки длины сделаны для защиты от злоупотребления из webview и не учитывают внутренний источник данных; ошибки не агрегируются.

**Recommended remediation.** Урезать/нормализовать URL до допустимой длины (или хранить полный URL в зашифрованном поле, а в `project` — домен); возвращать `total`, `imported`, список отклонённых с причиной; не выдавать токен удаления, если `imported < total`.

**Regression tests.** CSV с длинным URL импортируется полностью; при частичном импорте токен удаления не выдаётся.

**Confidence:** HIGH (воспроизведено).

---

### M-08 / `vault_change_pin` работает без сессии и открывает её в обход Windows Hello

**Severity:** MEDIUM
**Component:** `src-tauri/src/commands/vault/lifecycle.rs:194–272`

**Evidence.** Команда не проверяет, что хранилище разблокировано; проверяет MAC, счётчик и старый PIN, затем вызывает `open_session` (строка 271). Проверки `meta.use_windows_hello` нет — в отличие от `vault_unlock` (`unlock.rs:105`).

**Description.** Это третий путь «PIN → сессия», в котором второй фактор не участвует.

**Attack scenario.** Скомпрометированный фронтенд рисует поддельный экран PIN, получает PIN и вызывает `vault_change_pin(pin, pin2)` — сессия открыта без Hello. Затем читает записи (при `require_auth_for_copy` — сначала выключает его, H-03).

**Preconditions:** возможность вызывать IPC + знание PIN.

**Impact:** обход второго фактора; смена PIN владельца.

**Why existing protections do not stop it.** Проверка Hello есть только в `vault_unlock`. Ценность ограничена: противник с кодом под пользователем обходит Hello и без этого (I-01).

**Recommended remediation.** Требовать разблокированную сессию (смена PIN — операция из настроек) и свежую re-auth по H-03; не открывать сессию заново, а переиспользовать текущую.

**Regression tests.** `vault_change_pin` при запертом хранилище → `Locked`; при включённом Hello без свежей проверки → отказ.

**Confidence:** HIGH.

---

### M-09 / Релизный пайплайн: широкий токен, нет provenance, невоспроизводимые установки

**Severity:** MEDIUM
**Component:** `.github/workflows/release.yml`, `ci.yml`, `audit.yml`, `build.ps1`

**Evidence**
- `release.yml`: job `build-and-release` имеет `permissions: contents: write` на весь job; `actions/checkout` без `persist-credentials: false` (токен сохраняется в `.git/config`); в том же job `npm install` (исполняет install-скрипты зависимостей) и сборка.
- `npm install` вместо `npm ci` во всех workflow (`ci.yml:18, 40`, `audit.yml:36`, `release.yml:46`).
- `ci.yml` и `audit.yml` без top-level `permissions` — права токена определяются настройкой репозитория.
- `SHA256SUMS.txt` создаётся в том же job; attestation/provenance нет; Authenticode нет.
- `.github/release_notes.md` — текст v3.1.0, публикуется для каждого релиза.
- `dtolnay/rust-toolchain@… # stable` — версия компилятора не зафиксирована.

**Description.** Компрометация любой npm-зависимости (включая dev) даёт код, исполняющийся в job с токеном, способным перезаписать релиз и `SHA256SUMS.txt`. Пользователь не может отличить бинарь из CI от подменённого.

**Attack scenario.** Вредоносная версия транзитивной dev-зависимости в `postinstall` читает токен из `.git/config`, после сборки подменяет артефакт и хеш через REST API.

**Preconditions:** компрометация npm-пакета.

**Impact:** распространение вредоносного бинаря под видом релиза.

**Why existing protections do not stop it.** Пины Actions по SHA защищают сами Actions, но не пакеты, устанавливаемые внутри job; `npm audit` видит только известные уязвимости.

**Recommended remediation.** Разделить сборку (`contents: read`, `npm ci --ignore-scripts` где возможно, `persist-credentials: false`) и публикацию (отдельный job, только скачивает артефакт, `contents: write`); добавить `actions/attest-build-provenance`; top-level `permissions: contents: read` во всех workflow; зафиксировать версию Rust (`rust-toolchain.toml`); генерировать release notes из changelog текущей версии.

**Regression tests.** Проверка workflow линтером (zizmor/actionlint) в CI; тест на соответствие версии в release notes.

**Confidence:** HIGH.

---

### L-01 / Неограниченные параметры Argon2 из заголовка VLT4

**Severity:** LOW · **Component:** `commands/vault/io.rs:276`, `core-shared/src/kdf.rs:216`
**Evidence:** `Argon2Params::from_stored(read_u32(4), read_u32(8), read_u32(12))` без верхних границ; вызов под глобальным мьютексом `ARGON2_SINGLE_FLIGHT`.
**Description / Attack scenario:** злонамеренный `.vault` с `t_cost = 0xFFFFFFFF` занимает мьютекс на годы — все последующие разблокировки висят до перезапуска; `m_cost` в терабайтах → отказ выделения памяти и аварийное завершение (`panic = "abort"`).
**Preconditions:** пользователь выбирает подложенный файл для импорта/restore. **Impact:** DoS.
**Why not stopped:** проверяется только «не ноль». **Remediation:** принимать параметры только в диапазоне [минимум сборки … разумный максимум, напр. 2 ГиБ, t ≤ 20, p ≤ 16]; то же для мета. **Tests:** заголовок с экстремальными параметрами → `BadInput` без вычисления.
**Confidence:** HIGH.

### L-02 / Устаревшие SQLCipher/SQLite и разбор недоверенных БД

**Severity:** LOW · **Component:** `Cargo.lock` (`rusqlite 0.32.1`, `libsqlite3-sys 0.30.1` → SQLite 3.45.3, SQLCipher 4.5.7), `io.rs:218`
**Description:** импорт и restore открывают БД из недоверенного файла; `trusted_schema` и `SQLITE_DBCONFIG_DEFENSIVE` не настроены, генерируемые столбцы/представления схемы атакующего исполняются при чтении. После 3.45.3 в SQLite исправлен ряд ошибок повреждения памяти (в т.ч. CVE-2025-6965, CVE-2025-29087/29088). `cargo audit`/`cargo deny` не видят уязвимостей в вендорированном C-коде.
**Attack scenario:** специально построенная мета-БД в бэкапе провоцирует ошибку SQLite при импорте. **Preconditions:** рабочий эксплойт конкретной ошибки (предположение). **Impact:** от аварии до исполнения кода (теоретически).
**Remediation:** обновить `rusqlite`/SQLCipher; для недоверенных файлов `PRAGMA trusted_schema=OFF`, `SQLITE_DBCONFIG_DEFENSIVE`, проверка схемы на точное совпадение с эталоном до любых запросов; отслеживать версии C-библиотек в SDLC.
**Tests:** БД с лишними объектами схемы (VIEW, TRIGGER, generated column) отвергается. **Confidence:** MEDIUM (реальная эксплуатируемость не проверялась).

### L-03 / Ленивая автоблокировка и продление простоя в `recovery_disable`

**Severity:** LOW · **Component:** `state.rs:216`, `recovery.rs:552`, `useIdleAutolock.ts`
**Description:** простой проверяется только при входящем IPC; таймера в backend нет — если webview завис или упал, MK остаётся в памяти неограниченно. `recovery_disable` вызывает `touch()` без `check_autolock()` — просроченная сессия «оживает» и выполняет отзыв восстановления. Движение мыши над окном считается активностью.
**Preconditions:** зависание фронтенда / вызов IPC. **Impact:** удлинение окна компрометации памяти и «обеденного» доступа.
**Remediation:** фоновый таймер в backend, вызывающий `check_autolock()`; единый обёрточный guard для всех команд (сначала автоблокировка, потом `touch`). **Tests:** сессия блокируется без IPC-вызовов; `recovery_disable` после истечения → `Locked`. **Confidence:** HIGH.

### L-04 / Блокировка по сну/завершению сеанса не срабатывает

**Severity:** LOW · **Component:** `windows_api/session.rs:69`
**Description:** окно наблюдателя создано как message-only (`HWND_MESSAGE`); `WM_POWERBROADCAST` и `WM_ENDSESSION` рассылаются только окнам верхнего уровня и до него не доходят. Блокировка при засыпании держится только на том, что Windows при пробуждении блокирует сеанс. Тест проверяет лишь таблицу соответствия сообщений.
**Remediation:** `RegisterSuspendResumeNotification` / скрытое окно верхнего уровня. **Tests:** ручной тест сна с отключённым «требовать вход при пробуждении». **Confidence:** MEDIUM.

### L-05 / `generator_copy` в обход step-up

**Severity:** LOW · **Component:** `commands/generator.rs:124`
**Description:** копирование выданных генератором секретов не проходит `require_copy_view_auth`, в отличие от копирования полей. Эти значения обычно тут же становятся реальными паролями.
**Remediation:** добавить гейт. **Tests:** при `require_auth_for_copy` без Hello → отказ. **Confidence:** HIGH.

### L-06 / Fail-open буфера обмена

**Severity:** LOW · **Component:** `windows_api/clipboard.rs:246–257`
**Description:** `CF_UNICODETEXT` ставится до маркеров исключения; если `put_format` падает, функция возвращает ошибку, но буфер закрывается уже с секретом, без маркеров (попадёт в историю Win+V/облако), а таймер очистки не взводится (последовательность не сохранена).
**Remediation:** при ошибке маркера — `EmptyClipboard()` до закрытия. **Tests:** инъекция ошибки `RegisterClipboardFormatW` → буфер пуст. **Confidence:** HIGH.

### L-07 / `recovery_restore` не закрывает живую сессию

**Severity:** LOW · **Component:** `commands/recovery.rs:192`
**Description:** восстановление ротирует `integrity_key` в БД, а открытая сессия продолжает писать мета старым ключом; следующая разблокировка — `META_TAMPERED`, а конверт восстановления уже отозван. В UI путь восстановления доступен только с экрана блокировки, поэтому достижимо через IPC.
**Remediation:** `state.lock()` в начале `recovery_restore`. **Tests:** восстановление при открытой сессии → сессия закрыта, последующие записи отвергаются. **Confidence:** HIGH.

### L-08 / Непроверенное чтение мета до проверки MAC (TOCTOU)

**Severity:** LOW · **Component:** `unlock.rs:32–43`, `lifecycle.rs:64–76`
**Description:** решения (лимит попыток, параметры Argon2, `use_windows_hello`, список FIDO2-ключей) принимаются по строке, прочитанной **до** `verify_meta_integrity`, отдельным запросом. Процесс того же пользователя может подменить строку между чтениями. Практической выгоды мало (этот противник и так перебирает офлайн), но инвариант «решение по проверенным данным» нарушен.
**Remediation:** читать и проверять MAC одним запросом в одной транзакции и использовать ровно проверенную структуру. **Tests:** не требуется динамически; юнит-тест на API, возвращающий только проверенную строку. **Confidence:** MEDIUM.

### L-09 / Мёртвый код и лишние зависимости

**Severity:** LOW · **Component:** разное
**Evidence:** `cng_hello::sign`, `sign_blocking` (вызывается только из теста) и вся цепочка `hello::verify_with_window*` — путь «Hello-жест перед TPM-подписью» не используется; заголовочный комментарий `cng_hello.rs` описывает несуществующую архитектуру. FIDO2-ветки API v1/v4 без PRF (`fido2.rs:520, 566`) заведомо не дают PRF → вход отвергается. Ветка `recovery_restore` с `vault_create` для неинициализированной мета недостижима (раньше требуется `recovery_meta`). `Argon2Params::from_stored` трактует нули как «старые записи». Неиспользуемые зависимости: `rand_chacha` (в обоих крейтах), `anyhow` (только `From`), `tauri-plugin-fs` (зарегистрирован, прав нет), в `core-shared` — `serde_json`, `base64`, `subtle`, `hmac`. Устаревшие комментарии: `Cargo.toml` («WinRT остаётся для restricted migration старых CNG Hello vaults»), `storage/mod.rs` и `meta_db/mod.rs` (`pin_hash`), `records_db.rs` («cascade unlock через Hello+TPM»), `rng.rs` (WASM).
**Impact:** поверхность атаки и ложное представление об архитектуре. **Remediation:** удалить. **Tests:** `cargo machete`/`cargo udeps` в CI. **Confidence:** HIGH.

### L-10 / «UV из подписанных authData» — не проверяется подпись

**Severity:** LOW · **Component:** `auth/fido2.rs:31–34, 639–655`, `settings.rs` (сохранение `public_key`)
**Description:** политика ПИН + Touch опирается на бит UV из authData, но подпись assertion не проверяется; в поле `public_key` сохраняется **весь** authenticatorData регистрации, COSE-ключ не извлекается. Реальная криптографическая опора — различие CredRandom с UV и без UV в hmac-secret (CTAP 2.1); для токенов, где этого различия нет, требование ПИН — только проверка непроверенного флага. Для противника вне процесса это не обходится, но заявление «подделать нельзя» в коде и SECURITY.md завышено.
**Remediation:** извлекать COSE-ключ при регистрации и проверять подпись assertion (как уже сделано для Hello), либо исправить формулировки. **Tests:** assertion с изменённым флагом UV отвергается. **Confidence:** HIGH.

### L-11 / FFI: ссылки на структуры ответа крупнее выделенных ОС

**Severity:** LOW · **Component:** `auth/fido2.rs:295, 638`
**Description:** `&*p_attestation` (тип V5) и `&*p_assertion` (V3) создают Rust-ссылку на полный размер структуры до проверки `dwVersion`; на сборке Windows, возвращающей более раннюю версию, это неопределённое поведение (чтение за пределами выделения). Поля старших версий читаются только после проверки версии — корректно. Окно родителя — `GetForegroundWindow()` (может принадлежать другому приложению).
**Remediation:** читать `dwVersion` через сырой указатель (`addr_of!`), затем приводить к нужной версии; передавать HWND главного окна. **Tests:** layout-тесты уже есть; добавить тест на минимальную версию. **Confidence:** MEDIUM.

### L-12 / Гигиена секретов в памяти

**Severity:** LOW · **Component:** `storage/records/crud.rs:108–172`, `commands/import.rs`, `core-shared/Cargo.toml`
**Description:** health check расшифровывает **все** секретные поля обеих БД на каждый `record_list` (включая каждый символ поиска) — многократное появление всего набора паролей в куче. PIN приходит `String` в структурах IPC и не зануляется; CSV-разбор создаёт незануляемые `Vec<Vec<String>>` с паролями; `secure_delete_authorized_file` держит содержимое CSV в незануляемом `Vec`. `argon2` собран без фичи `zeroize` (512 МиБ блоков остаются до возврата страниц ОС; могут попасть в pagefile). SQLCipher-ключ и `integrity_key` открыты всю сессию; `VirtualLock` не используется.
**Remediation:** кэшировать результаты health check по ревизии БД; `Zeroizing<String>` в IPC-структурах через `#[serde(deserialize_with)]`; фича `argon2/zeroize`. **Tests:** не динамические; ревью. **Confidence:** HIGH.

### L-13 / Ретенция бэкапов и тихое создание пустой `web.db`

**Severity:** LOW · **Component:** `commands/backup.rs:25, 392`, `storage/records_db.rs:65`
**Description:** хранятся 3 последние копии, автобэкап идёт при входе. Если `vault.web.db` пропал, `RecordsDb::open` молча создаёт пустую БД, и три входа подряд вытесняют все копии с данными. Любая порча (в т.ч. H-02) распространяется на все копии за три входа.
**Remediation:** не создавать БД записей при разблокировке существующего хранилища (создание только в `vault_create`); ретенция по времени (например, 7 дневных + 4 недельных). **Tests:** отсутствующая `web.db` при разблокировке → ошибка, а не пустая БД. **Confidence:** MEDIUM.

### L-14 / Расхождения документации и интерфейса с кодом

**Severity:** LOW · **Component:** README.md, SECURITY.md, `src/screens/Lock.tsx:96–98`, `.github/release_notes.md`
**Description:** см. §17. Самые значимые: «PIN обязателен всегда» (README 4.0.0), «Без TPM этого устройства и без PIN файлы бесполезны» (SECURITY п.1), «Passwordless 2FA», «домен v9», комментарий в `Lock.tsx` «Hello и FIDO2 — дополнительные факторы, а не альтернатива ему», release notes v3.1.0.
**Remediation:** выверить формулировки по фактической матрице §5. **Tests:** док-тест на ключевые утверждения (по образцу `release.test.ts`). **Confidence:** HIGH.

### I-01 / Второй фактор Hello — политика, а не ключевой материал

**Severity:** INFO · **Component:** `unlock.rs:102–142`, `windows_api/key_credential.rs`
MK выводится только из PIN (+DS); Hello — корректно реализованная проверка WebAuthn-assertion (свой challenge, `rpIdHash`, UP+UV, ES256 через BCrypt, строгий DER). Против человека у интерфейса Hello — реальный барьер; против кода под пользователем — нет (обход офлайн). SECURITY.md это признаёт. Рекомендация: формулировать как «проверка присутствия», не «второй фактор, защищающий ключ».

### I-02 / TPM-ключ Device Secret: подпись без жеста и привязка к машине, а не к личности

**Severity:** INFO · **Component:** `windows_api/cng_hello.rs:115–135`
Ключ Platform KSP создаётся без политики использования; подпись фиксированного challenge доступна любому процессу пользователя (признано). Ключ привязан к TPM машины, а не к учётной записи: при физическом владении ПК без шифрования диска blob ключа из профиля, по всей видимости, загружается в тот же TPM из другой ОС (предположение, зависит от usage auth PCP-ключей). Тогда безопасность хранилища на украденном ПК держится на пароле Windows (DPAPI) и энтропии PIN: 11-значный цифровой PIN — ≈ 36,5 бит; при Argon2id(512 МиБ, t=6) и ~300 хешей/с на GPU полный перебор занимает ~10 GPU-лет (≈ 4 дня на 1000 GPU). Рекомендация: рекомендовать BitLocker и буквенно-цифровой PIN; рассмотреть привязку DS к PCR/политике.

### I-03 / RP ID `vaultisor.app`

**Severity:** INFO · RP ID отображается в «Ключах доступа» Windows и может быть использован сайтом на этом домене для WebAuthn-запросов (PRF-выход браузера захеширован и с конвертом не совпадёт, повтор Hello-assertion невозможен из-за свежего challenge). Использовать домен, контролируемый владельцем продукта.

### I-04 / Устройство + одна доля = захват хранилища

**Severity:** INFO · **Component:** `recovery.rs:221–248`
На том же ПК доля A подгружается автоматически; одна доля B (файл на флешке) плюс доступ к сессии Windows дают новый PIN, сброс счётчика и отключение Hello. Это следствие схемы «A на устройстве»; стоит явно указать пользователю не хранить долю B рядом с ПК/хранилищем.

### I-05 / `panic = "abort"` и молчаливый plaintext в `EncryptedMemoryBuffer`

**Severity:** INFO · `Cargo.toml` (profile.release), `core-shared/src/ram_protect.rs:39–46`
При панике Drop не выполняется (процесс завершается, память возвращается ОС — остаточный риск только через дампы). При сбое `CryptProtectMemory` буфер хранит MK открыто без сигнала. Рекомендация: логировать и считать фатальной ошибкой.

### I-06 / Транзитивные unmaintained/unsound крейты

**Severity:** INFO · `cargo audit`: `proc-macro-error` (RUSTSEC-2024-0370), `unic-*` (RUSTSEC-2025-0075/0080/0081/0098/0100) — build-time зависимости Tauri; `glib` (RUSTSEC-2024-0429) — вне целевой платформы Windows. `deny.toml` задаёт `unmaintained = "workspace"`, поэтому такие крейты не видны в CI — это стоит отражать в отчёте SCA явно.

---

## 8. Криптографический обзор

| Область | Оценка | Обоснование |
|---|---|---|
| RNG | **STRONG** | `OsRng` (BCryptGenRandom) для ключей, солей, nonce, DS, RK, entropy; `thread_rng` только для challenge; фронтенд-генератор — `crypto.getRandomValues` с rejection sampling |
| AES | **STRONG** | RustCrypto `aes-gcm` 0.10.3, AES-256 |
| AEAD | **STRONG** | уникальный ключ на значение (HKDF с солью 128 бит) снимает birthday-bound 96-битных nonce; каждая обёртка MK — свежий KEK (новая соль Argon2); AAD привязывает к записи/полю/типу/поколению. Слабость — композиция с изменяемым типом поля (H-02) |
| HKDF | **STRONG** | RFC 5869 (RustCrypto), раздельные `info` для каждой цели, фиксированные соли по назначению, случайные — для полей |
| Argon2 | **STRONG** / NEEDS HARDENING | Argon2id, 512 МиБ, t=6, p=2, параметры хранятся под MAC и используются при распаковке; single-flight против DoS. Нужно: границы параметров из файлов (L-01), фича `zeroize` |
| SQLCipher | **ACCEPTABLE** | v4, raw 256-битный ключ из HKDF, `secure_delete`, `DELETE`-журнал, `temp_store=MEMORY`; устаревшая версия (L-02), нет защиты от отката (M-05) |
| FIDO2/WebAuthn | **NEEDS HARDENING** | KEK из PRF (не из публичного credential_id) — правильно; allowlist и проверка вернувшегося credential; per-key UV. Но: путь самостоятелен и не привязан к устройству (H-04), подпись assertion не проверяется (L-10) |
| TPM | **ACCEPTABLE** | неэкспортируемый RSA-2048, проверка аппаратного провайдера и политики экспорта; детерминированная PKCS#1 v1.5 как источник KEK корректна. Используется без жеста и без привязки к личности (I-02) |
| DPAPI | **ACCEPTABLE** | CurrentUser, per-vault энтропия, зануление буфера ОС; стандартная граница same-user (признана) |
| Windows Hello | **NEEDS HARDENING** | Верификация assertion выполнена образцово. Но фактор — только политика (I-01), обходится `vault_change_pin` (M-08), отключается без re-auth (H-03) |
| Recovery / Shamir | **ACCEPTABLE** / NEEDS HARDENING | GF(2^8) корректен, порог ≥ 2, проверка дубликатов x, делится RK, а не MK; перебор пар с проверкой конвертом; поколение в AAD. Нужно: атомарность (M-01), ротация MK (M-04); таблицы log/exp не константного времени (для локального приложения несущественно) |
| Backup crypto | **ACCEPTABLE** | VLT4: Argon2id + AES-GCM с параметрами в заголовке; VLT2 опирается на внутренние слои (DPAPI/TPM/SQLCipher/конверт). Нужно: границы параметров (L-01) |
| Целостность метаданных | **STRONG** / NEEDS HARDENING | HMAC-SHA256, домен, однозначное кодирование с префиксами длины, дайджест FIDO2-таблицы, эпоха, два якоря; `recovery_local` вне MAC (подмена доли A даёт только DoS). Нужно: атомарная запись якоря (M-06) |
| Защита памяти | **NEEDS HARDENING** | MK под `CryptProtectMemory` и зануляется; SQLCipher-ключ, `integrity_key`, массовые расшифровки health check — открыто (L-12) |

**Композиционные слабости, найденные при сложении безопасных примитивов:** AAD с типом поля + «null = не менять» (H-02); DPAPI-привязка PIN-пути + параллельный непривязанный FIDO2-путь (H-04); отзыв конверта + неизменный MK (M-04); anti-rollback для мета + отсутствие связи мета ↔ records (M-05); санитизация для переноса + restore на месте (M-02); fail-closed + отключаемый recovery (H-05).

---

## 9. Data-at-Rest Assessment

- **Записи:** двойной слой — SQLCipher (страницы) и AES-GCM на per-value субключах. Имена записей и метки полей защищены только SQLCipher.
- **Мета:** открытая SQLite; секретов в открытом виде нет: обёртка MK — DPAPI поверх AES-GCM; `integrity_key` — DPAPI; DS — AES-GCM под TPM-KEK; доля A — DPAPI; конверт recovery — AES-GCM под RK. **Исключение — FIDO2-конверты** без DPAPI (H-04).
- **Вспомогательные файлы SQLite:** журнал `DELETE` (не WAL), `temp_store=MEMORY`, `secure_delete=ON` — остатков в `-wal/-shm` нет.
- **Временные файлы:** снимки мета/БД для бэкапа пишутся в `%TEMP%` (`NamedTempFile`); сырая копия мета (до санитизации) содержит FIDO2-конверты и долю A (под DPAPI) и удаляется без затирания. Записи — зашифрованы SQLCipher.
- **Логи:** в релизе выключены; режим `VAULTISOR_DIAG=1` пишет рядом с exe пути (с именем пользователя), имена FIDO2-ключей, коды ошибок — секретов нет (проверено по всем `log::`).
- **Ошибки для фронтенда:** системные/БД/IO-детали скрыты, наружу — машинные коды (есть тест).
- **Экспорт/бэкап:** VLT2 без пароля содержит всё, кроме факторов устройства; безопасность держится на DPAPI+TPM+PIN или B+C.

**Вывод:** при краже файлов без FIDO2-токена и без двух долей данные защищены сильно. Основной риск хранения — не конфиденциальность, а целостность/доступность (M-05, M-06, H-02, H-05).

---

## 10. Same-User Malware Assessment

Граница признана в SECURITY.md и подтверждается кодом. Такой код может:
1. Снять DPAPI с обёртки MK и `integrity_key` (энтропия лежит в той же мета).
2. Получить подпись DS через `NCryptSignHash` без жеста (имя ключа в мета открыто).
3. Перебирать PIN офлайн без счётчика: одна попытка = Argon2id 512 МиБ; 11-значный цифровой PIN — ≈ 10¹¹ вариантов (см. I-02).
4. Подделывать MAC мета (включая отключение Hello, сброс счётчика) и якоря.
5. Внедриться в процесс и прочитать MK/значения из памяти (`CryptProtectMemory(SAME_PROCESS)` против кода внутри процесса не защищает).
6. Читать буфер обмена в течение окна автоочистки.

Что реально затрудняет: стоимость Argon2 и длина/алфавит PIN; отсутствие открытых секретов на диске. **Итог: слабая устойчивость, честно задокументированная.** Существенно улучшить её можно только аппаратной политикой использования ключа (жест Hello на каждом использовании TPM-ключа, либо DS под политикой с PIN) — это архитектурное решение уровня P2.

---

## 11. Offline Attack Assessment

| Сценарий | Что нужно атакующему | Оценка |
|---|---|---|
| Файлы / бэкап на чужой машине | пароль Windows владельца (DPAPI) **и** TPM той машины | невозможно без исходного ПК |
| Файлы + две доли B, C | больше ничего | MK — ожидаемо по дизайну |
| Живые файлы + touch-only FIDO2-токен | больше ничего | **MK на любой машине** (H-04) |
| Живые файлы + ПИН+Touch токен | ПИН токена (аппаратный счётчик токена) | сильная защита |
| Украденный ПК без BitLocker | пароль Windows (перебор NT-хеша для локальной учётки) + DS через TPM из другой ОС (предположение) + перебор PIN | зависит от пароля Windows и энтропии PIN |
| Украденный ПК с BitLocker (TPM+PIN) | — | сильная |

---

## 12. Backup / Recovery Assessment

**Сильные стороны.** Snapshot через online backup API (консистентность); санитизация с остановкой экспорта при ошибке; MAC снимка под текущим ключом и совпадение `checkpoint_id` при restore; проверка каждой страницы SQLCipher и `integrity_check`; журнал `RestoreTransaction` с долговечными переименованиями и откатом при старте; одноразовые файловые полномочия через нативный диалог; конфиг каталога бэкапов под HMAC.

**Моделирование прерванного restore** (`storage/restore.rs`):

| Момент сбоя | Результат при следующем старте |
|---|---|
| во время `prepare` (нет `PREPARED`) | журнал удаляется, живые файлы не тронуты |
| после `PREPARED`, до `SWAPPING` | то же |
| во время `swap` (часть файлов заменена) | все файлы и внешний checkpoint возвращаются из `.old` |
| после `swap`, во время записи якорей | то же — возврат к исходному состоянию |
| после `COMMITTED` | журнал удаляется, новое состояние действует |

Restore корректен. **Recovery** (M-01) и **создание хранилища** (H-01) такой защиты не имеют.

**Слабые стороны.** H-05, M-01, M-02, M-03, M-04, L-01, L-13. Журнал восстановления, подложенный в каталог `vault/`, может заставить приложение при старте удалить внешний checkpoint (`machine.absent`) — только DoS.

---

## 13. Windows Security Assessment

| Механизм | Кто может вызвать операцию | Что защищает железо | UV без ожидания? | Переживает смену учётных данных Windows? |
|---|---|---|---|---|
| DPAPI CurrentUser | любой процесс пользователя | ничего (ключи ОС) | — | да при смене пароля штатно; **нет** при сбросе пароля администратором (мастер-ключ DPAPI теряется) → recovery |
| TPM DS (Platform KSP) | любой процесс пользователя, без жеста | неэкспортируемость приватного ключа | да — жеста нет вообще | да (привязан к TPM); сброс TPM/замена платы → recovery |
| Hello WebAuthn | инициировать может любой процесс пользователя, но нужен жест Hello | ключ платформенного аутентификатора | нет — UV обязателен и проверяется в authData и подписи | сброс Hello/PIN Windows удаляет ключи → recovery |
| FIDO2 hmac-secret | любой, у кого токен | CredRandom в токене | touch-only — по замыслу | не зависит от Windows |
| `CryptProtectMemory` | тот же процесс | ничего от кода внутри процесса | — | — |
| Файловая система | пользователь | — | — | anti-rollback только для мета |

Хорошо: проверка аппаратного провайдера (`NCRYPT_IMPL_HARDWARE_FLAG`) и явная проверка политики экспорта; удаление ключей при откате; `WebAuthNDeletePlatformCredential` резолвится динамически; буфер обмена одной сессией с маркерами. Недостатки: H-04, M-08, L-04, L-06, L-11, I-01, I-02.

---

## 14. IPC Assessment

Frontend считается враждебным. Для каждой команды: что будет при прямом вызове с произвольными аргументами.

| Команда | Требует сессию | Re-auth / step-up | Риск при враждебном вызове |
|---|---|---|---|
| `system_check`, `vault_exists`, `vault_lock_info`, `recovery_status`, `generator_limits`, `get_ui_language` | нет | — | раскрытие флагов конфигурации (Hello/FIDO/recovery есть) — приемлемо |
| `vault_create` | нет | — | **удаление существующего хранилища** (H-01) |
| `vault_unlock` | нет | PIN (+Hello) | корректно; счётчик под MAC, сериализация `auth_flow` |
| `vault_unlock_with_fido2` | нет | токен | корректно в рамках модели; самостоятельный путь (H-04) |
| `vault_change_pin` | **нет** | старый PIN | **сессия без Hello** (M-08) |
| `vault_lock` | нет | — | только блокировка — безопасно |
| `recovery_restore` | нет | доли | корректно по криптографии; не закрывает живую сессию (L-07); неатомарно (M-01) |
| `recovery_prepare_save`, `recovery_save_to_usb` | да | — | путь только из нативного диалога, `create_new`, TTL 60 с |
| `recovery_load_from_usb` | нет (полномочие) | — | чтение только выбранного в диалоге файла |
| `recovery_regenerate`, `recovery_disable` | да | **нет** | выдача B/C, отзыв восстановления (H-03); `recovery_disable` продлевает простой (L-03) |
| `file_prepare` | зависит от операции | — | нативный диалог; полномочие на одну операцию и одну сессию — **образцово** |
| `vault_export`, `backup_now`, `backup_set_config` | да | **нет** | экспорт/перенаправление бэкапов без re-auth (H-03); пути только из диалога |
| `vault_import` | нет (только при пустом хранилище) | — | DoS через параметры Argon2 (L-01), разбор недоверенной SQLite (L-02) |
| `vault_restore` | да | **нет** | откат политики (M-02); DoS (L-01) |
| `record_list/get/create/delete/reorder`, `records_batch_delete`, `record_clear_password_history` | да | нет | изменение/удаление данных — ожидаемо для сессии; размеры полей ограничены, число полей — нет |
| `record_update` | да | step-up | потеря значения при смене типа (H-02) |
| `record_reveal_field`, `record_get_password_history`, `record_copy_password_history`, `record_restore_password_history`, `clipboard_copy_secret` | да | step-up | корректно; `clear_after_seconds` из фронтенда может отключить автоочистку для конкретного копирования |
| `clipboard_copy_text`, `clipboard_clear` | да | нет | запись произвольного текста — ожидаемо |
| `settings_get` | да | нет | — |
| `settings_update` | да | **нет** | отключение step-up и Hello (H-03) |
| `set_ui_language`, `set_enable_*`, `get_enable_*` | да | нет | отключение истории паролей удаляет историю — ожидаемо |
| `get_fido2_status` | да | нет | — |
| `register_fido2_key`, `unbind_fido2_key` | да | **нет** | привязка своего ключа / отвязка чужих (H-03) |
| `generator_list/create/delete` | да (+флаг) | нет | проверка алфавита и длины — корректно |
| `generator_copy` | да (+флаг) | **нет** | обход step-up (L-05) |
| `session_heartbeat` | нет | — | продление сессии — ожидаемо |
| `import_chromium_csv`, `secure_delete_file` | да | нет | удаление только файла, принятого импортом, с проверкой хеша и длины — **образцово**; тихая потеря записей (M-07) |
| `open_security_key_settings` | нет | — | фиксированный URI — безопасно |

Произвольного чтения/записи/удаления файлов через IPC нет; инъекции команд нет; SQL параметризован (включая экранирование `LIKE`).

---

## 15. Supply Chain Assessment

| Пункт | Состояние |
|---|---|
| Пины Actions | все по SHA — **хорошо** |
| `cargo deny` (advisories, licenses, sources, wildcards) | включён; локальный прогон — `advisories ok` |
| `cargo audit` | в CI; 0 уязвимостей; 7 предупреждений (unmaintained/unsound) — транзитивные, вне Windows-таргета (I-06) |
| `npm audit` | moderate в CI, high в `build.ps1` |
| Dependabot | cargo, npm, actions — ежемесячно |
| Воспроизводимость | `npm install` вместо `npm ci`; Rust `stable` без версии; `build.ps1` без `--locked` (CI проверяет `--locked` отдельным шагом) |
| Права токенов | нет top-level `permissions` в `ci.yml`/`audit.yml`; релизный job с `contents: write` и `npm install` (M-09) |
| Подпись и provenance | нет Authenticode, нет attestation; SHA-256 из того же job |
| C-зависимости | SQLCipher 4.5.7 / SQLite 3.45.3 устарели, OpenSSL 3.6.2 свежий; SCA их не видит (L-02) |
| Лишние зависимости | `rand_chacha`, `anyhow`, `tauri-plugin-fs`, несколько в `core-shared` (L-09) |
| Рискованные FFI | `webauthn.dll`, NCrypt/BCrypt, DPAPI, WinRT UserConsentVerifier (мёртвый путь), user32/clipboard — все с комментариями SAFETY; разметка WebAuthn покрыта тестами |
| Фронтенд-зависимости | минимальный набор (react, i18next, lucide, clsx, tailwind-merge) — хорошо |

---

## 16. Test Coverage Assessment

**Что покрыто хорошо:** примитивы (AEAD, KDF, Shamir — все пары и тройки, дубли, переполнение счётчика), MAC мета (изменение каждого поля, инъекция FIDO2-ключа, откат снимка, удалённые/повреждённые якоря), журнал restore (прерывание на каждом шаге), файловые полномочия (повтор, истечение, чужая операция и сессия), разбор бандлов, разметка FFI WebAuthn, DER/COSE-парсеры, санитизация ошибок, CSV-разбор, релизный чек-лист.

**Что тестами только кажется:**
- `unlock.rs::policy_tests` проверяет модельную функцию `can_open`, определённую **в самом тесте**, а не `vault_unlock` — тавтология.
- `device_secret.rs` и `dpapi.rs`: тесты обёрнуты в `if let Ok(…)` — при сбое генерации проходят молча.
- `session.rs`: проверяется таблица сообщений, а не их доставка (L-04).

**Критичные потоки без тестов:**
- `vault_create` и его откат (H-01); `vault_unlock` целиком (MAC → счётчик → PIN → Hello → сессия); `vault_change_pin` (M-08); `settings_update` (H-03); `register_fido2_key`.
- `recovery_restore` — атомарность и fault injection (M-01); восстановление при открытой сессии (L-07).
- `update_record` со сменой типа (H-02); импорт CSV с длинными URL (M-07).
- `vault_import` → разблокировка (M-03); `vault_restore` → сохранность факторов (M-02).
- Откат `records.db` (M-05); атомарность якоря (M-06); границы Argon2 (L-01).
- Интеграционные тесты команд с `AppState` отсутствуют — большая часть логики безопасности живёт в командах. Рекомендуется вынести ядро команд в функции, принимающие `&AppState`-подобный контекст без `tauri::State`, и тестировать их.
- Аппаратные тесты (`#[ignore]`) существуют для TPM и Hello — оформить их как обязательный ручной чек-лист релиза.

---

## 17. Documentation Accuracy

| Утверждение | Где | Факт |
|---|---|---|
| «PIN обязателен всегда. Windows Hello и FIDO2 стали вторым фактором поверх PIN» | README, 4.0.0 | FIDO2 — самостоятельный путь без PIN и Hello |
| «Hello и FIDO2 — дополнительные факторы, а не альтернатива ему» | `Lock.tsx:96–98` | то же |
| «Touch-only (Passwordless 2FA)» | README, RU и EN | один фактор владения |
| «Без TPM этого устройства и без PIN файлы бесполезны» | SECURITY п.1 | неверно при привязанном FIDO2 (H-04) |
| «DPAPI и Device Secret привязывают данные к паре пользователь + устройство» | SECURITY п.3 | FIDO2-конверт и пара B+C не привязаны |
| «Незаметный… откат к старому снимку» защищён | SECURITY п.4 | только мета (M-05) |
| «домен v9» | SECURITY, таблица | `vaultisor:meta-integrity:v1` |
| «Бит UV в подписанных authenticator data — подделать нельзя» | SECURITY п.4, `fido2.rs` | подпись не проверяется (L-10) |
| «старые поколения отзываются после регенерации» | README | только относительно текущей мета (M-04) |
| «бандл полностью зашифрован и привязан к устройству (TPM+DPAPI); восстановление на другом ПК только через Shamir» | `backup.rs:7–8` | мета открыта; на **том же** ПК после утраты хранилища тоже только Shamir B+C (M-03) |
| «авто-очистка исходного CSV (затирание случайными байтами)» | README | best-effort (честно оговорено в SECURITY п.6) |
| Release notes v3.1.0 | `.github/release_notes.md` | публикуются для 5.x |
| Честные границы same-user, кейлоггер, Hello-ключ в Параметрах, внешний checkpoint | SECURITY | **соответствуют коду** — хорошая практика |

---

## 18. Positive Findings

1. **Нет оракула перебора PIN:** хеш PIN не хранится; проверка только разворотом MK; DS делает офлайн-перебор без TPM невозможным.
2. **Per-value HKDF-субключи + AAD** с привязкой к записи, полю и типу; MK не используется напрямую как AES-ключ.
3. **Recovery через KEK-конверт** с поколением в AAD; перебор пар долей с проверкой конвертом; проверка открытия `records.db` до деструктивных шагов.
4. **Метаданные под HMAC** с доменом, однозначным кодированием, дайджестом FIDO2-таблицы, монотонной эпохой, локальным и внешним якорями; негативные тесты на каждое поле.
5. **Модель файловых полномочий:** webview никогда не передаёт путь; только одноразовый токен от нативного диалога, привязанный к операции и сессии, с TTL.
6. **Удаление CSV только по квитанции импорта** с проверкой хеша и длины через один дескриптор.
7. **Верификация Windows Hello** выполнена как у RP: собственный challenge, `rpIdHash`, UP+UV, ES256, строгий DER/CBOR-разбор без паник.
8. **FIDO2:** KEK из PRF (а не из публичного credential_id), allowlist, проверка вернувшегося ID, режим проверяется для каждого ключа отдельно.
9. **Буфер обмена:** одна атомарная сессия с тремя маркерами исключения, очистка по номеру последовательности без чтения содержимого обратно, очистка при блокировке.
10. **Restore как журнальная транзакция** с долговечными переименованиями и восстановлением при старте.
11. **Argon2 single-flight и вынос в blocking-пул** — защита от DoS из webview и от зависания интерфейса.
12. **Санитизация ошибок** с машинными кодами и тестом «детали не утекают».
13. **Минимальная поверхность:** нет сети, строгая CSP, devtools выключены в релизе, capabilities только `core:*`, один экземпляр, блокировка по Win+L.
14. **Разметка FFI WebAuthn** сверена с `webauthn.h` тестами; единственный биндинг.
15. **SDLC:** пины Actions по SHA, cargo-deny с запретом wildcard и неизвестных источников, Dependabot, релизный чек-лист как тест.
16. **Честный SECURITY.md** с явными границами (same-user, кейлоггер, touch-only, удаление ключа Hello).

---

## 19. Residual Risks

После исправления всех находок останутся осознанные риски:
- same-user malware и кейлоггеры (граница DPAPI/CNG);
- перебор короткого цифрового PIN хорошо оснащённым противником, получившим DS (I-02);
- открытые значения секретов в webview после reveal (неизбежно для отображения);
- неподписанный бинарь, пока нет Authenticode (решение владельца);
- touch-only FIDO2 как один фактор владения (выбор пользователя);
- физические атаки на выключенное устройство без BitLocker.

---

## 20. Recommended Roadmap

**P0 — до следующего релиза**
1. H-01: откат `vault_create` только для созданного этим вызовом; `vault_exists` различает частичное состояние.
2. H-02: перешифрование при смене типа поля (или запрет смены без значения) + тест.
3. H-03: re-auth (PIN, и Hello если включён) для всех операций с политикой безопасности; отключение step-up только с Hello.
4. H-05: backoff вместо безвозвратной блокировки либо запрет отключения recovery без альтернативного фактора.
5. M-06: атомарная запись локального якоря.
6. M-07: импорт CSV без потерь; нет токена удаления при частичном импорте.
7. M-01: `recovery_restore` в одной транзакции; удаление старых ключей после `COMMIT`.
8. L-14: исправить «PIN обязателен всегда», «Passwordless 2FA», SECURITY п.1/п.3, «домен v9», release notes.

**P1 — ближайший security-релиз**
1. H-04: DPAPI-слой поверх FIDO2-конверта (или явная переносимость + предупреждение при touch-only).
2. M-08: `vault_change_pin` только из сессии с re-auth.
3. M-02, M-03: restore/import сохраняют текущие факторы; управляемый вход после импорта на том же ПК.
4. M-05: ревизия `records.db`/`web.db` под MAC мета.
5. M-04: операция ротации MK (перешифрование, новое поколение долей).
6. M-09: разделить сборку и публикацию, provenance-attestation, `npm ci`, `permissions: contents: read`, `rust-toolchain.toml`.
7. L-01, L-02: границы Argon2 из файлов; обновление SQLCipher; `trusted_schema=OFF` и defensive-режим для недоверенных БД.
8. Интеграционные тесты команд (§16).

**P2 — hardening**
1. L-03: таймер автоблокировки в backend; единый guard команд.
2. L-04, L-05, L-06, L-07, L-08, L-11: точечные исправления.
3. L-09: удаление мёртвого кода и зависимостей; `cargo machete` в CI.
4. L-10: проверка подписи FIDO2-assertion.
5. L-12: кэш health check, `Zeroizing` в IPC-структурах, `argon2/zeroize`.
6. L-13: ретенция по времени; не создавать пустые БД при разблокировке.
7. I-02: политика использования TPM-ключа (жест или PCR) — как архитектурное усиление против same-user.

---

## 21. Финальный вердикт

**1. Можно ли считать текущий Vaultisor криптографически корректно спроектированным?**
Да — на уровне примитивов и иерархии ключей. Выбор алгоритмов, разделение доменов, AAD, KEK-конверты, отсутствие оракула PIN и защита метаданных сделаны грамотно. Некорректна **композиция**: параллельный FIDO2-путь вне DPAPI (H-04), неротируемый MK при заявленном отзыве (M-04), изменяемые данные AAD без перешифрования (H-02).

**2. Есть ли пути раскрытия Master Key без ожидаемых факторов?**
Да, один существенный: копия живой мета + touch-only токен дают MK на любой машине без PIN, DPAPI и TPM (H-04). Кроме того, старые доли + любая старая копия мета дают текущий MK после «отзыва» (M-04). Путей к MK без какого-либо фактора нет.

**3. Есть ли authentication downgrade paths?**
Да: FIDO2 обходит PIN и Hello (H-04, задокументировано противоречиво); `vault_change_pin` открывает сессию без Hello (M-08); step-up и Hello отключаются из сессии без повторной проверки (H-03); restore молча выключает Hello и возвращает старые доли и PIN (M-02).

**4. Насколько устойчив vault при краже файлов?**
Высоко, если не привязан touch-only FIDO2-ключ и не утекли две доли: нужны пароль Windows владельца, TPM его машины и PIN. С привязанным touch-only ключом устойчивость равна физической защищённости токена.

**5. Насколько устойчив vault при same-user malware?**
Низко, что честно указано в SECURITY.md: DPAPI, подпись TPM и MAC доступны такому коду; остаётся только стоимость Argon2 и энтропия PIN.

**6. Насколько безопасны backup/restore/recovery?**
Криптографически — хорошо (подлинность, консистентность, журнал restore). Эксплуатационно — есть серьёзные пробелы: неатомарный recovery (M-01), тихий откат политики при restore (M-02), бэкап без B+C бесполезен после утраты хранилища (M-03), неограниченные параметры Argon2 (L-01).

**7. Есть ли риск необратимого lockout/data loss?**
Да, и это главный практический риск продукта: удаление существующего хранилища откатом `vault_create` (H-01), потеря значения при смене типа поля (H-02), тупиковые fail-closed состояния при выключенном восстановлении (H-05), неатомарные якорь и recovery (M-06, M-01), потеря записей при импорте CSV (M-07).

**8. Три самые важные проблемы**
1. **H-01** — откат `vault_create` удаляет существующее хранилище.
2. **H-02** — смена типа поля уничтожает значение обычным действием в UI.
3. **H-03** — политика безопасности меняется из сессии без повторной аутентификации (step-up отключается тем, против кого он поставлен; постоянный бэкдор через свой FIDO2-ключ или доли).

**9. Особенно удачные архитектурные решения**
Отсутствие оракула PIN и DS в TPM; per-value субключи с AAD; recovery через KEK-конверт с поколением; HMAC-метаданные с эпохой и двумя якорями; модель одноразовых файловых полномочий; журнальный restore; образцовая проверка WebAuthn-assertion для Hello; атомарная защищённая запись в буфер обмена; честный SECURITY.md.

**10. Что обязательно исправить перед дальнейшим функциональным развитием**
Всё из P0: H-01, H-02, H-03, H-05, M-01, M-06, M-07 и выверку документации (L-14). Каждая новая функция, меняющая состояние хранилища, умножает число мест, где повторится одна из трёх корневых причин этих находок: деструктивный откат без учёта владения артефактами, композиция инвариантов без проверки (AAD и «null = не менять»), и отсутствие класса «операций с политикой» с повторной аутентификацией. Их стоит закрыть как архитектурные правила, а не точечно.

---

## Приложение A. Второй adversarial-проход по HIGH

| Находка | Попытка опровергнуть | Результат |
|---|---|---|
| H-01 | Есть ли проверка существования до побочных эффектов? Держатся ли файлы открытыми, мешая удалению? | Проверка есть, но её ошибка сама запускает откат. При запертом хранилище соединения закрыты — Windows файлы удаляет. **Подтверждено** |
| H-02 | Может, фронтенд не даёт менять тип нераскрытого поля? Может, backend перешифровывает? | Бейдж типа доступен всегда; ветка без значения обновляет только столбцы. **Воспроизведено тестом** |
| H-03 | Может, UI скрывает переключатель без Hello, или backend требует Hello при выключении? | Переключатель обычный; в `settings_update` проверки нет; привязка ключа требует assertion только нового ключа. **Подтверждено** |
| H-04 | Может, конверт под DPAPI? Может, приложение нужно для разворота? Может, соль недоступна? | Конверт — голый AES-GCM в открытой SQLite; соль и RP ID — константы в бинаре; raw hmac-secret доступен из libfido2. Для ПИН+Touch не работает (нужен ПИН токена). **Подтверждено для touch-only**, confidence MEDIUM (офлайн-шаг не выполнялся) |
| H-05 | Есть ли сброс счётчика кроме recovery? Можно ли войти по FIDO2 или через restore? | FIDO2 и смена PIN блокируются тем же условием; restore требует сессию; импорт даёт `META_TAMPERED`. **Подтверждено**; необратимость — только при выключенном восстановлении |

## Приложение B. Проверенные и отклонённые гипотезы (false positives)

| Гипотеза | Почему отклонена |
|---|---|
| Параллельные вызовы `vault_unlock` обходят счётчик попыток | вход, смена PIN, FIDO2 и recovery сериализованы `auth_flow` (tokio::Mutex) |
| Смешанный набор FIDO2-ключей понижает требование ПИН | решение по конкретному ключу и флагу UV; для CTAP 2.1 PRF с UV и без UV различается |
| Path traversal / произвольная запись через экспорт, бэкап, долю | путь не принимается из webview; только полномочие от нативного диалога; `create_new` |
| Перенаправление автобэкапа подменой `backup.json` | конфиг под HMAC `integrity_key` |
| SQL-инъекция в поиске | запрос параметризован, `LIKE` экранирован |
| XSS в webview | строгая CSP, React-экранирование, нет `innerHTML`/`dangerouslySetInnerHTML` |
| Restore чужого хранилища или копии, сделанной до recovery | требуется совпадение `checkpoint_id` и MAC под текущим `integrity_key` |
| Подделка доли Шамира даёт «мусорный» мастер-ключ | каждая пара проверяется AEAD-конвертом, затем открытием `records.db` |
| Повтор Hello-assertion | свежий challenge в собственном `clientDataJSON` и проверка подписи |
| Паника в DER-разборе подписи Hello | длины ограничены, есть тест на компоненты > 32 байт |
| Утечка секретов в логи | проверены все `log::` — значения, PIN, доли, ключи не пишутся |
| Утечка деталей ошибок во фронтенд | `System`/`Storage`/`Io`/`Internal`/`DbFailure` сериализуются кодом; есть тест |
| Удаление произвольного файла через `secure_delete_file` | только квитанция импорта, проверка хеша и длины через тот же дескриптор, отказ для symlink |
