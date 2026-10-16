# Security Policy — Vaultisor

[Русский](#русский) | [English](#english)

---

## Русский

### Как сообщить об уязвимости

Пишите приватно через [GitHub Security Advisories](https://github.com/vasilydupidu/Vaultisor/security/advisories/new).
Пожалуйста, не открывайте публичный issue до выпуска исправления.

Мы стараемся ответить в течение 5 рабочих дней, выпустить исправление
критических находок — в течение 30 дней, и указать автора находки в релизных
заметках, если он не против.

### Поддерживаемые версии

Исправления безопасности выпускаются только для последней минорной ветки.

| Версия | Поддержка |
|--------|-----------|
| 5.1.x  | ✅ |
| ≤ 5.0.x | ❌ |

### Модель угроз

Vaultisor — локальное приложение без сетевой поверхности. Формулируем честно,
от чего оно защищает, а от чего нет.

**Защищает:**

1. **Кража файлов хранилища** (`vault/*.db`, резервные копии `.vault`).
   Записи лежат в SQLCipher 4, значения полей дополнительно зашифрованы
   AES-256-GCM на отдельных HKDF-ключах с привязкой к записи и полю через AAD.
   Мастер-ключ обёрнут Argon2id (512 МиБ, t=6, p=2) от PIN и Device Secret из
   TPM, поверх — DPAPI. Без TPM и учётной записи этого устройства и без PIN
   файлы бесполезны.
2. **Офлайн-перебор PIN по украденному файлу.** Хэш PIN не хранится: PIN
   проверяется только AEAD-разворотом мастер-ключа, а он требует Device
   Secret, неизвлекаемый из TPM.
3. **Онлайн-перебор PIN.** После 5 неверных попыток — нарастающая задержка
   (30 с, 1, 5, 15 минут, затем час на каждую попытку). Попытка
   засчитывается до проверки PIN, поэтому ни сбой процесса, ни отказ записи
   не дают попытки мимо счётчика. Состояние задержки хранится под MAC и во
   внешнем checkpoint; откат файлов, импорт копии и перевод часов назад его
   не снимают. Безвозвратной блокировки нет.
4. **Изменение политики безопасности из открытой сессии.** Смена PIN,
   Windows Hello, подтверждение копирования, FIDO2, восстановление, restore,
   и папка резервных копий требуют свежего подтверждения PIN (и
   Hello, если включён). Разрешение живёт только на стороне backend, выдаётся
   на одно действие, действует 2 минуты, одноразово и исчезает при
   блокировке.
5. **Перенос хранилища на другую машину или в другую учётную запись Windows**
   — в том числе вместе с FIDO2-токеном. DPAPI (CurrentUser) и Device Secret
   привязывают данные, включая конверты FIDO2, к паре пользователь +
   устройство. Легальный перенос — только восстановление по схеме Шамира
   2-из-3.
6. **Незаметная правка или откат метаданных** (сброс задержки PIN, подмена
   факторов, папки копий, откат к старому снимку). Метаданные подписаны
   HMAC-SHA256 с монотонной эпохой; внешний checkpoint фиксирует эпоху и MAC.
7. **Откат и подмена баз записей.** Каждое изменение базы увеличивает её
   ревизию в той же транзакции; ревизия и SHA-256 файла подтверждаются во
   внешнем checkpoint после commit. База старее подтверждённой — и целиком,
   и отдельными страницами SQLCipher — даёт `DATA_ROLLBACK`. Продолжить со
   старыми данными можно только явным решением владельца с проверкой PIN, и
   только для показанного ему снимка; подтверждённая ревизия при этом не
   уменьшается.
8. **Подделка ответов аутентификатора.** Регистрация и каждый вход FIDO2 и
   Windows Hello проверяются как у сервера WebAuthn: rpIdHash, флаги UP/UV,
   clientData (тип, challenge, origin), подпись ES256 открытым ключом из
   регистрации, защищённым MAC метаданных.
9. **Утечка секретов через буфер обмена.** Секрет пишется одной сессией
   буфера с запретом истории и облачной синхронизации, очищается по таймеру
   и при блокировке — только если в буфере всё ещё наше содержимое.
10. **Квантовый противник со снимком файлов.** На диске нет асимметричной
    мишени: всё защищено симметричной схемой.

**Не защищает (осознанные границы):**

1. **Вредоносный код под той же учётной записью Windows.** Это граница DPAPI
   и CNG: такой код может вызвать `CryptUnprotectData` и `NCryptSignHash`
   так же, как Vaultisor, в том числе получить подпись Device Secret, которая
   выдаётся без жеста пользователя. Windows Hello — второй фактор поверх PIN,
   а не источник ключа: противник, снявший PIN кейлоггером, проходит его
   вместе с пользователем. Тормоз — Argon2id 512 МиБ и задержки на каждую
   попытку, но не невозможность атаки.
2. **Аппаратные атаки на выключенное устройство** (cold boot, извлечение TPM).
3. **Кейлоггер или скринграббер** — они перехватывают PIN до Vaultisor.
4. **Физический FIDO2-ключ в режиме Touch-only** — один фактор владения.
   Оставленный в порту ключ открывает хранилище на этом устройстве; режим
   задаётся осознанно при привязке. Для двух факторов привязывайте ключ как
   ПИН + Touch. Вход по FIDO2 — самостоятельный путь к мастер-ключу (без PIN
   Vaultisor); режим соблюдается для каждого ключа отдельно по биту UV в
   подписанных authenticator data.
5. **Удаление ключа Windows Hello самим пользователем** в «Параметры →
   Учётные записи → Ключи доступа» (`vaultisor.app`). Второй фактор пропадает,
   и хранилище открывается только восстановлением по долям B и C: вход по
   одному PIN был бы обходом фактора. Отключайте Hello в настройках Vaultisor.
6. **Последнее изменение базы в окне сбоя.** Если процесс прервался между
   commit изменения и записью его ревизии в checkpoint, противник, успевший
   подменить базу до следующего входа, может скрыть именно это последнее
   неподтверждённое изменение. Закрыть окно полностью без неоткатываемого
   аппаратного счётчика (TPM NV) нельзя.
7. **Скомпрометированные доли восстановления.** Две доли из трёх дают доступ
   к мастер-ключу. Новое поколение отзывает старые доли, но смены мастер-ключа
   (перешифрования всех данных) после компрометации в 5.1.0 нет.
8. **Гарантированное уничтожение импортированного CSV.** Перезапись
   случайными байтами не устраняет копии в журнале NTFS, теневых копиях и
   внутреннем пуле SSD. Это best-effort, а не шредер.

### Где лежат данные

| Что | Где | Зачем |
|---|---|---|
| Метаданные, записи, пароли сайтов | папка `vault` рядом с `Vaultisor-<версия>.exe` | портативность |
| Внешний checkpoint | `%LOCALAPPDATA%\Vaultisor\SecurityCheckpoints\` | эпоха и MAC метаданных, задержки PIN, ревизии и SHA-256 баз; свой файл у каждого integrity-ключа, защищён DPAPI |
| TPM-ключ Device Secret | Microsoft Platform Crypto Provider | неэкспортируемый ключ этого устройства |
| Ключ Windows Hello | хранилище ключей доступа Windows (`vaultisor.app`) | только при включённом Hello |

Checkpoint намеренно лежит вне папки хранилища: он обязан пережить подмену
файлов в `vault`. Если его нет или он испорчен, вход отказывает
(`META_TAMPERED`): отличить «почистили профиль» от «удалили маркер, чтобы
откатить базу» невозможно. Легальный путь переноса — восстановление по долям.

### Криптографические решения

| Назначение | Алгоритм | Параметры |
|---|---|---|
| Обёртка мастер-ключа PIN | Argon2id → AES-256-GCM, затем DPAPI | m=512 МиБ, t=6, p=2; ключ из PIN и Device Secret |
| Обёртка мастер-ключа FIDO2 | HKDF(PRF ‖ Device Secret) → AES-256-GCM, затем DPAPI | PRF — расширение hmac-secret токена; KEK привязан к credential id |
| Поля записей | HKDF-SHA256 → AES-256-GCM | соль 16 байт на значение, AAD = запись:поле:тип |
| Базы записей | SQLCipher 4 | AES-256-CBC + HMAC-SHA512 постранично |
| Целостность метаданных | HMAC-SHA256 | монотонная эпоха; все поля под MAC, включая состояние восстановления |
| Внешний checkpoint | HMAC-SHA256 под DPAPI | эпоха, MAC метаданных, задержки PIN, ревизии и SHA-256 баз |
| Проверка FIDO2 и Hello | ECDSA P-256 (ES256) | открытый ключ из регистрации под MAC |
| Восстановление | Shamir над GF(2^8), 2 из 3 | доли восстанавливают ключ конверта, а не мастер-ключ |
| Привязка к устройству | TPM 2.0 RSA-2048 (Platform KSP) → HKDF | подпись фиксированного challenge |
| Привязка к учётной записи | DPAPI CurrentUser | энтропия 32 байта на хранилище |

### Дисциплина цепочки поставок

- Все GitHub Actions закреплены по SHA коммита; токены с минимальными
  правами на каждый job; `persist-credentials: false`; workflows проверяются
  `actionlint` и `zizmor`.
- Релиз: сборка без кэшей → неизменяемый артефакт → публикация после сверки
  SHA-256; toolchain Rust зафиксирован, `npm ci`, cargo `--locked`.
- `cargo deny` (advisories, лицензии, источники), `cargo audit`, `npm audit`
  — перед релизом и после обновления зависимостей. CI автоматически не
  запускается: проверки прогоняются локально и вручную в GitHub Actions.
- Бинарник **не подписан** Authenticode. Проверяйте SHA-256 по
  `SHA256SUMS.txt` из релиза и provenance сборки:
  `gh attestation verify Vaultisor-<версия>.exe --repo vasilydupidu/Vaultisor`.

---

## English

### Reporting a vulnerability

Please report privately through
[GitHub Security Advisories](https://github.com/vasilydupidu/Vaultisor/security/advisories/new).
Do not open a public issue before a fix ships.

We aim to acknowledge within 5 business days, fix critical findings within
30 days, and credit reporters in the release notes unless they prefer otherwise.

### Supported versions

| Version | Supported |
|---------|-----------|
| 5.1.x   | ✅ |
| ≤ 5.0.x | ❌ |

### Threat model

Vaultisor is a local application with no network surface. What it does and does
not defend against, stated plainly.

**Protects against:**

1. **Theft of vault files** (`vault/*.db`, `.vault` backups). Records live in
   SQLCipher 4; field values are additionally encrypted with AES-256-GCM under
   per-value HKDF keys bound to the record and field through AAD. The master
   key is wrapped with Argon2id (512 MiB, t=6, p=2) over the PIN and a
   TPM-held Device Secret, then with DPAPI.
2. **Offline PIN guessing from a stolen file.** No PIN hash is stored; the PIN
   can only be checked by unwrapping the master key, which needs the
   non-exportable Device Secret.
3. **Online PIN guessing.** After 5 wrong attempts a growing delay applies
   (30 s, 1, 5, 15 minutes, then an hour per attempt). An attempt is counted
   before the PIN is checked, so neither a crash nor a failed write yields an
   uncounted attempt. The delay state is MAC-protected and mirrored in the
   external checkpoint; rolling back files, importing a backup or moving the
   clock back does not clear it. There is no permanent lockout.
4. **Security-policy changes from an open session.** Changing the PIN, Windows
   Hello, copy confirmation, FIDO2, recovery, restore and the backup folder
   all require a fresh PIN (plus Hello when enabled). The authorization
   lives only in the backend, covers one action, lasts 2 minutes, is single-use
   and disappears on lock.
5. **Moving the vault to another machine or Windows account** — including
   together with a FIDO2 token. DPAPI (CurrentUser) and the Device Secret bind
   the data, FIDO2 envelopes included, to the user+device pair. The supported
   path is Shamir 2-of-3 recovery.
6. **Silent edits or rollback of the metadata** (clearing the PIN delay,
   swapping factors or the backup folder, rolling back to an older snapshot).
   Metadata is signed with HMAC-SHA256 and a monotonic epoch; the external
   checkpoint records the epoch and MAC.
7. **Rollback and tampering of the databases.** Every database change raises
   its revision in the same transaction; the revision and the file's SHA-256
   are confirmed in the external checkpoint after commit. A database older than
   the confirmed state — whole or by individual SQLCipher pages — yields
   `DATA_ROLLBACK`. Continuing with the old data takes an explicit owner
   decision with a PIN check, valid only for the snapshot that was shown; the
   confirmed revision never decreases.
8. **Forged authenticator responses.** FIDO2 and Windows Hello registration and
   every sign-in are verified the way a WebAuthn server does: rpIdHash, UP/UV
   flags, clientData (type, challenge, origin) and the ES256 signature against
   the registered public key, which is covered by the metadata MAC.
9. **Clipboard leakage.** Secrets are written in one clipboard session that
   excludes history and cloud sync, and cleared on a timer and on lock, only
   while the clipboard still holds our own content.
10. **A quantum adversary holding a file snapshot.** Nothing on disk relies on
    asymmetric cryptography.

**Does not protect against (accepted boundaries):**

1. **Malicious code running as the same Windows user.** This is the DPAPI/CNG
   boundary: such code can call `CryptUnprotectData` and `NCryptSignHash`
   exactly as Vaultisor does, including obtaining the Device Secret signature,
   which is issued without a user gesture. Windows Hello is a second factor on
   top of the PIN, not a key source: an attacker who captured the PIN with a
   keylogger passes it alongside the user. Argon2id at 512 MiB and the delays
   slow such an attacker down but do not stop them.
2. **Hardware attacks on a powered-off device** (cold boot, TPM extraction).
3. **Keyloggers and screen capture**, which observe the PIN before Vaultisor does.
4. **A FIDO2 key registered as Touch-only** — a single possession factor. A
   key left in the port opens the vault on this device; the mode is chosen
   deliberately at binding time. Bind the key as PIN + Touch for two factors.
   FIDO2 sign-in is a standalone path to the master key (no Vaultisor PIN); the
   mode is enforced per key from the UV bit in the signed authenticator data.
5. **The user deleting the Windows Hello key** under Settings → Accounts →
   Passkeys (`vaultisor.app`). The second factor is gone and the vault opens
   only through recovery with shares B and C: falling back to the PIN alone
   would defeat the factor. Turn Hello off in Vaultisor's settings instead.
6. **The last database change in a crash window.** If the process stops
   between committing a change and recording its revision in the checkpoint, an
   attacker who swaps the database before the next sign-in can hide exactly
   that last unconfirmed change. Closing the window completely would need a
   non-rollbackable hardware counter (TPM NV).
7. **Compromised recovery shares.** Two shares out of three give access to the
   master key. A new generation revokes old shares, but 5.1.0 has no master-key
   rotation (re-encrypting all data) after a compromise.
8. **Guaranteed erasure of an imported CSV.** Overwriting with random bytes
   does not remove copies in the NTFS journal, shadow copies or SSD
   over-provisioned blocks. It is best-effort, not a shredder.

### Where data lives

| What | Where | Why |
|---|---|---|
| Metadata, records, website passwords | the `vault` folder next to `Vaultisor-<version>.exe` | portability |
| External checkpoint | `%LOCALAPPDATA%\Vaultisor\SecurityCheckpoints\` | metadata epoch and MAC, PIN delay, database revisions and SHA-256; one file per integrity key, DPAPI-protected |
| TPM Device Secret key | Microsoft Platform Crypto Provider | a non-exportable key of this device |
| Windows Hello key | Windows passkey store (`vaultisor.app`) | only when Hello is enabled |

The checkpoint deliberately lives outside the vault folder: it must survive
replacement of the files in `vault`. If it is missing or corrupt, sign-in fails
(`META_TAMPERED`): "the profile was wiped" cannot be told apart from "the marker
was deleted to roll the database back". The supported way to move a vault is
share recovery.

### Cryptography

| Purpose | Algorithm | Parameters |
|---|---|---|
| PIN wrap of the master key | Argon2id → AES-256-GCM, then DPAPI | m=512 MiB, t=6, p=2; key from the PIN and Device Secret |
| FIDO2 wrap of the master key | HKDF(PRF ‖ Device Secret) → AES-256-GCM, then DPAPI | PRF is the token's hmac-secret extension; the KEK is bound to the credential id |
| Record fields | HKDF-SHA256 → AES-256-GCM | 16-byte salt per value, AAD = record:field:type |
| Record databases | SQLCipher 4 | AES-256-CBC + HMAC-SHA512 per page |
| Metadata integrity | HMAC-SHA256 | monotonic epoch; every field covered, recovery state included |
| External checkpoint | HMAC-SHA256 under DPAPI | epoch, metadata MAC, PIN delay, database revisions and SHA-256 |
| FIDO2 and Hello verification | ECDSA P-256 (ES256) | registered public key under the MAC |
| Recovery | Shamir over GF(2^8), 2 of 3 | shares reconstruct an envelope key, not the master key |
| Device binding | TPM 2.0 RSA-2048 (Platform KSP) → HKDF | signature over a fixed challenge |
| Account binding | DPAPI CurrentUser | 32-byte per-vault entropy |

### Supply chain

- Every GitHub Action is pinned by commit SHA; tokens get least privilege per
  job; `persist-credentials: false`; workflows are checked with `actionlint`
  and `zizmor`.
- Release: a cache-free build → an immutable artifact → publication after the
  SHA-256 is verified; the Rust toolchain is pinned, `npm ci`, cargo `--locked`.
- `cargo deny` (advisories, licenses, sources), `cargo audit` and `npm audit`
  run before every release and after dependency updates. CI never runs
  automatically: checks run locally and, on demand, in GitHub Actions.
- The binary is **not** Authenticode-signed. Verify its SHA-256 against
  `SHA256SUMS.txt` from the release and its build provenance:
  `gh attestation verify Vaultisor-<version>.exe --repo vasilydupidu/Vaultisor`.
