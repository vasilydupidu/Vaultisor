## Vaultisor v5.2.0 — Security & Reliability Consolidation

[Русский](#русский) | [English](#english)

### Русский

> Хранилища предыдущих версий не открываются: миграции нет — 5.2.0 создаёт хранилище заново.

- Атомарность всех операций с хранилищем проверена отказом на каждом шаге записи.
- Изменения безопасности требуют свежего подтверждения PIN (и Windows Hello).
- Нарастающая задержка после неверных PIN вместо безвозвратной блокировки.
- FIDO2 привязан к устройству; ответы токена проверяются полностью.
- Обнаружение отката баз записей и паролей сайтов.
- Восстановление только по обеим частям, B и C: на устройстве части нет, одна часть хранилище не открывает.
- Restore из копии возвращает только данные, а не старые факторы входа. Отдельного экспорта больше нет — копия создаётся бэкапом.
- Ввод PIN быстрее: Argon2id считается на нескольких ядрах при той же стоимости перебора.
- Поле «Комментарий» — открытая многострочная заметка к записи.

Бинарник распространяется без Authenticode-подписи. Перед запуском сверьте SHA-256 с `SHA256SUMS.txt` и проверьте происхождение сборки: `gh attestation verify Vaultisor-5.2.0.exe --repo vasilydupidu/Vaultisor`. Сведения о сборке — в `build-info.json`.

### English

> Vaults from earlier versions will not open: there is no migration — 5.2.0 creates the vault from scratch.

- Atomicity of every vault operation verified with a failure at each write step.
- Security changes require a fresh PIN confirmation (plus Windows Hello).
- A growing delay after wrong PINs instead of a permanent lockout.
- FIDO2 is bound to the device; authenticator responses are fully verified.
- Rollback detection for the records and website-password databases.
- Recovery needs both parts, B and C: nothing is stored on the device, and one part does not open the vault.
- Restoring a backup brings back data only, not old sign-in factors. There is no separate export any more — a copy is made by a backup.
- Faster PIN entry: Argon2id runs on several cores at the same brute-force cost.
- The "Comment" field is a plain multi-line note on a record.

The binary is not Authenticode-signed. Before running it, verify its SHA-256 against `SHA256SUMS.txt` and its build provenance: `gh attestation verify Vaultisor-5.2.0.exe --repo vasilydupidu/Vaultisor`. Build details are in `build-info.json`.
