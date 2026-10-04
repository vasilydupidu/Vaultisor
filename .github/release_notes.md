## Vaultisor v5.1.0 — Security & Reliability Consolidation

[Русский](#русский) | [English](#english)

### Русский

> Хранилища версий 5.0.x не открываются: экспортируйте данные перед обновлением.

- Атомарность всех операций с хранилищем проверена отказом на каждом шаге записи.
- Изменения безопасности требуют свежего подтверждения PIN (и Windows Hello).
- Нарастающая задержка после неверных PIN вместо безвозвратной блокировки.
- FIDO2 привязан к устройству; ответы токена проверяются полностью.
- Обнаружение отката баз записей и паролей сайтов.
- Восстановление по долям и restore из копии переработаны; restore не возвращает старые факторы входа.

Бинарник распространяется без Authenticode-подписи. Перед запуском сверьте SHA-256 с `SHA256SUMS.txt`; сведения о сборке — в `build-info.json`.

### English

> Vaults from 5.0.x will not open: export your data before upgrading.

- Atomicity of every vault operation verified with a failure at each write step.
- Security changes require a fresh PIN confirmation (plus Windows Hello).
- A growing delay after wrong PINs instead of a permanent lockout.
- FIDO2 is bound to the device; authenticator responses are fully verified.
- Rollback detection for the records and website-password databases.
- Share recovery and backup restore were reworked; restore does not bring back old sign-in factors.

The binary is not Authenticode-signed. Verify its SHA-256 against `SHA256SUMS.txt` before running it; build details are in `build-info.json`.
