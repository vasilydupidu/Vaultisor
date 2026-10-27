# Vaultisor 5.2.0 — консолидация безопасности

Итоговый документ этапа 5: статус каждой находки независимого аудита
([`VAULTISOR-INDEPENDENT-SECURITY-AUDIT.md`](./VAULTISOR-INDEPENDENT-SECURITY-AUDIT.md),
версия 5.0.x), находки этапов консолидации, покрытие отказами и честный список
остаточных рисков.

**Статусы:** CLOSED — причина устранена и закреплена тестом или структурой
кода; PARTIAL — риск снижен, но остаётся пробел; RESIDUAL — не исправлено и
принято осознанно (описано в `SECURITY.md`).

## 1. Как проверялось

- **Внедрение отказов.** Перед каждым шагом персистентности (commit SQLite,
  запись файла, создание и удаление ресурса ОС) стоит точка отказа
  `failpoint::hit`. Свип прогоняет команду без отказов, считает шаги, затем
  повторяет её с отказом на каждом шаге — падением процесса (`Crash`) и
  ошибкой (`Error`). После каждого прогона: перезапуск, проверка инвариантов
  (`tests/invariants.rs`), вход по PIN и классификация итога — старое или новое
  состояние, без промежуточных.
- **Повторный аудит.** Все 34 находки аудита 5.0.x перепроверены по текущему
  коду с доказательствами (файл, функция, тест); попутно найдено шесть новых
  проблем (раздел 4).
- **Статический аудит записи в обход точек отказа** (раздел 5).
- **Аппаратный smoke-test** — [`SMOKE-TEST-5.2.0.md`](./SMOKE-TEST-5.2.0.md),
  9 сценариев на реальном железе (Windows Hello, Рутокен MFA, TPM 2.0, DPAPI).

## 2. Находки аудита 5.0.x

| ID | Находка | Статус | Исправление | Тесты | Остаток |
|---|---|---|---|---|---|
| H-01 | Откат `vault_create` удалял существующее хранилище | CLOSED | Отказ до побочных эффектов при любом живом файле; сборка в `.create-staging`, публикация переносом; TPM-ключ в журнале | `create_never_destroys_an_existing_vault`, `create_refuses_over_a_partial_vault_without_deleting_anything`, `create_is_atomic` | Частичное хранилище ведёт в онбординг, где создание и импорт отказывают без объяснения (доступность) |
| H-02 | Смена типа поля уничтожала значение | CLOSED | Значение перешифровывается под новый AAD в той же транзакции | `field_type_change_keeps_the_value`, `field_type_change_is_atomic` | — |
| H-03 | Изменение политики без повторной аутентификации | PARTIAL | Разрешение на одно действие: 120 с, одноразовое, привязано к сессии; `consume()` во всех командах политики. Вход по FIDO2 больше не выдаёт части восстановления без PIN (N-3) | `every_policy_change_requires_authorization`, `authorization_is_single_use`, `fido_unlock_does_not_grant_recovery_regeneration` | Настройки удобства (`autolock=никогда`, `clipboard=не очищать`, выключение истории паролей) меняются без PIN — N-5 |
| H-04 | FIDO2 не привязан к устройству | CLOSED | KEK = HKDF(PRF ‖ Device Secret из TPM), поверх DPAPI; полная RP-проверка ответа | `fido_key_with_copied_vault_on_another_device_does_not_unlock`, `unknown_fido_token_does_not_unlock`, `only_the_same_token_device_and_credential_unwrap` | Ключ «только касание» на этом ПК — один фактор; это осознанный выбор продукта |
| H-05 | Тупиковые fail-closed состояния | PARTIAL | Блокировка заменена нарастающей задержкой (30 с … 1 ч), строжайшее из метаданных и checkpoint'а | `pin_backoff_follows_the_schedule_and_never_locks_out`, `clock_rewind_applies_the_maximum_delay` | Пропавший checkpoint или удалённый ключ Hello — только восстановление по B и C |
| M-01 | Неатомарное восстановление | CLOSED | Одна транзакция `reseed`; старые ресурсы удаляет журнал после commit | `recovery_restore_is_atomic`, `recovery_restore_on_another_device_is_atomic` | — |
| M-02 | Restore откатывал политику | CLOSED | Restore заменяет только `records`/`web`; метаданные копии не используются | `restore_keeps_the_current_authentication_policy`, `restore_is_atomic_and_never_mixes_snapshots` | — |
| M-03 | Бэкап бесполезен без B+C после потери хранилища | CLOSED (тот же ПК) | Импорт на чистую установку: MAC проверяется, `reseal_import` не ослабляет эпоху и задержки → вход по PIN | `same_device_import_is_atomic`, `import_never_lowers_the_pin_backoff`, `tampered_bundle_is_rejected_on_the_source_device` | На другом ПК — только B и C (по замыслу) |
| M-04 | Нет ротации мастер-ключа | RESIDUAL | — | — | Старые B+C вместе со старой копией дают текущий мастер-ключ |
| M-05 | Откат и сращивание страниц баз | CLOSED | Ревизия растёт триггерами в той же транзакции; ревизия и SHA-256 файла — во внешнем checkpoint; принять откат можно только для показанного снимка | `swapping_in_old_databases_is_detected`, `spliced_old_pages_do_not_bring_back_old_data`, `accepting_a_rollback_is_bound_to_the_shown_snapshot` | Окно между commit и записью checkpoint'а (раздел 7) |
| M-06 | Неатомарный локальный якорь | CLOSED | Локального якоря нет; внешний checkpoint пишется атомарно (temp → fsync → `MoveFileExW`) | `wrong_pin_accounting_is_atomic`, `corrupted_external_checkpoint_fails_closed` | — |
| M-07 | Импорт CSV терял записи | CLOSED | Одна транзакция; отчёт об отклонённых строках; удаление исходника — только при полном импорте | `csv_import_is_all_or_nothing`, `partial_import_reports_every_rejected_row`, `import_chromium_csv_is_atomic` | — |
| M-08 | Смена PIN без сессии и в обход Hello | CLOSED | Нужны открытая сессия и `consume(ChangePin)`; сессию команда не открывает | `change_pin_never_opens_a_session`, `change_pin_is_atomic`, `retried_pin_change_is_recognised_as_done` | Ветка повтора по `request_id` — N-6 |
| M-09 | Релизный пайплайн | PARTIAL | `permissions: {}`, SHA-пины, `persist-credentials: false`, сборка без кэша и без install-скриптов (`npm ci --ignore-scripts`), обязательная attestation, publish — единственный job с `contents: write`; только ручной запуск | `src/lib/release.test.ts`; локально `actionlint`, `zizmor --persona pedantic` | Нет Authenticode; `npm audit`/`cargo deny` запускаются вручную перед релизом, не в релизном job; публикация ещё не проходила реальный запуск |
| L-01 | Неограниченные параметры Argon2 | CLOSED | Формат VLT4 удалён; параметры из метаданных ограничены до деривации | `stored_params_outside_the_safe_range_are_rejected` | — |
| L-02 | Старый SQLite и разбор недоверенных БД | PARTIAL | Read-only `quick_check`; схема метаданных сверяется с эталоном при каждом открытии (N-1) | `untrusted_file_validation_rejects_non_sqlite_and_foreign_databases`, `planted_schema_objects_are_rejected_on_open` | rusqlite 0.32 / SQLite не обновлены |
| L-03 | Ленивая автоблокировка | PARTIAL | `check_autolock` в начале команд и в `consume`; heartbeat 5 с | — | Фонового таймера в backend нет: зависший webview держит сессию |
| L-04 | Блокировка по сну | RESIDUAL | Документация исправлена: блокировка — при блокировке сеанса Windows | smoke 9.1–9.2 | Сообщения питания до окна `HWND_MESSAGE` не доходят; при сне защита держится на блокировке сеанса Windows |
| L-05 | `generator_copy` в обход step-up | CLOSED | Тот же гейт `require_copy_view_auth`, что у копирования секретов | — | — |
| L-06 | Fail-open буфера обмена | CLOSED | Маркеры исключения ставятся первыми; любой сбой очищает буфер до его закрытия | — (Win32) | — |
| L-07 | `recovery_restore` не закрывал сессию | CLOSED | Сессия закрывается в начале | `recovery_closes_the_session_and_rotates_every_key` | — |
| L-08 | Чтение метаданных до проверки MAC | PARTIAL | `verified_meta` перечитывает строку после проверки; схема под эталоном (N-1) | — | Несколько мест читают метаданные без MAC (имя ключа Hello для step-up, состояние генератора) |
| L-09 | Мёртвый код и зависимости | CLOSED | Удалены `rand_chacha`, `anyhow`, `tauri-plugin-fs`, неиспользуемые зависимости `core-shared`, лишние функции `windows`, ветки WebAuthn API < 6 (без PRF привязка невозможна), устаревшие комментарии | clippy `-D warnings` | — |
| L-10 | UV без проверки подписи | CLOSED | ES256 над authData ‖ SHA-256(clientData), rpIdHash, UP/UV по режиму | `every_forged_part_of_an_assertion_is_rejected` | signCount не проверяется |
| L-11 | FFI-структуры крупнее выделенных ОС | CLOSED | Общие поля читаются через V1, поля новых версий — только после проверки `dwVersion` | `webauthn_layout` | — |
| L-12 | Гигиена секретов в памяти | PARTIAL | `Zeroizing` для CSV и health check; Argon2 затирает рабочую память (`zeroize`) | — | PIN в IPC — обычная строка; health check расшифровывает все секреты при каждом списке |
| L-13 | Ретенция бэкапов, пустая `web.db` | PARTIAL | Пропавшая или пустая база — `DATA_ROLLBACK`; автобэкап по расписанию | `swapping_in_old_databases_is_detected` | Ретеншн по количеству: три вызова подряд вытесняют прежние копии |
| L-14 | Расхождения документации | CLOSED | README, SECURITY и комментарии сверены с кодом: FIDO2 — самостоятельный вход, p=4, actionlint/zizmor — локально, схема B+C | `release.test.ts` | — |
| I-01 | Hello — политика, а не ключевой материал | RESIDUAL | — | — | Принято; FIDO2-путь Hello не спрашивает (N-4) |
| I-02 | TPM-ключ без политики использования | RESIDUAL | — | — | Код того же пользователя подписывает без жеста |
| I-03 | RP ID `vaultisor.app` | RESIDUAL | — | — | Владение доменом не подтверждено |
| I-04 | Устройство + одна доля = захват | CLOSED | Часть A удалена: нужны обе части, B и C, на любом ПК | `one_share_is_not_enough_on_the_same_device` | — |
| I-05 | `panic = "abort"` и открытый ключ при сбое `CryptProtectMemory` | RESIDUAL | — | — | Защита от дампа памяти, а не граница доверия |
| I-06 | Транзитивные unmaintained-крейты | RESIDUAL | `cargo deny`, `cargo audit` | — | Unmaintained-крейты в SCA не видны |

**Итог:** CLOSED — 19, PARTIAL — 8, RESIDUAL — 7 (из 34).

## 3. Находки этапов консолидации

| ID | Находка | Как найдена | Статус | Тест |
|---|---|---|---|---|
| C-01 | Выключение Hello могло запереть хранилище (P0): ключ удалялся до commit | свип `hello_disable` | CLOSED — удаление после commit через журнал | `hello_disable_is_atomic` |
| C-02 | Неверный PIN не учитывался, если запись счётчика не удалась | свип `wrong_pin` | CLOSED — попытка списывается до проверки | `wrong_pin_accounting_is_atomic` |
| C-03 | Локальная часть A вне MAC | ревью этапа 3 | CLOSED — часть A удалена целиком | `one_share_is_not_enough_on_the_same_device` |
| C-04 | Неатомарная запись резервной копии | свип `backup` | CLOSED — temp → fsync → замена | `backup_is_atomic` |
| C-05 | Restore возвращал старые факторы входа | ревью этапа 3 | CLOSED — только `records`/`web` | `restore_keeps_the_current_authentication_policy` |
| C-06 | Повтор смены PIN с другим PIN | ревью идемпотентности | CLOSED — `request_id` и проверка, что новый PIN открывает обёртку | `retried_pin_change_is_recognised_as_done` |
| C-07 | Сращивание страниц баз (M-05 частично) | тест сращивания | CLOSED — дайджест файла в checkpoint'е | `spliced_old_pages_do_not_bring_back_old_data` |
| F-01 | `records_batch_delete` удалял частично и отвечал успехом | свип этапа 5 | CLOSED — одна транзакция | `records_batch_delete_is_atomic` |
| F-02 | Выключение истории паролей оставляло историю (флаг и две базы — три commit'а) | свип этапа 5 | CLOSED — включение начинается с очистки, вход дочищает | `password_history_disable_is_atomic` |
| F-03 | Конфиг бэкапа оставлял временный файл вне уборки | свип этапа 5 | CLOSED — `fsio::write_atomic` | `backup_set_config_is_atomic` |
| F-04 | Безопасное удаление CSV — 0 шагов, мимо точек отказа | свип этапа 5 | CLOSED — точки отказа перед затиранием и удалением | `secure_delete_file_is_atomic` |
| F-05 | Свип молча пропускал операцию с 0 шагов | свип этапа 5 | CLOSED — `sweep_report` требует хотя бы один шаг | весь набор |

## 4. Новые находки повторного аудита

| ID | Находка | Уровень | Статус | Исправление | Тест |
|---|---|---|---|---|---|
| N-1 | Схема `vault.meta.db` не под MAC: подложенный триггер заставлял приложение подписать подменённые значения (выключить Hello и step-up, обнулить задержки PIN) | Medium | CLOSED | Схема сверяется с эталоном при каждом открытии; любой лишний объект — `META_TAMPERED` | `planted_schema_objects_are_rejected_on_open` |
| N-2 | Журналы в `vault\` управляли удалением при старте: подложенная запись удаляла TPM-ключ, ключ Hello, checkpoint; маркер сборки — живые базы | Medium | CLOSED | Журнал ресурсов ОС — в профиле пользователя рядом с checkpoint'ами; откат сборки не трогает файлы, если есть живые метаданные | `journal_planted_in_the_vault_folder_deletes_nothing`, `planted_staging_marker_never_deletes_a_live_vault` |
| N-3 | Вход по FIDO2 выдавал разрешение на новые части без PIN | Low–Medium | CLOSED | Разрешение выдаёт только вход по PIN; после FIDO2 интерфейс спрашивает PIN | `fido_unlock_does_not_grant_recovery_regeneration` |
| N-4 | Вход по FIDO2 минует Windows Hello | Low | RESIDUAL (по замыслу) | FIDO2 — самостоятельный путь входа; README и SECURITY это описывают | — |
| N-5 | Настройки удобства без повторного PIN | Low | RESIDUAL | — | — |
| N-6 | Ветка повтора `change_pin` проверяет PIN вне задержек | Low/Info | RESIDUAL | Нужны открытая сессия и `request_id` последней смены PIN | — |

## 5. Покрытие отказами

40 свипов (Crash и Error на каждом шаге). Новые свипы этапа 5:

| Свип | Шагов | Старое / новое (на режим) |
|---|---|---|
| generator_create / generator_delete | 5 / 5 | 1 / 4 |
| settings_update, set_ui_language, set_enable_health_check, set_enable_generator, set_enable_password_history(true) | 4 | 1 / 3 |
| set_enable_password_history(false) | 14 | только старое или новое — после исправления F-02 |
| vault_unlock после неверных PIN | 8 | 5 / 3 |
| vault_unlock_with_fido2 после неверных PIN | 4 | 1 / 3 |
| vault_unlock_accept_rollback | 12 | 8 / 4 |
| recovery_acknowledge | 4 | 1 / 3 |
| backup_set_config | 2 | 2 / 0 |
| import_chromium_csv | 5 | 1 / 4 |
| secure_delete_file | 2 | 1 / 1 |
| record_update, record_delete, records_batch_delete, record_reorder, record_restore_password_history, record_clear_password_history | 5 | 1 / 4 |

Свипы этапов 2–4: create (54 шага), Hello вкл./выкл. (18/18), смена PIN (7),
неверный PIN (7), FIDO2 привязка/отвязка (8/7), step-up (7), восстановление на
том же и другом ПК (27/27), новое поколение / отключение восстановления (4/4),
бэкап (4), restore (18), импорт на том же и другом ПК (22/25), изменение
записей и паролей сайтов (5/5).

**Запись в обход точек отказа** (статический аудит): осталась одна мелочь —
`RecordsDb::set_revision` при принятии отката и rebase после импорта пишет без
своей точки отказа (свип accept_rollback проходит, но сбой между двумя
записями ревизий не моделируется); удаление старых копий ретеншном идёт вне
хранилища. Остальное идёт через `fsio`, `MetaDb`/`RecordsDb`, журнал ОС или
временные файлы вне хранилища.

## 6. Статусы pipeline

- **Attestation:** обязательна в `release.yml` (publish без неё не запускается);
  доступна, так как репозиторий публичный. Первая проверка — на релизе 5.2.0:
  `gh attestation verify Vaultisor-5.2.0.exe --repo vasilydupidu/Vaultisor`.
- **Actions E2E:** проверки и сборка артефакта прошли реальный запуск на GitHub
  (CI, audit и пробная релизная сборка, 2026-10-05). Публикация релиза реальным
  запуском ещё не проверена — это первый релиз.

## 7. Остаточные риски

1. **Нет ротации мастер-ключа (M-04).** Скомпрометированные B и C вместе со
   старой копией дают доступ; новое поколение частей этого не отменяет.
2. **Окно commit → checkpoint.** Сбой между commit базы и записью внешнего
   checkpoint'а оставляет базу на ревизию впереди; первый вход её догоняет.
   Без аппаратного монотонного счётчика (TPM NV) окно не закрыть.
3. **TOCTOU хэширования.** Дайджест файла базы считается после commit; код того
   же пользователя может подменить файл между commit и хэшированием.
4. **Вредоносный код в сессии пользователя.** Он получает Device Secret без
   жеста, расшифровывает DPAPI и дожидается разблокировки. TPM, DPAPI и
   `CryptProtectMemory` повышают цену атаки, но не отменяют её (I-02, I-05).
5. **FIDO2 «только касание»** — один фактор владения на этом ПК; FIDO2-путь не
   спрашивает Hello (H-04, N-4). Осознанный выбор продукта.
6. **Fail-closed без запасного входа (H-05).** Пропавший checkpoint или
   удалённый в Windows ключ Hello оставляют только восстановление по B и C.
7. **Настройки удобства без PIN (N-5)** и **ленивая автоблокировка (L-03).**
8. **Сон (L-04):** Vaultisor блокируется вместе с сеансом Windows; если Windows
   не требует входа после сна, хранилище остаётся открытым до автоблокировки.
9. **Нет Authenticode-подписи.** Целостность — SHA-256 и provenance-attestation.
10. **SQLite/SQLCipher** не обновлены до последних версий (L-02).
11. **Без нормализации Unicode.** Парольная фраза не приводится к NFC: при
    разной нормализации ввода (редкие IME) хранилище не откроется тем же вводом.
12. **Счётчик подписей FIDO2 не проверяется.** Клон аппаратного токена не
    получит секрет hmac-secret, а проверка счётчика рискует запереть владельца
    токеном с нестандартным счётчиком.
13. **Старые копии хранилища.** Смена PIN и новое поколение частей не отзывают
    прежние резервные копии: старые B и C вместе со старой копией открывают
    хранилище (нет ротации мастер-ключа, п. 1).
14. **Удаление записей и очистка истории без подтверждения** — осознанное
    решение продукта (данные возвращаются из копии через restore под PIN).

## 8. Второй независимый аудит (отчёт VLT-01 … VLT-33)

Внешний аудит версии 5.2.0 (24.10.2026) перепроверен по коду: каждая находка
и каждый её подпункт оценены отдельно, уровни критичности пересмотрены (в
релизе `panic = "abort"`, поэтому сценарии «паника → утечка или отравленный
мьютекс» к нему не относятся; многие находки требуют кода под той же
учётной записью Windows, а это граница модели угроз, п. 4 раздела 7).
Исправлено всё реальное; ложные срабатывания и осознанные решения
перечислены с причиной.

| ID | Находка | Итог | Что сделано / почему не делалось |
|---|---|---|---|
| VLT-01 | Импорт копии на том же ПК снимал Hello и подтверждение копирования, возвращал старый PIN и тихо принимал старые данные | CLOSED (реальный уровень Medium/High, не Critical) | Checkpoint v5 помнит политику входа; импорт, который её ослабил бы, или без checkpoint'а, не запечатывается — вход только по B и C; копия старее подтверждённого состояния требует решения с PIN. Тесты: `import_cannot_switch_off_windows_hello`, `import_cannot_bring_back_an_old_pin`, `import_without_a_checkpoint_needs_the_recovery_parts`, `import_of_an_older_copy_needs_an_explicit_decision`. Остаток: старые B+C со старой копией (п. 13) |
| VLT-02 | `EncryptedMemoryBuffer`: тихий отказ `CryptProtectMemory`, копии массива | CLOSED | `is_protected()`, предупреждение в журнал через `seal_master_key`, конструктор по `&mut` затирает массив вызывающего. Паника при раскрутке — неприменимо (`panic=abort`) |
| VLT-03 | FIDO2 Touch-only: расхождение UV при регистрации и входе | FALSE POSITIVE | Секрет берётся из проверочного входа с тем же требованием UV, что и при обычном входе; при регистрации hmac-secret не запрашивается |
| VLT-04 | Секрет PRF в буфере `webauthn.dll` не затирался | CLOSED | `take_hmac_secret` копирует в `Zeroizing` и затирает оба буфера ОС до `WebAuthNFreeAssertion`; тесты `prf_wipe_tests` |
| VLT-05 | Удаление записей и очистка истории без подтверждения | ACCEPTED | Решение продукта: без подтверждения (п. 14 раздела 7, SECURITY.md «Не защищает» п. 9) |
| VLT-06 | `require_copy_view_auth` читал данные Hello без проверки MAC | CLOSED | `verify_meta_integrity` до чтения; тест с подменой имени credential'а |
| VLT-07 | Чтение файлов без лимита, хэш всей базы на каждый commit | CLOSED | Лимиты (копия 512 МиБ, часть 64 КиБ), отказ симлинкам и не-файлам; `file_digest` потоковый |
| VLT-08 | Проверка здоровья паролей расшифровывала всё на каждый список | CLOSED | Кэш по ревизии базы (только id, без открытых значений); команды выполняются вне потока интерфейса |
| VLT-09 | Сбои после входа по FIDO2 (`pending`, откат) | CLOSED | Выдача частей спрашивает PIN, откат объясняет вход по PIN |
| VLT-10 | Восстановление: один слот файла, символы пароля без TPM | CLOSED | Два слота B и C; без TPM пароль не обрезается; тесты |
| VLT-11 | Нет W3C VC; нет защиты от IDN-гомографов | NOT A DEFECT | VC — продуктовая функция; гомографы опасны при автозаполнении, а его нет |
| VLT-12 | WebAuthn RP: `signCount`, дубли CBOR | PARTIAL | Дубли меток COSE отвергаются; `signCount` намеренно не проверяется (п. 12 раздела 7); `clientData` при регистрации собирает само приложение |
| VLT-13 | Повтор `change_pin` вне задержек; настройки удобства без PIN | CLOSED (1), ACCEPTED (2) | Повтор идёт через те же задержки; формат проверяется до подтверждения; настройки удобства — вне гарантии |
| VLT-14 | Тривиальные парольные фразы, нет NFC | PARTIAL | Отвергаются пустые, из одного символа и с менее чем 6 разными символами (backend и фронтенд); NFC не добавлялся (п. 11) |
| VLT-15 | Гигиена `shamir`, `aead`, `kdf`, `open_envelope` | CLOSED | `Zeroizing` для точек Шамира и результата `aead::decrypt`; предел 4 долей; `combined` в `kdf` затирался и раньше |
| VLT-16 | UNC и сетевые пути | CLOSED | Единая проверка канонического пути (`reject_network_path`); утечка NTLM по чужому пути невозможна — пути только из системного диалога |
| VLT-17 | Повторное включение истории стирало её | CLOSED (удержание мьютекса сессии при записи — Low, принято) | Повтор того же значения — пустая операция; тест `enabling_password_history_again_keeps_it` |
| VLT-18 | `vault_exists` не согласован с созданием и импортом | CLOSED | Любой из трёх файлов → экран входа; вход в неполное хранилище объясняет, что делать |
| VLT-19 | `GetMessageW(-1)`, окно диалога FIDO2, `ShowWindow` из фонового потока | CLOSED (1)(2), NOT REPRODUCIBLE (3) | Три значения результата `GetMessageW`; диалоги FIDO2 привязаны к окну приложения |
| VLT-20 | Отравление мьютексов; поток на каждое копирование; формат DWORD | FALSE POSITIVE / ACCEPTED | В релизе нет раскрутки стека; поток спит не более 120 с; формат маркера соответствует требованиям |
| VLT-21 | Проглоченные ошибки архива истории и `backup.json` | CLOSED | Ошибки пробрасываются, транзакция откатывается целиком; повтор запроса дописывает `last_backup` |
| VLT-22 | Валидация IPC | CLOSED | Неизвестный `db_type` отвергается, `deny_unknown_fields`, серверные id новых полей, лимит `clipboard_copy_text`; срок очистки буфера в `clipboard_copy_secret` — только из настроек |
| VLT-23 | Блокирующий I/O, SQL в цикле, индекс | CLOSED (1)(2) | Команды записей, генератора, импорта и восстановления выполняются в фоновом пуле; остальное несущественно |
| VLT-24 | Смещение генератора фразы, `sanitizeError` | CLOSED | Выборка с отбраковкой; коды `AUTH_REQUIRED` и `DATA_ROLLBACK` не попадают в сообщения |
| VLT-25 | Несогласованные подсказки и проверки | CLOSED | Формат нового PIN проверяется до запроса подтверждения; тексты исправлены |
| VLT-26 | Размер файлов, `check_autolock` в бэкапе | NOT A DEFECT | Стиль; обхода автоблокировки нет |
| VLT-27 | Тесты и `FakePlatform` | CLOSED | `if let Ok` заменён на `expect`; тест временных файлов ищет настоящий префикс; `hello_verify` сверяет ключ |
| VLT-28 | Пайплайн и артефакты | CLOSED | `-Clean` чистит `target`, не трогая `release\vault`; заметки к релизу актуальны |
| VLT-29 | Лишние зависимости, права CI | CLOSED | Удалены; права и `npm ci --ignore-scripts` |
| VLT-30 | Защитное программирование | CLOSED | Насыщающая арифметика в задержках, проверяемые касты в DPAPI, имя TPM-ключа в AAD |
| VLT-31 | Локальное время в именах копий | CLOSED | Ретеншн по времени изменения файла |
| VLT-32 | Мелочи UI и i18n | CLOSED | Зашитые строки в i18n, теги без `className` в локалях |
| VLT-33 | Метаданные и документация | CLOSED | Текст `tauri.conf.json`, TODO, баннер «исторический документ» |

Итог по 33 находкам: CLOSED — 24, PARTIAL — 2, ACCEPTED — 3 (VLT-05, VLT-13(2),
VLT-17 остаток), ложные срабатывания и не-дефекты — 4 (VLT-03, VLT-11, VLT-20,
VLT-26).
