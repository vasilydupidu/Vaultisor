//! Закрытые замечания аудита по командам: кэш проверки паролей, смена PIN,
//! проверка входных значений IPC, сбои, которые нельзя глотать, сохранность
//! конфига резервных копий, неполное хранилище, предел числа долей и
//! целостность метаданных в гейте копирования.

use super::data_flow::{add, entry, unlocked};
use super::harness::{arm, observed, Env, NEW_PIN, PIN};
use super::recovery_flow::{created, restore_input};
use crate::commands::file_grants::FileOperation;
use crate::commands::records::{GetInput, ListInput};
use crate::commands::security::SecurityAction;
use crate::commands::vault::ChangePinInput;
use crate::error::VaultError;
use crate::failpoint::Mode;
use crate::storage::records::{FieldInput, FieldType, RecordInput};

fn request() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ------------------------------------------------------------ кэш проверки паролей

fn list(env: &Env, db_type: &str) -> Vec<crate::storage::records::Record> {
    crate::commands::records::list_entries(
        &env.state,
        ListInput {
            query: None,
            category: None,
            limit: None,
            offset: None,
            db_type: db_type.into(),
        },
    )
    .expect("list")
}

fn health_runs(env: &Env) -> u64 {
    env.with_session(|_, records, _| records.health_runs())
        .expect("unlocked")
}

fn flags_of(list: &[crate::storage::records::Record], name: &str) -> (bool, bool) {
    let record = list.iter().find(|r| r.name == name).expect("record");
    (record.has_weak, record.has_reused)
}

#[tokio::test]
async fn health_check_decrypts_once_per_database_revision() {
    let (env, _) = unlocked().await;
    assert_eq!(health_runs(&env), 0);

    let first = list(&env, "records");
    assert_eq!(health_runs(&env), 1, "первый список считает проверку");
    let second = list(&env, "records");
    let third = list(&env, "records");
    assert_eq!(
        health_runs(&env),
        1,
        "без записей список не расшифровывает базу заново"
    );
    assert_eq!(first.len(), second.len());
    assert_eq!(first.len(), third.len());
    // Чтение карточки базу не меняет.
    let id = first[0].id.clone();
    crate::commands::records::get_entry(
        &env.state,
        GetInput {
            id,
            db_type: "records".into(),
        },
    )
    .expect("get");
    list(&env, "records");
    assert_eq!(health_runs(&env), 1);
}

#[tokio::test]
async fn write_invalidates_the_health_cache_and_flags_follow_the_data() {
    let (env, _) = unlocked().await;
    let a = add(&env, false, "dup-A").expect("A");
    add(&env, false, "dup-B").expect("B");
    let before = list(&env, "records");
    // Одинаковое значение «secret» у двух записей: слабый и повторяющийся.
    assert_eq!(flags_of(&before, "dup-A"), (true, true));
    assert_eq!(flags_of(&before, "dup-B"), (true, true));
    let runs = health_runs(&env);

    // Меняем значение одной записи на сильное и уникальное.
    let field = field_ids(&env, &a).remove(0);
    env.with_session(|master, records, _| {
        crate::storage::records::update_record(
            records,
            master,
            &a,
            &RecordInput {
                fields: vec![FieldInput {
                    id: Some(field.clone()),
                    field_type: FieldType::Secret,
                    label: "password".into(),
                    is_secret: true,
                    sort_order: 0,
                    value: Some("Zq7#vLp2-unique-strong".into()),
                }],
                ..entry("dup-A", "x")
            },
            false,
        )
    })
    .unwrap()
    .unwrap();

    let after = list(&env, "records");
    assert_eq!(
        health_runs(&env),
        runs + 1,
        "запись увеличила ревизию — кэш пересчитан"
    );
    assert_eq!(flags_of(&after, "dup-A"), (false, false));
    assert_eq!(flags_of(&after, "dup-B"), (true, false));
}

#[tokio::test]
async fn health_cache_does_not_survive_lock() {
    let (env, _) = unlocked().await;
    list(&env, "records");
    assert_eq!(health_runs(&env), 1);
    env.state.lock();
    env.unlock(PIN).await.expect("unlock");
    assert_eq!(
        health_runs(&env),
        0,
        "новая сессия — новая база без унаследованного кэша"
    );
    list(&env, "records");
    assert_eq!(health_runs(&env), 1);
}

// ------------------------------------------------------------ смена PIN

async fn change_pin(env: &Env, id: &str, pin: &str) -> crate::error::Result<()> {
    crate::commands::vault::change_pin(
        &env.state,
        ChangePinInput {
            new_pin: pin.into(),
            request_id: id.into(),
        },
    )
    .await
}

#[tokio::test]
async fn invalid_new_pin_does_not_burn_the_authorization() {
    let (env, _) = unlocked().await;
    env.authorize(SecurityAction::ChangePin).await;
    for bad in ["12345", "00000000000", "           ", "abababababab"] {
        assert!(
            matches!(
                change_pin(&env, &request(), bad).await,
                Err(VaultError::BadInput(_))
            ),
            "{bad:?}"
        );
    }
    // Подтверждение осталось и годится для корректного PIN.
    change_pin(&env, &request(), NEW_PIN)
        .await
        .expect("authorization is still usable");
}

#[tokio::test]
async fn wrong_retry_of_pin_change_is_charged_like_a_lock_screen_attempt() {
    let (env, _) = unlocked().await;
    let id = request();
    env.authorize(SecurityAction::ChangePin).await;
    change_pin(&env, &id, NEW_PIN).await.expect("change");
    assert_eq!(env.backoff().failures, 0);

    // Другой PIN под тем же request_id — это угадывание текущего PIN.
    for attempt in 1..=3u32 {
        let result = change_pin(&env, &id, "93847561029").await;
        assert!(matches!(result, Err(VaultError::BadInput(_))), "{result:?}");
        assert_eq!(env.backoff().failures, attempt, "попытка {attempt} списана");
    }
    // Верный повтор снимает списание, как верный вход.
    change_pin(&env, &id, NEW_PIN).await.expect("same retry");
    assert_eq!(env.backoff().failures, 0);

    // После порога задержка останавливает перебор и здесь.
    for _ in 0..6 {
        let _ = change_pin(&env, &id, "93847561029").await;
    }
    assert!(matches!(
        change_pin(&env, &id, "93847561029").await,
        Err(VaultError::PinBackoff(_))
    ));
    assert!(
        matches!(
            change_pin(&env, &id, NEW_PIN).await,
            Err(VaultError::PinBackoff(_))
        ),
        "пока идёт задержка, не проверяется и верный PIN"
    );
}

// ------------------------------------------------------------ IPC: типы и идентификаторы

#[tokio::test]
async fn unknown_db_type_is_rejected_by_commands() {
    let (env, _) = unlocked().await;
    for bad in ["", "Web", "other", "records2"] {
        let result = crate::commands::records::list_entries(
            &env.state,
            ListInput {
                query: None,
                category: None,
                limit: None,
                offset: None,
                db_type: bad.into(),
            },
        );
        assert!(matches!(result, Err(VaultError::BadInput(_))), "{bad:?}");
    }
}

fn secret_field(id: Option<&str>, label: &str, value: Option<&str>) -> FieldInput {
    FieldInput {
        id: id.map(str::to_owned),
        field_type: FieldType::Secret,
        label: label.into(),
        is_secret: true,
        sort_order: 0,
        value: value.map(str::to_owned),
    }
}

fn record_with(fields: Vec<FieldInput>) -> RecordInput {
    RecordInput {
        fields,
        ..entry("rec", "x")
    }
}

fn update(env: &Env, id: &str, input: &RecordInput, history: bool) -> crate::error::Result<()> {
    env.with_session(|master, records, _| {
        crate::storage::records::update_record(records, master, id, input, history)
    })
    .expect("unlocked")
}

fn field_ids(env: &Env, record: &str) -> Vec<String> {
    env.with_session(|_, records, _| {
        crate::storage::records::get_record(records, record)
            .expect("record")
            .fields
            .into_iter()
            .map(|f| f.id)
            .collect()
    })
    .expect("unlocked")
}

fn reveal(env: &Env, record: &str, field: &str) -> String {
    env.with_session(|master, records, _| {
        crate::storage::records::reveal_field(records, master, record, field)
            .expect("reveal")
            .to_string()
    })
    .expect("unlocked")
}

#[tokio::test]
async fn duplicate_field_ids_in_one_update_are_rejected() {
    let (env, _) = unlocked().await;
    let id = add(&env, false, "dup").expect("record");
    let field = field_ids(&env, &id).remove(0);
    let input = record_with(vec![
        secret_field(Some(&field), "a", Some("one-value")),
        secret_field(Some(&field), "b", Some("two-value")),
    ]);
    let result = update(&env, &id, &input, true);
    assert!(matches!(result, Err(VaultError::BadInput(_))), "{result:?}");
    assert_eq!(reveal(&env, &id, &field), "secret", "ничего не изменилось");
}

#[tokio::test]
async fn client_chosen_ids_of_new_fields_are_replaced_by_server_ids() {
    let (env, _) = unlocked().await;
    let victim = add(&env, false, "victim").expect("victim");
    let victim_field = field_ids(&env, &victim).remove(0);
    let own = add(&env, false, "own").expect("own");
    let own_field = field_ids(&env, &own).remove(0);

    let input = record_with(vec![
        secret_field(Some(&own_field), "kept", None),
        // Выдуманный идентификатор и идентификатор поля ЧУЖОЙ записи.
        secret_field(Some("client-chosen"), "invented", Some("invented-value")),
        secret_field(Some(&victim_field), "hijack", Some("hijack-value")),
    ]);
    update(&env, &own, &input, true).expect("update");

    let ids = field_ids(&env, &own);
    assert_eq!(ids.len(), 3);
    assert!(ids.contains(&own_field), "существующее поле осталось");
    assert!(!ids.contains(&"client-chosen".to_string()));
    assert!(
        !ids.contains(&victim_field),
        "поле другой записи не присваивается"
    );
    assert_eq!(
        reveal(&env, &victim, &victim_field),
        "secret",
        "чужое поле не тронуто"
    );
    assert_eq!(field_ids(&env, &victim), vec![victim_field]);

    // Новое поле без значения по-прежнему отвергается.
    let bad = record_with(vec![secret_field(Some("anything"), "x", None)]);
    assert!(matches!(
        update(&env, &own, &bad, true),
        Err(VaultError::BadInput(_))
    ));
}

// ------------------------------------------------------------ сбои истории паролей

#[tokio::test]
async fn failed_history_archive_fails_the_whole_update() {
    let (env, _) = unlocked().await;
    let id = add(&env, false, "keep-me").expect("record");
    let field = field_ids(&env, &id).remove(0);
    env.with_session(|_, records, _| {
        records
            .with_conn(|c| {
                c.execute_batch(
                    "CREATE TRIGGER no_history BEFORE INSERT ON record_password_history \
                     BEGIN SELECT RAISE(ABORT, 'blocked'); END;",
                )?;
                Ok(())
            })
            .expect("trigger")
    })
    .unwrap();

    let mut input = record_with(vec![secret_field(
        Some(&field),
        "password",
        Some("new-value-1"),
    )]);
    input.name = "renamed".into();
    assert!(
        update(&env, &id, &input, true).is_err(),
        "не удалось заархивировать — обновление не проходит"
    );
    let record = env
        .with_session(|_, records, _| crate::storage::records::get_record(records, &id).unwrap())
        .unwrap();
    assert_eq!(
        record.name, "keep-me",
        "имя не изменилось: транзакция откатилась"
    );
    assert_eq!(reveal(&env, &id, &field), "secret");

    // Без истории то же обновление проходит: отказ был именно из-за архива.
    update(&env, &id, &input, false).expect("update without history");
    assert_eq!(reveal(&env, &id, &field), "new-value-1");
}

// ------------------------------------------------------------ резервные копии

async fn backup_ready() -> (Env, std::path::PathBuf) {
    let (env, _) = unlocked().await;
    let dir = env.root.parent().unwrap().join("backups");
    std::fs::create_dir_all(&dir).unwrap();
    env.authorize(SecurityAction::ChangeBackupDirectory).await;
    let capability = env.grant(&dir, FileOperation::BackupDirectory);
    crate::commands::backup::set_backup_config(
        &env.state,
        crate::commands::backup::BackupSetInput {
            directory_capability: Some(capability),
            frequency: "daily".into(),
        },
    )
    .unwrap();
    (env, dir)
}

fn last_backup(env: &Env) -> chrono::DateTime<chrono::FixedOffset> {
    let config = crate::commands::backup::read_config(&env.state).expect("config");
    chrono::DateTime::parse_from_rfc3339(&config.last_backup.expect("last_backup")).unwrap()
}

#[tokio::test]
async fn config_write_failure_after_backup_is_reported_and_repaired_by_retry() {
    let (env, dir) = backup_ready().await;
    // Первая копия: заодно снимаем трассу шагов персистентности.
    arm(None);
    crate::commands::backup::backup_now_blocking(&env.state, &request()).unwrap();
    let (_, trace) = observed();
    let config_write = trace
        .iter()
        .rposition(|point| *point == "fs.write_temp")
        .expect("config is written last")
        + 1;
    let old = last_backup(&env);

    // Вторая копия: отказ ровно на записи конфига.
    let id = request();
    arm(Some((config_write, Mode::Error)));
    let failed = crate::commands::backup::backup_now_blocking(&env.state, &id);
    assert!(
        matches!(failed, Err(VaultError::Injected(_))),
        "ошибка записи конфига не глотается: {failed:?}"
    );
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        2,
        "сама копия уже записана"
    );
    assert_eq!(last_backup(&env), old, "last_backup не обновился");

    // Повтор того же запроса находит копию и дописывает конфиг.
    arm(None);
    let retried = crate::commands::backup::backup_now_blocking(&env.state, &id).unwrap();
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2, "дубликата нет");
    assert!(retried.path.contains(&id[..8]));
    assert!(last_backup(&env) > old, "last_backup догнан повтором");
}

// ------------------------------------------------------------ неполное хранилище

#[tokio::test]
async fn vault_exists_when_any_of_the_three_files_exists() {
    let env = Env::new();
    assert!(!crate::commands::system::vault_exists_at(&env.state).unwrap());
    env.create().await;
    env.state.lock();
    assert!(crate::commands::system::vault_exists_at(&env.state).unwrap());

    for survivor in ["vault.meta.db", "vault.records.db", "vault.web.db"] {
        let mut env = Env::new();
        env.create().await;
        env.state.lock();
        for name in ["vault.meta.db", "vault.records.db", "vault.web.db"] {
            if name != survivor {
                std::fs::remove_file(env.root.join(name)).unwrap();
            }
        }
        env.restart();
        assert!(
            crate::commands::system::vault_exists_at(&env.state).unwrap(),
            "остался только {survivor}"
        );
    }
}

#[tokio::test]
async fn incomplete_vault_explains_what_to_do_and_creates_nothing() {
    let mut env = Env::new();
    env.create().await;
    env.state.lock();
    std::fs::remove_file(env.root.join("vault.meta.db")).unwrap();
    env.restart();

    let error = crate::commands::system::require_complete_vault(&env.state).unwrap_err();
    let VaultError::BadInput(message) = error else {
        panic!("ожидалась понятная ошибка, получено {error:?}");
    };
    assert!(message.contains("vault.meta.db"), "{message}");
    assert!(
        message.contains("импортируйте резервную копию"),
        "{message}"
    );
    assert!(message.contains("B и C"), "{message}");

    // Вход по FIDO2 идёт тем же путём и не плодит пустые метаданные.
    let fido = crate::commands::vault::unlock_with_fido2(&env.state).await;
    assert!(matches!(fido, Err(VaultError::BadInput(_))), "{fido:?}");
    assert!(!env.root.join("vault.meta.db").exists());
}

#[tokio::test]
async fn missing_records_database_is_named_in_the_message() {
    let mut env = Env::new();
    env.create().await;
    env.state.lock();
    std::fs::remove_file(env.root.join("vault.records.db")).unwrap();
    env.restart();
    let VaultError::BadInput(message) =
        crate::commands::system::require_complete_vault(&env.state).unwrap_err()
    else {
        panic!("ожидалась понятная ошибка");
    };
    assert!(message.contains("vault.records.db"), "{message}");
    assert!(!message.contains("vault.meta.db"), "{message}");
}

// ------------------------------------------------------------ доли восстановления

#[tokio::test]
async fn too_many_shares_are_rejected_up_front() {
    let (env, shares) = created().await;
    env.unlock(PIN).await.expect("unlock");
    let mut input = restore_input(&shares, NEW_PIN);
    input.shares_hex = std::iter::repeat_n(shares.b.clone(), 5).collect();
    let result = crate::commands::recovery::restore_from_shares(&env.state, input).await;
    assert!(matches!(result, Err(VaultError::BadInput(_))), "{result:?}");
    assert!(
        env.state.session.lock().is_unlocked(),
        "отказ по числу долей не запирает сессию"
    );
}

// ------------------------------------------------------------ гейт копирования

async fn gate_env() -> Env {
    let (env, _) = unlocked().await;
    env.enable_hello().await;
    env.authorize(SecurityAction::EnableStepUp).await;
    crate::commands::settings::set_step_up(&env.state, true)
        .await
        .expect("enable step-up");
    env
}

#[tokio::test]
async fn copy_gate_prompts_hello_for_intact_metadata() {
    let env = gate_env().await;
    crate::commands::auth_gate::require_copy_view_auth(&env.state)
        .await
        .expect("Hello passes on intact metadata");
}

#[tokio::test]
async fn copy_gate_refuses_tampered_credential_row() {
    let env = gate_env().await;
    let connection = rusqlite::Connection::open(env.state.meta_path()).unwrap();
    connection
        .execute(
            "UPDATE vault_meta SET hello_key_credential_name = 'attacker-credential' WHERE id = 1",
            [],
        )
        .unwrap();
    drop(connection);
    let result = crate::commands::auth_gate::require_copy_view_auth(&env.state).await;
    assert!(
        matches!(result, Err(VaultError::MetaTampered)),
        "{result:?}"
    );
}
