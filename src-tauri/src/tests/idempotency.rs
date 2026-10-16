//! Повтор после «commit состоялся, ответ потерян» и монотонность
//! подтверждённой ревизии баз.
//!
//! Потерянный ответ моделируется отказом на шаге после commit: операция
//! уже изменила состояние, но вызывающий видит ошибку и повторяет запрос.

use super::harness::{arm, observed, Env, CANARY, NEW_PIN, PIN};
use super::recovery_flow::{created, meta, restore_input};
use crate::commands::file_grants::FileOperation;
use crate::commands::security::SecurityAction;
use crate::failpoint::Mode;
use crate::storage::records::{FieldInput, FieldType, RecordInput};

fn request() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn entry(name: &str) -> RecordInput {
    RecordInput {
        name: name.into(),
        project: None,
        icon: None,
        color: None,
        category: Some("personal".into()),
        fields: vec![FieldInput {
            id: None,
            field_type: FieldType::Secret,
            label: "password".into(),
            is_secret: true,
            sort_order: 0,
            value: Some("secret".into()),
        }],
    }
}

fn create(env: &Env, request_id: &str) -> crate::error::Result<String> {
    env.with_session(|master, records, _| {
        crate::storage::records::create_record(records, master, &entry("item"), Some(request_id))
    })
    .expect("unlocked")
}

fn records(env: &Env) -> usize {
    env.with_session(|_, records, _| {
        crate::storage::records::list_records(records, None, false, None, None, 100, 0)
            .unwrap()
            .len()
    })
    .expect("unlocked")
}

/// Номер шага `name` в трассе успешного прогона `run`.
fn step_of(trace: &[&'static str], name: &str) -> usize {
    trace
        .iter()
        .position(|step| *step == name)
        .unwrap_or_else(|| panic!("шага {name} нет в {trace:?}"))
        + 1
}

async fn unlocked() -> Env {
    let (env, _) = created().await;
    env.unlock(PIN).await.unwrap();
    env
}

#[tokio::test]
async fn retried_record_create_does_not_duplicate() {
    // Ответ потерян: запись закоммичена, подтверждение ревизии не удалось.
    let env = unlocked().await;
    arm(None);
    create(&env, &request()).unwrap();
    let (_, trace) = observed();
    let after_commit = step_of(&trace, "revision.checkpoint");

    let env = unlocked().await;
    let before = records(&env);
    let id = request();
    arm(Some((after_commit, Mode::Error)));
    assert!(create(&env, &id).is_err(), "вызывающий видит ошибку");
    let first = records(&env);
    assert_eq!(first, before + 1, "но запись уже закоммичена");
    let again = create(&env, &id).expect("повтор успешен");
    let again_twice = create(&env, &id).unwrap();
    assert_eq!(again, again_twice);
    assert_eq!(records(&env), before + 1, "дубликата нет");
    // Другой запрос — другая запись.
    create(&env, &request()).unwrap();
    assert_eq!(records(&env), before + 2);
}

#[tokio::test]
async fn reimporting_the_same_csv_does_not_duplicate() {
    const CSV: &str =
        "name,url,username,password\nA,https://a.example,u1,P1\nB,https://b.example,u2,P2\n";
    let env = unlocked().await;
    let import = || {
        env.with_session(|master, _, web| {
            crate::commands::import::import_entries(
                web,
                master,
                crate::commands::import::parse_chromium_csv(CSV),
                Some("csv-same-content"),
            )
        })
        .unwrap()
        .unwrap()
    };
    let first = import();
    let second = import();
    assert_eq!(first.imported_ids, second.imported_ids);
    let count = env
        .with_session(|_, _, web| {
            crate::storage::records::list_records(web, None, false, None, None, 100, 0)
                .unwrap()
                .len()
        })
        .unwrap();
    assert_eq!(count, 2);
}

#[tokio::test]
async fn retried_fido_bind_returns_the_existing_binding() {
    let env = unlocked().await;
    let id = request();
    env.authorize(SecurityAction::BindFido).await;
    let first = crate::commands::settings::bind_fido2_key(&env.state, None, Some(false), &id)
        .await
        .unwrap();
    let credentials = env.fake.fido_credentials();
    // Повтор: без нового подтверждения и без второго credential на токене.
    let second = crate::commands::settings::bind_fido2_key(&env.state, None, Some(false), &id)
        .await
        .unwrap();
    assert_eq!(first.id, second.id);
    assert_eq!(env.fake.fido_credentials(), credentials);
    assert_eq!(
        env.state
            .open_meta()
            .unwrap()
            .get_fido2_keys()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn retried_pin_change_is_recognised_as_done() {
    let mut env = unlocked().await;
    let id = request();
    env.authorize(SecurityAction::ChangePin).await;
    let change = |request_id: String| {
        crate::commands::vault::change_pin(
            &env.state,
            crate::commands::vault::ChangePinInput {
                new_pin: NEW_PIN.into(),
                request_id,
            },
        )
    };
    change(id.clone()).await.unwrap();
    let wrapper = meta(&env).wrapped_master_dpapi;
    // Повтор того же запроса: ни подтверждения старым PIN, ни новой обёртки.
    change(id.clone()).await.unwrap();
    assert_eq!(meta(&env).wrapped_master_dpapi, wrapper);
    // Тот же запрос с другим PIN не выдаётся за выполненный.
    assert!(crate::commands::vault::change_pin(
        &env.state,
        crate::commands::vault::ChangePinInput {
            new_pin: "93847561029".into(),
            request_id: id.clone(),
        },
    )
    .await
    .is_err());
    // Новый запрос — снова только с подтверждением.
    assert!(matches!(
        change(request()).await,
        Err(crate::error::VaultError::AuthorizationRequired(_))
    ));
    assert!(env.opens_with_pin(NEW_PIN).await);
}

#[tokio::test]
async fn retried_backup_writes_one_file() {
    let env = unlocked().await;
    let dir = env.root.parent().unwrap().join("backups");
    std::fs::create_dir_all(&dir).unwrap();
    env.authorize(SecurityAction::ChangeBackupDirectory).await;
    let capability = env.grant(&dir, FileOperation::BackupDirectory);
    crate::commands::backup::set_backup_config(
        &env.state,
        crate::commands::backup::BackupSetInput {
            directory_capability: Some(capability),
            frequency: "off".into(),
        },
    )
    .unwrap();
    let id = request();
    let first = crate::commands::backup::backup_now_blocking(&env.state, &id).unwrap();
    let second = crate::commands::backup::backup_now_blocking(&env.state, &id).unwrap();
    assert_eq!(first.path, second.path);
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    assert!(crate::commands::backup::backup_now_blocking(&env.state, "../../evil").is_err());
}

#[tokio::test]
async fn repeated_security_mutations_are_no_ops() {
    let (env, shares) = created().await;
    env.unlock(PIN).await.unwrap();
    // Подтверждение уже активного поколения.
    crate::commands::recovery::acknowledge_recovery(&env.state, shares.generation).unwrap();
    // Отключение: второй раз — без подтверждения и без новой мутации.
    env.authorize(SecurityAction::DisableRecovery).await;
    crate::commands::recovery::disable_recovery(&env.state).unwrap();
    let generation = meta(&env).recovery_generation;
    crate::commands::recovery::disable_recovery(&env.state).unwrap();
    assert_eq!(meta(&env).recovery_generation, generation);
    // Hello и подтверждение копирования: повтор уже применённого — успех.
    env.enable_hello().await;
    crate::commands::settings::set_hello(&env.state, true)
        .await
        .unwrap();
    crate::commands::settings::set_step_up(&env.state, false)
        .await
        .unwrap();
    // Удаление уже удалённой записи — успех.
    let id = create(&env, &request()).unwrap();
    env.with_session(|_, records, _| {
        crate::storage::records::delete_record(records, &id).unwrap();
        crate::storage::records::delete_record(records, &id).unwrap();
    })
    .unwrap();
}

// ------------------------------------------------------------ ревизии

fn confirmed(env: &Env) -> (u64, u64) {
    let db = env.state.open_meta().unwrap();
    let meta = db.vault_load().unwrap().unwrap();
    let key = crate::commands::vault::unwrap_integrity_key(
        &db.get_integrity_key_dpapi().unwrap().unwrap(),
        &meta.dpapi_entropy,
    )
    .unwrap();
    let (records, web) = db.data_state(&key).unwrap();
    (records.revision, web.revision)
}

fn rollback_snapshot(result: crate::error::Result<()>) -> String {
    match result {
        Err(crate::error::VaultError::DataRollback(snapshot)) => snapshot,
        other => panic!("ожидался DATA_ROLLBACK, получено {other:?}"),
    }
}

async fn accept(env: &Env, snapshot: String) -> crate::error::Result<()> {
    crate::commands::vault::unlock_with_pin_policy(
        &env.state,
        crate::commands::vault::VaultUnlockInput { pin: PIN.into() },
        crate::commands::vault::helpers::DataRollback::Accept { snapshot },
    )
    .await
}

fn strictly_above(after: (u64, u64), before: (u64, u64)) -> bool {
    after.0 > before.0 && after.1 > before.1
}

/// Принятие отката делает старые данные новым состоянием: подтверждённая
/// ревизия растёт, история anti-rollback не забывается.
#[tokio::test]
async fn accepting_a_rollback_moves_revisions_forward() {
    let mut env = unlocked().await;
    env.state.lock();
    let aside = env.put_file(
        "records.old",
        &std::fs::read(env.state.records_path()).unwrap(),
    );
    env.unlock(PIN).await.unwrap();
    create(&env, &request()).unwrap();
    let before = confirmed(&env);
    env.state.lock();
    std::fs::copy(&aside, env.state.records_path()).unwrap();
    env.restart();
    let snapshot = rollback_snapshot(env.unlock(PIN).await);
    accept(&env, snapshot).await.unwrap();
    assert!(strictly_above(confirmed(&env), before));
    // Та же старая копия, подложенная ещё раз, — снова откат.
    env.state.lock();
    std::fs::copy(&aside, env.state.records_path()).unwrap();
    env.restart();
    rollback_snapshot(env.unlock(PIN).await);
}

/// Решение «продолжить» привязано к показанному снимку: если между
/// предупреждением и подтверждением подложили другие файлы, принимается
/// не новый снимок, а снова отказ с его собственным идентификатором.
#[tokio::test]
async fn accepting_a_rollback_is_bound_to_the_shown_snapshot() {
    let mut env = unlocked().await;
    env.state.lock();
    let oldest = env.put_file(
        "records.oldest",
        &std::fs::read(env.state.records_path()).unwrap(),
    );
    env.unlock(PIN).await.unwrap();
    create(&env, &request()).unwrap();
    env.state.lock();
    let older = env.put_file(
        "records.older",
        &std::fs::read(env.state.records_path()).unwrap(),
    );
    env.unlock(PIN).await.unwrap();
    create(&env, &request()).unwrap();
    env.state.lock();

    std::fs::copy(&older, env.state.records_path()).unwrap();
    env.restart();
    let shown = rollback_snapshot(env.unlock(PIN).await);
    // Пока владелец читал предупреждение, файл заменили ещё более старым.
    std::fs::copy(&oldest, env.state.records_path()).unwrap();
    let other = rollback_snapshot(accept(&env, shown).await);
    assert!(!env.state.session.lock().is_unlocked());
    accept(&env, other)
        .await
        .expect("явное решение для нового снимка");
    assert_eq!(records(&env), 1, "данные самого старого снимка");
}

/// Импорт привязан к импортированному снимку: подменённые до первого входа
/// базы не проходят rebase.
#[tokio::test]
async fn import_rebase_is_bound_to_the_imported_snapshot() {
    let mut env = unlocked().await;
    let older = env.put_file("backup-older.vault", &env.bundle());
    create(&env, &request()).unwrap();
    let newer = env.put_file("backup-newer.vault", &env.bundle());
    env.lose_live_vault();
    let capability = env.grant(&newer, FileOperation::Import);
    crate::commands::vault::vault_import_blocking(
        crate::commands::vault::ImportInput { capability },
        &env.state,
    )
    .unwrap();
    // До первого входа базы подменены более старым снимком.
    let (_, records, _) =
        crate::commands::vault::parse_bundle(&std::fs::read(&older).unwrap()).unwrap();
    std::fs::write(env.state.records_path(), records).unwrap();
    env.restart();
    let snapshot = rollback_snapshot(env.unlock(PIN).await);
    assert!(meta(&env).data_rebase_pending, "rebase не выполнен");
    // Явное решение владельца возможно, но только для показанного снимка.
    accept(&env, snapshot).await.unwrap();
    assert!(!meta(&env).data_rebase_pending);
}

/// Импорт старой копии на том же устройстве: подтверждённая ревизия не
/// уменьшается, первый вход переносит базы выше неё.
#[tokio::test]
async fn import_moves_revisions_forward_on_first_unlock() {
    let mut env = unlocked().await;
    let backup = env.put_file("backup.vault", &env.bundle());
    for _ in 0..3 {
        create(&env, &request()).unwrap();
    }
    let before = confirmed(&env);
    env.lose_live_vault();
    let capability = env.grant(&backup, FileOperation::Import);
    crate::commands::vault::vault_import_blocking(
        crate::commands::vault::ImportInput { capability },
        &env.state,
    )
    .unwrap();
    env.restart();
    assert!(confirmed(&env) >= before, "импорт не понизил ревизии");
    env.unlock(PIN).await.expect("первый вход после импорта");
    assert!(strictly_above(confirmed(&env), before));
    assert!(!meta(&env).data_rebase_pending);
    assert_eq!(env.read_canary().as_deref(), Some(CANARY));
}

/// Восстановление по долям: ревизии нового ключа выше старого checkpoint'а.
#[tokio::test]
async fn recovery_moves_revisions_forward() {
    let (mut env, shares) = created().await;
    env.unlock(PIN).await.unwrap();
    create(&env, &request()).unwrap();
    let before = confirmed(&env);
    crate::commands::recovery::restore_from_shares(&env.state, restore_input(&shares, NEW_PIN))
        .await
        .unwrap();
    env.restart();
    assert!(strictly_above(confirmed(&env), before));
    assert!(env.opens_with_pin(NEW_PIN).await);
}
