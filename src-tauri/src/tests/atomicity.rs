//! Атомарность операций с хранилищем: отказ на каждом шаге персистентности.
//!
//! Каждый сценарий: подготовка → операция с отказом на шаге N (режимы Error и
//! Crash) → перезапуск → общие инварианты (`invariants::inspect`) →
//! постусловия операции. Постусловия проверяют смысл, а не только то, что
//! хранилище открывается: состояние обязано быть целиком старым или целиком
//! новым.

use std::future::Future;
use std::pin::Pin;

use super::harness::{arm, assert_atomic, observed, Case, Env, CANARY, NEW_PIN, PIN, WRONG_PIN};
use super::invariants::{inspect, Observed};
use crate::commands::security::SecurityAction;
use crate::commands::vault::{ChangePinInput, VaultCreateInput};
use crate::error::VaultError;
use crate::failpoint::Mode;
use crate::storage::records::{FieldInput, FieldType, RecordInput};

type CaseFuture = Pin<Box<dyn Future<Output = Case>>>;

fn create_input() -> VaultCreateInput {
    VaultCreateInput {
        pin: PIN.into(),
        use_windows_hello: false,
        autolock_seconds: None,
        clipboard_clear_seconds: None,
    }
}

/// Хранилище с канарейкой, запертое.
async fn prepared() -> Env {
    let env = Env::new();
    env.create().await;
    env.add_canary();
    env.state.lock();
    env
}

/// Перезапуск и общие инварианты; хранилище обязано существовать.
async fn restart_and_inspect(
    env: &mut Env,
) -> (
    Option<Box<crate::storage::meta_db::VaultMetaRow>>,
    Vec<String>,
) {
    env.restart();
    let (observed, mut violations) = inspect(env).await;
    let meta = match observed {
        Some(Observed::Created(meta)) => Some(meta),
        Some(Observed::NotCreated) => {
            violations.push("хранилище исчезло".into());
            None
        }
        None => None,
    };
    (meta, violations)
}

// ---------------------------------------------------------------- создание

fn create_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let mut env = Env::new();
        arm(plan);
        let _ = crate::commands::vault::create_vault(&env.state, create_input()).await;
        let (steps, trace) = observed();

        env.restart();
        let (state, mut violations) = inspect(&env).await;
        match state {
            // Старое состояние: хранилища нет, и его можно создать заново.
            Some(Observed::NotCreated) => {
                match crate::commands::vault::create_vault(&env.state, create_input()).await {
                    Ok(_) => {
                        env.restart();
                        violations.extend(inspect(&env).await.1);
                    }
                    Err(error) => {
                        violations.push(format!("NOT_CREATED, но создать нельзя: {error}"))
                    }
                }
            }
            // Новое: хранилище открывается PIN.
            Some(Observed::Created(_)) => {
                if let Err(error) = env.unlock(PIN).await {
                    violations.push(format!("NO_UNLOCK_PATH: PIN не открывает: {error}"));
                }
            }
            None => {}
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

/// H-01: создание поверх существующего хранилища — при любой причине отказа —
/// не трогает ни файлы, ни TPM-ключ хранилища.
#[tokio::test]
async fn create_never_destroys_an_existing_vault() {
    let mut env = prepared().await;
    let tpm_before = env.fake.tpm_keys();
    for pin in ["", PIN, "short"] {
        let result = crate::commands::vault::create_vault(
            &env.state,
            VaultCreateInput {
                pin: pin.into(),
                ..create_input()
            },
        )
        .await;
        assert!(
            result.is_err(),
            "создание поверх хранилища обязано отказать"
        );
    }
    assert_eq!(
        env.fake.tpm_keys(),
        tpm_before,
        "TPM-ключ хранилища на месте"
    );
    assert!(
        env.opens_with_pin(PIN).await,
        "хранилище открывается и данные целы"
    );
}

/// Отсутствие одного файла не превращает создание в удаление остальных.
#[tokio::test]
async fn create_refuses_over_a_partial_vault_without_deleting_anything() {
    let env = prepared().await;
    std::fs::remove_file(env.state.records_path()).unwrap();
    let result = crate::commands::vault::create_vault(&env.state, create_input()).await;
    assert!(result.is_err());
    assert!(env.state.meta_path().exists(), "метаданные не удалены");
    assert!(env.state.web_path().exists(), "пароли сайтов не удалены");
    assert_eq!(env.fake.tpm_keys().len(), 1, "TPM-ключ не удалён");
}

#[tokio::test]
async fn create_is_atomic() {
    assert_atomic("create", create_case).await;
}

/// Commit создания — перенос метаданных. Сбой после него, но до уборки
/// каталога сборки, — это NEW_VALID + cleanup pending, а не откат.
#[tokio::test]
async fn create_crash_after_publication_keeps_the_new_vault() {
    let env = Env::new();
    arm(None);
    env.create().await;
    let (_, trace) = observed();
    let cleanup = trace
        .iter()
        .rposition(|step| *step == "staging.remove")
        .expect("staging cleanup step")
        + 1;

    for mode in [Mode::Crash, Mode::Error] {
        let mut env = Env::new();
        arm(Some((cleanup, mode)));
        let result = crate::commands::vault::create_vault(&env.state, create_input()).await;
        if mode == Mode::Error {
            assert!(result.is_ok(), "неудачная уборка не отменяет создание");
        }
        env.restart();
        let (state, violations) = inspect(&env).await;
        assert!(violations.is_empty(), "{mode:?}: {violations:?}");
        assert!(
            matches!(state, Some(Observed::Created(_))),
            "{mode:?}: опубликованное хранилище обязано остаться"
        );
        env.unlock(PIN)
            .await
            .expect("новое хранилище открывается PIN");
    }
}

// ---------------------------------------------------------------- неверный PIN

/// Ошибок до сценария: следующая неверная попытка — шестая, с задержкой.
const PRIOR_FAILURES: u32 = 5;

async fn with_prior_failures() -> Env {
    let env = prepared().await;
    for _ in 0..PRIOR_FAILURES {
        assert!(matches!(
            env.unlock(WRONG_PIN).await,
            Err(VaultError::InvalidPin)
        ));
    }
    env
}

fn wrong_pin_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let mut env = with_prior_failures().await;
        arm(plan);
        let result = env.unlock(WRONG_PIN).await;
        let (steps, trace) = observed();
        let (_, mut violations) = restart_and_inspect(&mut env).await;
        // Сбой никогда не уменьшает счётчик, а ответ «неверный PIN» получен
        // только за списанную попытку.
        let failures = env.backoff().failures;
        if failures < PRIOR_FAILURES {
            violations.push(format!("счётчик уменьшился: {failures}"));
        }
        if matches!(result, Err(VaultError::InvalidPin)) && failures < PRIOR_FAILURES + 1 {
            violations.push("ответ «неверный PIN» без списанной попытки".into());
        }
        // Постоянной блокировки нет: после задержки верный PIN открывает.
        env.fake.advance_clock(crate::auth::backoff::MAX_DELAY_SECS);
        if !env.opens_with_pin(PIN).await {
            violations.push("верный PIN не открывает хранилище".into());
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn wrong_pin_accounting_is_atomic() {
    assert_atomic("wrong_pin", wrong_pin_case).await;
}

// ---------------------------------------------------------------- тип поля

fn field_type_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let mut env = prepared().await;
        env.unlock(PIN).await.expect("unlock");
        let (record_id, field_id, _, _) = env.canary().expect("canary");
        arm(plan);
        let _ = env.with_session(|master, records, _| {
            crate::storage::records::update_record(
                records,
                master,
                &record_id,
                &RecordInput {
                    name: "canary".into(),
                    project: None,
                    icon: None,
                    color: None,
                    category: Some("work".into()),
                    fields: vec![FieldInput {
                        id: Some(field_id.clone()),
                        field_type: FieldType::Api,
                        label: "token".into(),
                        is_secret: true,
                        sort_order: 0,
                        value: None,
                    }],
                },
                true,
            )
        });
        let (steps, trace) = observed();

        let (_, mut violations) = restart_and_inspect(&mut env).await;
        if env.unlock(PIN).await.is_err() {
            violations.push("PIN не открывает хранилище".into());
        }
        // OLD: старый тип и значение. NEW: новый тип и то же значение.
        // Никогда: новый тип и нерасшифровываемый старый шифротекст.
        match env.canary() {
            Some((_, _, FieldType::Secret, Some(value))) if value == CANARY => {}
            Some((_, _, FieldType::Api, Some(value))) if value == CANARY => {}
            other => violations.push(format!(
                "поле не в старом и не в новом состоянии: {:?}",
                other.map(|(_, _, kind, value)| (kind, value))
            )),
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

/// H-02: смена типа без повторного ввода значения сохраняет значение.
#[tokio::test]
async fn field_type_change_keeps_the_value() {
    let env = prepared().await;
    env.unlock(PIN).await.unwrap();
    let (record_id, field_id, _, _) = env.canary().unwrap();
    for kind in [
        FieldType::Api,
        FieldType::Key,
        FieldType::Comment,
        FieldType::Secret,
    ] {
        env.with_session(|master, records, _| {
            crate::storage::records::update_record(
                records,
                master,
                &record_id,
                &RecordInput {
                    name: "canary".into(),
                    project: None,
                    icon: None,
                    color: None,
                    category: Some("work".into()),
                    fields: vec![FieldInput {
                        id: Some(field_id.clone()),
                        field_type: kind,
                        label: "token".into(),
                        is_secret: true,
                        sort_order: 0,
                        value: None,
                    }],
                },
                true,
            )
        })
        .unwrap()
        .unwrap();
        let (_, _, stored_kind, value) = env.canary().unwrap();
        assert_eq!(stored_kind, kind);
        assert_eq!(
            value.as_deref(),
            Some(CANARY),
            "значение пережило смену на {kind:?}"
        );
    }
}

#[tokio::test]
async fn field_type_change_is_atomic() {
    assert_atomic("field_type", field_type_case).await;
}

// ---------------------------------------------------------------- импорт CSV

const CSV: &str = "name,url,username,password\n\
    A,https://a.example,u1,P1\n\
    B,https://b.example,u2,P2\n\
    C,https://c.example,u3,P3\n";

fn web_count(env: &Env) -> Option<usize> {
    env.with_session(|_, _, web| {
        crate::storage::records::list_records(web, None, false, None, None, 100, 0)
            .map(|list| list.len())
            .ok()
    })
    .flatten()
}

fn csv_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let mut env = prepared().await;
        env.unlock(PIN).await.expect("unlock");
        arm(plan);
        let _ = env.with_session(|master, _, web| {
            crate::commands::import::import_entries(
                web,
                master,
                crate::commands::import::parse_chromium_csv(CSV),
                None,
            )
        });
        let (steps, trace) = observed();

        let (_, mut violations) = restart_and_inspect(&mut env).await;
        if env.unlock(PIN).await.is_err() {
            violations.push("PIN не открывает хранилище".into());
        }
        // Либо ничего, либо все три строки — половины импорта не бывает.
        match web_count(&env) {
            Some(0) | Some(3) => {}
            other => violations.push(format!("частичный импорт: {other:?} из 3")),
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn csv_import_is_all_or_nothing() {
    assert_atomic("csv_import", csv_case).await;
}

// ---------------------------------------------------------------- смена PIN

fn change_pin_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let mut env = prepared().await;
        env.unlock(PIN).await.expect("unlock");
        env.authorize(SecurityAction::ChangePin).await;
        arm(plan);
        let _ = crate::commands::vault::change_pin(
            &env.state,
            ChangePinInput {
                new_pin: NEW_PIN.into(),
                request_id: uuid::Uuid::new_v4().to_string(),
            },
        )
        .await;
        let (steps, trace) = observed();

        let (_, mut violations) = restart_and_inspect(&mut env).await;
        let old = env.opens_with_pin(PIN).await;
        let new = env.opens_with_pin(NEW_PIN).await;
        if old == new {
            violations.push(format!(
                "PIN не в старом и не в новом состоянии: старый={old}, новый={new}"
            ));
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn change_pin_is_atomic() {
    assert_atomic("change_pin", change_pin_case).await;
}

// ---------------------------------------------------------------- Hello

fn hello_enable_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let mut env = prepared().await;
        env.unlock(PIN).await.expect("unlock");
        env.authorize(SecurityAction::EnableHello).await;
        arm(plan);
        let _ = crate::commands::settings::set_hello(&env.state, true).await;
        let (steps, trace) = observed();
        // Согласованность флага и ключа — общий инвариант; здесь — вход.
        let (meta, mut violations) = restart_and_inspect(&mut env).await;
        if !env.opens_with_pin(PIN).await {
            violations.push("после включения Hello хранилище не открывается".into());
        }
        violations.extend(hello_postcondition(&mut env, meta.as_deref()).await);
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn hello_enable_is_atomic() {
    assert_atomic("hello_enable", hello_enable_case).await;
}

fn hello_disable_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let mut env = prepared().await;
        env.unlock(PIN).await.expect("unlock");
        env.enable_hello().await;
        env.authorize(SecurityAction::DisableHello).await;
        arm(plan);
        let _ = crate::commands::settings::set_hello(&env.state, false).await;
        let (steps, trace) = observed();
        let (meta, mut violations) = restart_and_inspect(&mut env).await;
        if !env.opens_with_pin(PIN).await {
            violations.push("после выключения Hello хранилище не открывается".into());
        }
        violations.extend(hello_postcondition(&mut env, meta.as_deref()).await);
        Case {
            steps,
            trace,
            violations,
        }
    })
}

/// OLD/NEW для Hello. Включён: ключ существует (общий инвариант) и вход без
/// подтверждения Hello невозможен. Выключен: ключа нет (инвариант сирот),
/// подтверждение копирования тоже выключено, вход — одним PIN.
async fn hello_postcondition(
    env: &mut Env,
    meta: Option<&crate::storage::meta_db::VaultMetaRow>,
) -> Vec<String> {
    let mut violations = Vec::new();
    let Some(meta) = meta else {
        return violations;
    };
    if meta.use_windows_hello {
        env.restart();
        env.fake.refuse_next_hello();
        if env.unlock(PIN).await.is_ok() {
            violations.push("Hello включён, но вход прошёл без него".into());
        }
    } else {
        if meta.require_auth_for_copy {
            violations.push("Hello выключен, а подтверждение копирования осталось".into());
        }
        if !env.fake.hello_keys().is_empty() {
            violations.push("Hello выключен, а его ключ остался в ОС".into());
        }
    }
    violations
}

#[tokio::test]
async fn hello_disable_is_atomic() {
    assert_atomic("hello_disable", hello_disable_case).await;
}

/// Регрессия находки «Disable Hello: ключ удалён → флаг остался → lockout»:
/// ключ Hello удаляется только после commit флага, поэтому отказ удаления
/// оставляет Hello выключенным, а ключ дочищается при старте.
#[tokio::test]
async fn hello_disable_deletes_the_key_only_after_commit() {
    let env = prepared().await;
    env.unlock(PIN).await.unwrap();
    env.enable_hello().await;
    env.authorize(SecurityAction::DisableHello).await;
    arm(None);
    crate::commands::settings::set_hello(&env.state, false)
        .await
        .unwrap();
    let (_, trace) = observed();
    let delete = trace
        .iter()
        .position(|step| *step == "hello.delete")
        .expect("credential deletion step")
        + 1;
    let commit = trace
        .iter()
        .position(|step| *step == "meta.commit")
        .expect("metadata commit step")
        + 1;
    assert!(commit < delete, "удаление ключа раньше commit: {trace:?}");

    let mut env = prepared().await;
    env.unlock(PIN).await.unwrap();
    env.enable_hello().await;
    env.authorize(SecurityAction::DisableHello).await;
    arm(Some((delete, Mode::Crash)));
    let _ = crate::commands::settings::set_hello(&env.state, false).await;
    let (meta, violations) = restart_and_inspect(&mut env).await;
    assert!(violations.is_empty(), "{violations:?}");
    assert!(
        !meta.unwrap().use_windows_hello,
        "commit состоялся: Hello выключен"
    );
    assert!(env.fake.hello_keys().is_empty(), "ключ дочищен при старте");
    assert!(env.opens_with_pin(PIN).await);
}

// ---------------------------------------------------------------- step-up

fn step_up_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let mut env = prepared().await;
        env.unlock(PIN).await.expect("unlock");
        env.enable_hello().await;
        env.authorize(SecurityAction::EnableStepUp).await;
        arm(plan);
        let _ = crate::commands::settings::set_step_up(&env.state, true).await;
        let (steps, trace) = observed();
        let (meta, mut violations) = restart_and_inspect(&mut env).await;
        if let Some(meta) = meta {
            if meta.require_auth_for_copy && !meta.use_windows_hello {
                violations.push("подтверждение копирования без Hello".into());
            }
        }
        if !env.opens_with_pin(PIN).await {
            violations.push("хранилище не открывается".into());
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn step_up_change_is_atomic() {
    assert_atomic("step_up", step_up_case).await;
}

// ---------------------------------------------------------------- FIDO2

fn fido_bind_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let mut env = prepared().await;
        env.unlock(PIN).await.expect("unlock");
        env.authorize(SecurityAction::BindFido).await;
        arm(plan);
        let _ = crate::commands::settings::bind_fido2_key(
            &env.state,
            None,
            Some(false),
            &uuid::Uuid::new_v4().to_string(),
        )
        .await;
        let (steps, trace) = observed();

        let (_, mut violations) = restart_and_inspect(&mut env).await;
        if !env.opens_with_pin(PIN).await {
            violations.push("после привязки ключа PIN не открывает хранилище".into());
        }
        // NEW: ключ записан — им обязано открываться.
        let stored = env
            .state
            .open_meta()
            .and_then(|db| db.get_fido2_keys())
            .map(|keys| !keys.is_empty())
            .unwrap_or(false);
        if stored {
            env.restart();
            let opened = crate::commands::vault::unlock_with_fido2(&env.state).await;
            if opened.is_err() || env.read_canary().as_deref() != Some(CANARY) {
                violations.push("ключ записан, но не открывает хранилище".into());
            }
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn fido_bind_is_atomic() {
    assert_atomic("fido_bind", fido_bind_case).await;
}

fn fido_unbind_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let mut env = prepared().await;
        env.unlock(PIN).await.expect("unlock");
        env.bind_fido().await;
        let id = env
            .state
            .open_meta()
            .and_then(|db| db.get_fido2_keys())
            .expect("keys")[0]
            .id
            .clone();
        env.authorize(SecurityAction::UnbindFido).await;
        arm(plan);
        let _ = crate::commands::settings::unbind_fido2(&env.state, &id).await;
        let (steps, trace) = observed();

        let (_, mut violations) = restart_and_inspect(&mut env).await;
        if !env.opens_with_pin(PIN).await {
            violations.push("после отвязки PIN не открывает хранилище".into());
        }
        // OLD: ключ записан и открывает. NEW: ключа нет и он не открывает.
        let stored = env
            .state
            .open_meta()
            .and_then(|db| db.get_fido2_keys())
            .map(|keys| !keys.is_empty())
            .unwrap_or(false);
        env.restart();
        let opened = crate::commands::vault::unlock_with_fido2(&env.state)
            .await
            .is_ok()
            && env.read_canary().as_deref() == Some(CANARY);
        if stored != opened {
            violations.push(format!(
                "FIDO2 не в старом и не в новом состоянии: записан={stored}, открывает={opened}"
            ));
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn fido_unbind_is_atomic() {
    assert_atomic("fido_unbind", fido_unbind_case).await;
}

#[tokio::test]
async fn harness_counts_steps_and_crash_stops_all_later_writes() {
    let env = Env::new();
    arm(None);
    env.create().await;
    let (total, trace) = observed();
    assert!(
        total > 5,
        "создание должно пройти несколько шагов: {trace:?}"
    );

    // После краха на шаге 2 ни один следующий шаг уже не выполняется.
    let env = Env::new();
    arm(Some((2, Mode::Crash)));
    let result = crate::commands::vault::create_vault(&env.state, create_input()).await;
    assert!(result.is_err());
    assert_eq!(observed().0, 2, "после краха шаги не засчитываются");
}
