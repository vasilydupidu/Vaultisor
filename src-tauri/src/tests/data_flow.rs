//! Этап 3: резервное копирование, восстановление данных из копии, импорт на
//! чистую установку, изменения баз и обнаружение их отката.

use std::future::Future;
use std::pin::Pin;

use super::harness::{
    arm, assert_atomic_outcomes, observed, record, Case, Env, Outcome, CANARY, NEW_PIN, PIN,
    WRONG_PIN,
};
use super::invariants::{inspect, Observed};
use super::recovery_flow::{created, meta, restart_and_inspect, restore_input, Shares};
use crate::commands::file_grants::FileOperation;
use crate::commands::security::SecurityAction;
use crate::commands::vault::ImportInput;
use crate::error::VaultError;
use crate::failpoint::Mode;
use crate::storage::meta_db::RecoveryState;
use crate::storage::records::{FieldInput, FieldType, RecordInput};

type CaseFuture = Pin<Box<dyn Future<Output = Case>>>;

pub(super) const CHANGED: &str = "sk-live-changed-after-backup";

pub(super) fn entry(name: &str, value: &str) -> RecordInput {
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
            value: Some(value.into()),
        }],
    }
}

pub(super) fn add(env: &Env, web: bool, name: &str) -> crate::error::Result<String> {
    env.with_session(|master, records, web_db| {
        let db = if web { web_db } else { records };
        crate::storage::records::create_record(db, master, &entry(name, "secret"), None)
    })
    .expect("vault must be unlocked")
}

pub(super) fn count(env: &Env, web: bool) -> Option<usize> {
    env.with_session(|_, records, web_db| {
        let db = if web { web_db } else { records };
        crate::storage::records::list_records(db, None, false, None, None, 100, 0)
            .map(|list| list.len())
            .ok()
    })
    .flatten()
}

fn set_canary(env: &Env, value: &str) {
    let (record_id, field_id, _, _) = env.canary().expect("canary");
    env.with_session(|master, records, _| {
        crate::storage::records::update_record(
            records,
            master,
            &record_id,
            &RecordInput {
                fields: vec![FieldInput {
                    id: Some(field_id.clone()),
                    field_type: FieldType::Secret,
                    label: "token".into(),
                    is_secret: true,
                    sort_order: 0,
                    value: Some(value.into()),
                }],
                ..entry("canary", value)
            },
            true,
        )
    })
    .unwrap()
    .unwrap();
}

/// Открытое хранилище: канарейка и один пароль сайта; доли подтверждены.
pub(super) async fn unlocked() -> (Env, Shares) {
    let (env, shares) = created().await;
    env.unlock(PIN).await.expect("unlock");
    add(&env, true, "site-A").expect("web entry");
    (env, shares)
}

fn import(env: &Env, path: &std::path::Path) -> crate::error::Result<()> {
    let capability = env.grant(path, FileOperation::Import);
    crate::commands::vault::vault_import_blocking(ImportInput { capability }, &env.state)
}

// ------------------------------------------------------------ restore

fn restore_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (mut env, _) = unlocked().await;
        let backup = env.put_file("backup.vault", &env.bundle());
        set_canary(&env, CHANGED);
        add(&env, true, "site-B").expect("web entry");
        env.authorize(SecurityAction::RestoreBackup).await;
        let capability = env.grant(&backup, FileOperation::Restore);
        arm(plan);
        let _ =
            crate::commands::vault::vault_restore_blocking(ImportInput { capability }, &env.state);
        let (steps, trace) = observed();

        let (_, mut violations) = restart_and_inspect(&mut env).await;
        match env.unlock(PIN).await {
            Err(error) => violations.push(format!("после restore вход не проходит: {error}")),
            Ok(()) => match (env.read_canary().as_deref(), count(&env, true)) {
                // Обе базы из копии или обе живые — смешанного состояния нет.
                (Some(CANARY), Some(1)) => record(Outcome::New),
                (Some(CHANGED), Some(2)) => record(Outcome::Old),
                other => violations.push(format!("базы из разных снимков: {other:?}")),
            },
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn restore_is_atomic_and_never_mixes_snapshots() {
    assert_atomic_outcomes("restore", restore_case).await;
}

/// Сценарий B: старая копия после смены PIN, включения Hello и привязки
/// FIDO2 возвращает данные, но не прежние факторы входа.
#[tokio::test]
async fn restore_keeps_the_current_authentication_policy() {
    let (mut env, _) = unlocked().await;
    let backup = env.put_file("backup.vault", &env.bundle());
    set_canary(&env, CHANGED);

    env.authorize(SecurityAction::ChangePin).await;
    crate::commands::vault::change_pin(
        &env.state,
        crate::commands::vault::ChangePinInput {
            new_pin: NEW_PIN.into(),
            request_id: uuid::Uuid::new_v4().to_string(),
        },
    )
    .await
    .unwrap();
    // Подтверждения ниже — уже новым PIN.
    for action in [SecurityAction::EnableHello, SecurityAction::BindFido] {
        crate::commands::security::authorize(&env.state, action, NEW_PIN)
            .await
            .unwrap();
        match action {
            SecurityAction::EnableHello => crate::commands::settings::set_hello(&env.state, true)
                .await
                .unwrap(),
            _ => {
                crate::commands::settings::bind_fido2_key(
                    &env.state,
                    None,
                    Some(false),
                    &uuid::Uuid::new_v4().to_string(),
                )
                .await
                .unwrap();
            }
        }
    }
    let policy = meta(&env);

    crate::commands::security::authorize(&env.state, SecurityAction::RestoreBackup, NEW_PIN)
        .await
        .unwrap();
    let capability = env.grant(&backup, FileOperation::Restore);
    crate::commands::vault::vault_restore_blocking(ImportInput { capability }, &env.state).unwrap();

    env.restart();
    let after = meta(&env);
    assert_eq!(after.wrapped_master_dpapi, policy.wrapped_master_dpapi);
    assert!(after.use_windows_hello, "Hello остался включённым");
    assert_eq!(
        after.hello_key_credential_name,
        policy.hello_key_credential_name
    );
    assert_eq!(after.recovery_generation, policy.recovery_generation);
    assert_eq!(after.recovery_state, policy.recovery_state);
    assert_eq!(
        env.state
            .open_meta()
            .unwrap()
            .get_fido2_keys()
            .unwrap()
            .len(),
        1,
        "FIDO2-ключ остался привязанным"
    );
    assert!(env.unlock(PIN).await.is_err(), "старый PIN не вернулся");
    env.unlock(NEW_PIN).await.expect("текущий PIN открывает");
    assert_eq!(
        env.read_canary().as_deref(),
        Some(CANARY),
        "данные из копии"
    );
    env.state.lock();
    crate::commands::vault::unlock_with_fido2(&env.state)
        .await
        .expect("FIDO2 по-прежнему открывает");
}

// ------------------------------------------------------------ сценарий C

fn copy_aside(env: &Env, name: &str) -> std::path::PathBuf {
    let aside = env.put_file(&format!("{name}.old"), &[]);
    std::fs::copy(env.root.join(name), &aside).unwrap();
    aside
}

/// Старые `records.db` / `web.db`, подложенные вместо текущих, обнаруживаются.
#[tokio::test]
async fn swapping_in_old_databases_is_detected() {
    for rolled_back in [
        &["vault.records.db"][..],
        &["vault.web.db"][..],
        &["vault.records.db", "vault.web.db"][..],
    ] {
        let (mut env, _) = unlocked().await;
        env.state.lock();
        let aside: Vec<_> = rolled_back
            .iter()
            .map(|name| (*name, copy_aside(&env, name)))
            .collect();
        env.unlock(PIN).await.unwrap();
        add(&env, false, "after-copy").unwrap();
        add(&env, true, "after-copy").unwrap();
        env.state.lock();
        for (name, path) in &aside {
            std::fs::copy(path, env.root.join(name)).unwrap();
        }
        env.restart();
        let snapshot = match env.unlock(PIN).await {
            Err(VaultError::DataRollback(snapshot)) => snapshot,
            other => panic!("откат {rolled_back:?} не обнаружен: {other:?}"),
        };
        let accept = |pin: &str, snapshot: String| {
            crate::commands::vault::unlock_with_pin_policy(
                &env.state,
                crate::commands::vault::VaultUnlockInput { pin: pin.into() },
                crate::commands::vault::helpers::DataRollback::Accept { snapshot },
            )
        };
        // Неверный PIN не даёт принять откат.
        assert!(accept(WRONG_PIN, snapshot.clone()).await.is_err());
        // Решение действует только для показанного снимка.
        assert!(matches!(
            accept(PIN, "0".repeat(32)).await,
            Err(VaultError::DataRollback(_))
        ));
        // Владелец явно продолжает со старыми базами — после проверки PIN.
        accept(PIN, snapshot).await.expect("accept rollback");
        assert_eq!(env.read_canary().as_deref(), Some(CANARY));
        env.restart();
        env.unlock(PIN)
            .await
            .expect("после принятия обычный вход работает");
    }
}

// ------------------------------------------------------------ изменения баз

fn mutation_case(web: bool, plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (mut env, _) = unlocked().await;
        let before = count(&env, web).unwrap();
        arm(plan);
        let _ = add(&env, web, "mutation");
        let (steps, trace) = observed();

        let (_, mut violations) = restart_and_inspect(&mut env).await;
        match env.unlock(PIN).await {
            // Сбой между commit и подтверждением ревизии — не откат.
            Err(error) => violations.push(format!("ложное срабатывание при входе: {error}")),
            Ok(()) => match count(&env, web) {
                Some(n) if n == before => record(Outcome::Old),
                Some(n) if n == before + 1 => record(Outcome::New),
                other => violations.push(format!("записей: {other:?}")),
            },
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

fn records_mutation_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    mutation_case(false, plan)
}

fn web_mutation_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    mutation_case(true, plan)
}

#[tokio::test]
async fn records_mutation_is_atomic_and_rollback_protected() {
    assert_atomic_outcomes("records_mutation", records_mutation_case).await;
}

#[tokio::test]
async fn web_mutation_is_atomic_and_rollback_protected() {
    assert_atomic_outcomes("web_mutation", web_mutation_case).await;
}

// ------------------------------------------------------------ backup

fn backups(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                        n.starts_with("Vaultisor-backup-") && n.ends_with(".vault")
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn backup_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (mut env, _) = unlocked().await;
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
        arm(plan);
        let _ = crate::commands::backup::backup_now_blocking(
            &env.state,
            &uuid::Uuid::new_v4().to_string(),
        );
        let (steps, trace) = observed();

        let (_, mut violations) = restart_and_inspect(&mut env).await;
        if !env.opens_with_pin(PIN).await {
            violations.push("резервное копирование повредило хранилище".into());
        }
        let found = backups(&dir);
        for path in &found {
            let bytes = std::fs::read(path).unwrap();
            if crate::commands::vault::parse_bundle(&bytes).is_err() {
                violations.push(format!("неполная копия {path:?}"));
            }
        }
        match found.len() {
            0 => record(Outcome::Old),
            1 => record(Outcome::New),
            n => violations.push(format!("копий: {n}")),
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn backup_is_atomic() {
    assert_atomic_outcomes("backup_create", backup_case).await;
}

// ------------------------------------------------------------ import

/// Импорт на исходном устройстве после потери живого хранилища.
fn same_device_import_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (mut env, _) = unlocked().await;
        let backup = env.put_file("backup.vault", &env.bundle());
        env.lose_live_vault();
        arm(plan);
        let _ = import(&env, &backup);
        let (steps, trace) = observed();

        env.restart();
        let (state, mut violations) = inspect(&env).await;
        match state {
            Some(Observed::NotCreated) => {
                record(Outcome::Old);
                if let Err(error) = import(&env, &backup) {
                    violations.push(format!("OLD, но повтор импорта не проходит: {error}"));
                }
                env.restart();
                violations.extend(inspect(&env).await.1);
            }
            Some(Observed::Created(_)) => record(Outcome::New),
            None => {}
        }
        if !env.opens_with_pin(PIN).await {
            violations.push("импортированное хранилище не открывается PIN".into());
        } else if meta(&env).recovery_state != RecoveryState::Pending {
            violations.push("после импорта восстановление обязано ждать нового комплекта".into());
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn same_device_import_is_atomic() {
    assert_atomic_outcomes("same_device_import", same_device_import_case).await;
}

/// Импорт на другом компьютере: вход только восстановлением по долям.
fn cross_device_import_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (source, shares) = unlocked().await;
        let bundle = source.bundle();
        let mut env = source.other_device();
        let backup = env.put_file("backup.vault", &bundle);
        arm(plan);
        let _ = import(&env, &backup);
        let (steps, trace) = observed();

        env.restart();
        let (state, mut violations) = match inspect(&env).await {
            // До восстановления метаданные ссылаются на TPM чужого устройства —
            // это ожидаемое «только по долям», а не нарушение.
            (Some(Observed::Created(_)), _) => (Some(true), Vec::new()),
            (other, violations) => (other.map(|_| false), violations),
        };
        match state {
            Some(true) => record(Outcome::New),
            Some(false) => {
                record(Outcome::Old);
                if let Err(error) = import(&env, &backup) {
                    violations.push(format!("OLD, но повтор импорта не проходит: {error}"));
                }
            }
            None => {}
        }
        env.restart();
        if env.unlock(PIN).await.is_ok() {
            violations.push("на чужом устройстве PIN открыл хранилище без Device Secret".into());
        }
        match crate::commands::recovery::restore_from_shares(
            &env.state,
            restore_input(&shares, NEW_PIN),
        )
        .await
        {
            Err(error) => violations.push(format!("восстановление по долям не проходит: {error}")),
            Ok(_) => {
                env.restart();
                violations.extend(inspect(&env).await.1);
                if !env.opens_with_pin(NEW_PIN).await {
                    violations.push("после восстановления данные недоступны".into());
                }
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
async fn cross_device_import_is_atomic() {
    assert_atomic_outcomes("cross_device_import", cross_device_import_case).await;
}

/// Задержки PIN — монотонное состояние: импорт копии, снятой до серии
/// неверных PIN, их не снимает.
#[tokio::test]
async fn import_never_lowers_the_pin_backoff() {
    let (mut env, _) = unlocked().await;
    env.fake.set_clock(1_800_000_000);
    let backup = env.put_file("backup.vault", &env.bundle());
    env.state.lock();
    for _ in 0..6 {
        assert!(matches!(
            env.unlock(WRONG_PIN).await,
            Err(VaultError::InvalidPin)
        ));
    }
    env.lose_live_vault();
    import(&env, &backup).unwrap();
    env.restart();
    assert!(matches!(
        env.unlock(PIN).await,
        Err(VaultError::PinBackoff(_))
    ));
    assert_eq!(env.backoff().failures, 6);
    env.fake.advance_clock(30);
    env.unlock(PIN).await.expect("после задержки PIN открывает");
}

/// Подделанные метаданные в бандле на исходном устройстве отвергаются.
#[tokio::test]
async fn tampered_bundle_is_rejected_on_the_source_device() {
    let (mut env, _) = unlocked().await;
    let (meta_bytes, records, web) = crate::commands::vault::parse_bundle(&env.bundle()).unwrap();
    let meta_path = env.put_file("tampered.meta.db", &meta_bytes);
    {
        let connection = rusqlite::Connection::open(&meta_path).unwrap();
        connection
            .execute(
                "UPDATE vault_meta SET failed_pin_attempts = 0, autolock_seconds = 5 WHERE id = 1",
                [],
            )
            .unwrap();
    }
    let tampered = vlt2(&std::fs::read(&meta_path).unwrap(), &records, &web);
    let backup = env.put_file("tampered.vault", &tampered);
    env.lose_live_vault();
    assert!(import(&env, &backup).is_err());
    env.restart();
    let (state, violations) = inspect(&env).await;
    assert!(
        matches!(state, Some(Observed::NotCreated)),
        "{violations:?}"
    );
    assert!(violations.is_empty(), "{violations:?}");
}

/// Бандл с другого компьютера или из другой учётной записи Windows:
/// integrity-ключ не разворачивается, хранилище публикуется «только по долям».
#[tokio::test]
async fn bundle_from_another_windows_account_opens_only_via_recovery() {
    let (source, shares) = unlocked().await;
    let (meta_bytes, records, web) =
        crate::commands::vault::parse_bundle(&source.bundle()).unwrap();
    let meta_path = source.put_file("foreign.meta.db", &meta_bytes);
    {
        // DPAPI чужой учётной записи здесь не развернуть: моделируем порчей.
        let connection = rusqlite::Connection::open(&meta_path).unwrap();
        connection
            .execute(
                "UPDATE vault_meta SET integrity_key_dpapi = X'00' WHERE id = 1",
                [],
            )
            .unwrap();
    }
    let env = source.other_device();
    let backup = env.put_file(
        "foreign.vault",
        &vlt2(&std::fs::read(&meta_path).unwrap(), &records, &web),
    );
    import(&env, &backup).unwrap();
    let mut env = env;
    env.restart();
    assert!(env.unlock(PIN).await.is_err());
    crate::commands::recovery::restore_from_shares(&env.state, restore_input(&shares, NEW_PIN))
        .await
        .unwrap();
    env.restart();
    let (_, violations) = inspect(&env).await;
    assert!(violations.is_empty(), "{violations:?}");
    assert!(env.opens_with_pin(NEW_PIN).await);
    assert_eq!(env.read_canary().as_deref(), Some(CANARY));
}

fn vlt2(meta: &[u8], records: &[u8], web: &[u8]) -> Vec<u8> {
    let mut out = b"VLT2".to_vec();
    for part in [meta, records, web] {
        out.extend_from_slice(&(part.len() as u32).to_le_bytes());
        out.extend_from_slice(part);
    }
    out
}
