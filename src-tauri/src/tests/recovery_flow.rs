//! Этап 3: восстановление по долям, новое поколение, отключение,
//! `pending` / `active`.
//!
//! Главный инвариант: после любого отказа существует хотя бы один полностью
//! рабочий путь к тому же мастер-ключу — старый (старый PIN, старые доли)
//! или новый (новый PIN, новое поколение).

use std::future::Future;
use std::pin::Pin;

use super::harness::{
    arm, assert_atomic_outcomes, observed, record, Case, Env, Outcome, CANARY, NEW_PIN, PIN,
};
use super::invariants::{inspect, Observed};
use crate::commands::recovery::RestoreInput;
use crate::commands::security::SecurityAction;
use crate::failpoint::Mode;
use crate::storage::meta_db::{RecoveryState, VaultMetaRow};

type CaseFuture = Pin<Box<dyn Future<Output = Case>>>;

/// Выданный пользователю комплект долей.
#[derive(Clone)]
pub(super) struct Shares {
    pub generation: u64,
    pub b: String,
    pub c: String,
}

/// Хранилище с канарейкой, доли сохранены и подтверждены (`active`), заперто.
pub(super) async fn created() -> (Env, Shares) {
    let env = Env::new();
    let output = env.create().await;
    env.add_canary();
    crate::commands::recovery::acknowledge_recovery(&env.state, output.recovery_generation)
        .expect("acknowledge");
    env.state.lock();
    (
        env,
        Shares {
            generation: output.recovery_generation,
            b: output.recovery_share_b_hex,
            c: output.recovery_share_c_hex,
        },
    )
}

pub(super) fn restore_input(shares: &Shares, new_pin: &str) -> RestoreInput {
    RestoreInput {
        shares_hex: vec![shares.b.clone(), shares.c.clone()],
        new_pin: new_pin.into(),
    }
}

pub(super) fn meta(env: &Env) -> VaultMetaRow {
    env.state
        .open_meta()
        .expect("meta")
        .vault_load()
        .expect("load")
        .expect("vault")
}

/// Открывают ли доли B и C текущий конверт восстановления.
pub(super) fn shares_open(env: &Env, shares: &Shares) -> bool {
    let meta = meta(env);
    let Some(envelope) = meta.recovery_wrapped_master else {
        return false;
    };
    let parsed: Vec<_> = [&shares.b, &shares.c]
        .iter()
        .map(|hex| crate::commands::recovery::parse_share_hex(hex).expect("share"))
        .collect();
    crate::commands::recovery::open_envelope(&parsed, &envelope, meta.recovery_generation).is_ok()
}

/// Перезапуск и общие инварианты; хранилище обязано существовать.
pub(super) async fn restart_and_inspect(env: &mut Env) -> (Option<VaultMetaRow>, Vec<String>) {
    env.restart();
    let (observed, mut violations) = inspect(env).await;
    let meta = match observed {
        Some(Observed::Created(meta)) => Some(*meta),
        Some(Observed::NotCreated) => {
            violations.push("хранилище исчезло".into());
            None
        }
        None => None,
    };
    (meta, violations)
}

// ------------------------------------------------------------ восстановление

fn recovery_restore_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (mut env, shares) = created().await;
        let tpm_before = env.fake.tpm_keys();
        arm(plan);
        let _ = crate::commands::recovery::restore_from_shares(
            &env.state,
            restore_input(&shares, NEW_PIN),
        )
        .await;
        let (steps, trace) = observed();

        let (meta, mut violations) = restart_and_inspect(&mut env).await;
        if let Some(meta) = meta {
            if env.opens_with_pin(NEW_PIN).await {
                record(Outcome::New);
                // NEW: новые ключи устройства, доли израсходованы и отозваны,
                // хранилище ждёт нового комплекта.
                if meta.recovery_state != RecoveryState::Pending
                    || meta.recovery_wrapped_master.is_some()
                {
                    violations.push("после восстановления поколение не отозвано".into());
                }
                if env.fake.tpm_keys() == tpm_before {
                    violations.push("новый PIN работает со старым TPM-ключом".into());
                }
            } else if env.opens_with_pin(PIN).await {
                record(Outcome::Old);
                // OLD: старый PIN и старые доли работают.
                if !shares_open(&env, &shares) || meta.recovery_generation != shares.generation {
                    violations.push("OLD, но старые доли больше не открывают хранилище".into());
                }
            } else {
                violations.push("NO_UNLOCK_PATH: не открывают ни старый, ни новый PIN".into());
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
async fn recovery_restore_is_atomic() {
    assert_atomic_outcomes("recovery_restore", recovery_restore_case).await;
}

/// Восстановление на другом компьютере: TPM-ключа и checkpoint'а исходного
/// устройства там нет. OLD — хранилище по-прежнему открывается только долями
/// (и повтор восстановления проходит), NEW — открывается новым PIN.
fn recovery_restore_cross_device_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (source, shares) = created().await;
        let mut env = source.copy_to_other_device();
        arm(plan);
        let _ = crate::commands::recovery::restore_from_shares(
            &env.state,
            restore_input(&shares, NEW_PIN),
        )
        .await;
        let (steps, trace) = observed();

        env.restart();
        let mut violations = Vec::new();
        if env.opens_with_pin(NEW_PIN).await {
            record(Outcome::New);
        } else {
            record(Outcome::Old);
            env.restart();
            if let Err(error) = crate::commands::recovery::restore_from_shares(
                &env.state,
                restore_input(&shares, NEW_PIN),
            )
            .await
            {
                violations.push(format!(
                    "OLD, но повтор восстановления не проходит: {error}"
                ));
            }
            if !env.opens_with_pin(NEW_PIN).await {
                violations.push("после повтора восстановления новый PIN не открывает".into());
            }
        }
        env.restart();
        violations.extend(inspect(&env).await.1);
        if !env.opens_with_pin(NEW_PIN).await {
            violations.push("новый PIN не открывает хранилище с данными".into());
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn recovery_restore_on_another_device_is_atomic() {
    assert_atomic_outcomes(
        "recovery_restore_cross_device",
        recovery_restore_cross_device_case,
    )
    .await;
}

/// После восстановления старый integrity-ключ не остаётся в памяти: сессия
/// закрыта, вход — новым PIN.
#[tokio::test]
async fn recovery_closes_the_session_and_rotates_every_key() {
    let (mut env, shares) = created().await;
    env.unlock(PIN).await.unwrap();
    let before = meta(&env);
    let checkpoints_before = env.checkpoints();
    crate::commands::recovery::restore_from_shares(&env.state, restore_input(&shares, NEW_PIN))
        .await
        .unwrap();
    assert!(!env.state.session.lock().is_unlocked(), "сессия закрыта");
    let after = meta(&env);
    assert_ne!(after.dpapi_entropy, before.dpapi_entropy);
    assert_ne!(after.device_secret_tpm_name, before.device_secret_tpm_name);
    assert_ne!(after.wrapped_master_dpapi, before.wrapped_master_dpapi);
    assert!(
        env.checkpoints().is_disjoint(&checkpoints_before),
        "checkpoint сменился"
    );
    assert_eq!(env.checkpoints().len(), 1);
    assert!(env.opens_with_pin(NEW_PIN).await);
    assert_eq!(env.read_canary().as_deref(), Some(CANARY));
}

/// Одной части не хватает даже на том ПК, где создано хранилище: на
/// устройстве части нет, нужны обе — B и C. Повтор одной и той же части
/// второй не считается. Отказ ничего не меняет.
#[tokio::test]
async fn one_share_is_not_enough_on_the_same_device() {
    let (mut env, shares) = created().await;
    let before = meta(&env);
    for parts in [
        vec![shares.b.clone()],
        vec![shares.c.clone()],
        vec![shares.b.clone(), shares.b.clone()],
    ] {
        let input = RestoreInput {
            shares_hex: parts,
            new_pin: NEW_PIN.into(),
        };
        assert!(
            crate::commands::recovery::restore_from_shares(&env.state, input)
                .await
                .is_err()
        );
    }
    let after = meta(&env);
    assert_eq!(after.wrapped_master_dpapi, before.wrapped_master_dpapi);
    assert_eq!(after.security_epoch, before.security_epoch);
    assert!(
        env.opens_with_pin(PIN).await,
        "старый PIN по-прежнему открывает"
    );
}

// ------------------------------------------------------------ новое поколение

fn recovery_regenerate_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (mut env, old) = created().await;
        env.unlock(PIN).await.expect("unlock");
        env.authorize(SecurityAction::RegenerateRecovery).await;
        arm(plan);
        let result = crate::commands::recovery::regenerate_recovery(&env.state);
        let (steps, trace) = observed();

        let (meta, mut violations) = restart_and_inspect(&mut env).await;
        if let Some(meta) = meta {
            if meta.recovery_generation == old.generation {
                record(Outcome::Old);
                if meta.recovery_state != RecoveryState::Active || !shares_open(&env, &old) {
                    violations.push("OLD, но прежнее поколение не работает".into());
                }
            } else if meta.recovery_generation == old.generation + 1 {
                record(Outcome::New);
                if meta.recovery_state != RecoveryState::Pending {
                    violations.push("новое поколение не ждёт подтверждения".into());
                }
                if shares_open(&env, &old) {
                    violations.push("прежнее поколение не отозвано".into());
                }
                if let Ok(output) = &result {
                    let fresh = Shares {
                        generation: output.generation,
                        b: output.recovery_share_b_hex.clone(),
                        c: output.recovery_share_c_hex.clone(),
                    };
                    if !shares_open(&env, &fresh) {
                        violations.push("выданные доли не открывают хранилище".into());
                    }
                }
            } else {
                violations.push(format!("поколение {}", meta.recovery_generation));
            }
        }
        if !env.opens_with_pin(PIN).await {
            violations.push("PIN не открывает хранилище".into());
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn recovery_regenerate_is_atomic() {
    assert_atomic_outcomes("recovery_regenerate", recovery_regenerate_case).await;
}

// ------------------------------------------------------------ отключение

fn recovery_disable_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (mut env, old) = created().await;
        env.unlock(PIN).await.expect("unlock");
        env.authorize(SecurityAction::DisableRecovery).await;
        arm(plan);
        let _ = crate::commands::recovery::disable_recovery(&env.state);
        let (steps, trace) = observed();

        let (meta, mut violations) = restart_and_inspect(&mut env).await;
        if let Some(meta) = meta {
            match meta.recovery_state {
                RecoveryState::Active if shares_open(&env, &old) => record(Outcome::Old),
                RecoveryState::Disabled if !shares_open(&env, &old) => record(Outcome::New),
                other => violations.push(format!(
                    "восстановление ни старое, ни новое: {other:?}, доли открывают={}",
                    shares_open(&env, &old)
                )),
            }
        }
        if !env.opens_with_pin(PIN).await {
            violations.push("PIN не открывает хранилище".into());
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn recovery_disable_is_atomic() {
    assert_atomic_outcomes("recovery_disable", recovery_disable_case).await;
}

// ------------------------------------------------------------ сценарий A

/// Commit создания состоялся, а ответ с долями B и C до пользователя не
/// дошёл. Хранилище остаётся `pending`; следующий вход ведёт к выдаче нового
/// комплекта, а неполученное поколение отзывается.
#[tokio::test]
async fn lost_create_response_leads_to_a_new_share_set_on_next_unlock() {
    let mut env = Env::new();
    let lost = env.create().await; // ответ «потерян»: не подтверждён
    let lost = Shares {
        generation: lost.recovery_generation,
        b: lost.recovery_share_b_hex,
        c: lost.recovery_share_c_hex,
    };
    env.restart();
    assert_eq!(meta(&env).recovery_state, RecoveryState::Pending);

    env.unlock(PIN).await.unwrap();
    // Вход только что доказал PIN: новое поколение выдаётся без повторного ввода.
    let fresh = crate::commands::recovery::regenerate_recovery(&env.state)
        .expect("pending leads to a new generation right after unlock");
    assert!(fresh.generation > lost.generation);
    assert!(!shares_open(&env, &lost), "неполученное поколение отозвано");
    crate::commands::recovery::acknowledge_recovery(&env.state, fresh.generation).unwrap();
    assert_eq!(meta(&env).recovery_state, RecoveryState::Active);

    // Подтверждённое хранилище такого разрешения при входе уже не получает.
    env.restart();
    env.unlock(PIN).await.unwrap();
    assert!(matches!(
        crate::commands::recovery::regenerate_recovery(&env.state),
        Err(crate::error::VaultError::AuthorizationRequired(_))
    ));
}

/// То же для регенерации: сбой после commit нового поколения, до показа долей.
#[tokio::test]
async fn crash_after_regenerate_commit_leads_to_a_new_share_set() {
    let (env, _) = created().await;
    env.unlock(PIN).await.unwrap();
    env.authorize(SecurityAction::RegenerateRecovery).await;
    arm(None);
    crate::commands::recovery::regenerate_recovery(&env.state).unwrap();
    let (_, trace) = observed();
    let after_commit = trace
        .iter()
        .position(|step| *step == "meta.commit")
        .expect("commit step")
        + 2;

    let (mut env, _) = created().await;
    env.unlock(PIN).await.unwrap();
    env.authorize(SecurityAction::RegenerateRecovery).await;
    arm(Some((after_commit, Mode::Crash)));
    assert!(crate::commands::recovery::regenerate_recovery(&env.state).is_err());
    env.restart();
    assert_eq!(meta(&env).recovery_state, RecoveryState::Pending);
    env.unlock(PIN).await.unwrap();
    let fresh = crate::commands::recovery::regenerate_recovery(&env.state).unwrap();
    crate::commands::recovery::acknowledge_recovery(&env.state, fresh.generation).unwrap();
}

/// Подтвердить можно только текущее поколение.
#[tokio::test]
async fn only_the_current_generation_can_be_acknowledged() {
    let env = Env::new();
    let output = env.create().await;
    assert!(crate::commands::recovery::acknowledge_recovery(
        &env.state,
        output.recovery_generation + 1
    )
    .is_err());
    crate::commands::recovery::acknowledge_recovery(&env.state, output.recovery_generation)
        .unwrap();
}
