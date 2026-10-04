//! Постусловия этапа 2: подтверждение действий, смена PIN, задержки PIN,
//! привязка FIDO2 к устройству.

use super::harness::{Env, CANARY, NEW_PIN, PIN, WRONG_PIN};
use crate::auth::backoff::MAX_DELAY_SECS;
use crate::commands::security::{self, SecurityAction};
use crate::commands::vault::ChangePinInput;
use crate::error::VaultError;

/// Хранилище с канарейкой, открытое.
async fn unlocked() -> Env {
    let env = Env::new();
    env.create().await;
    env.add_canary();
    env.state.lock();
    env.unlock(PIN).await.expect("unlock");
    env
}

async fn change_pin(env: &Env, new_pin: &str) -> crate::error::Result<()> {
    crate::commands::vault::change_pin(
        &env.state,
        ChangePinInput {
            new_pin: new_pin.into(),
            request_id: uuid::Uuid::new_v4().to_string(),
        },
    )
    .await
}

fn auth_required(result: crate::error::Result<impl std::fmt::Debug>) -> bool {
    matches!(result, Err(VaultError::AuthorizationRequired(_)))
}

// ------------------------------------------------------------ SecurityAuthorization

/// Открытая сессия сама по себе ничего в политике безопасности не меняет.
#[tokio::test]
async fn every_policy_change_requires_authorization() {
    let mut env = unlocked().await;
    assert!(auth_required(change_pin(&env, NEW_PIN).await));
    assert!(auth_required(
        crate::commands::settings::set_hello(&env.state, true).await
    ));
    assert!(auth_required(
        crate::commands::settings::bind_fido2_key(
            &env.state,
            None,
            Some(false),
            &uuid::Uuid::new_v4().to_string()
        )
        .await
    ));
    // Отвязка существующего ключа требует подтверждения; уже отвязанного —
    // успех без него (повтор после потерянного ответа).
    env.bind_fido().await;
    let key_id = env.state.open_meta().unwrap().get_fido2_keys().unwrap()[0]
        .id
        .clone();
    assert!(auth_required(
        crate::commands::settings::unbind_fido2(&env.state, &key_id).await
    ));
    crate::commands::settings::unbind_fido2(&env.state, "already-gone")
        .await
        .unwrap();
    assert!(auth_required(
        crate::commands::recovery::regenerate_recovery(&env.state)
    ));
    assert!(auth_required(crate::commands::recovery::disable_recovery(
        &env.state
    )));
    assert!(auth_required(
        crate::commands::vault::vault_restore_blocking(
            crate::commands::vault::ImportInput {
                capability: "any".into(),
                password: None,
            },
            &env.state,
        )
    ));
    assert!(auth_required(
        crate::commands::vault::vault_export_blocking(
            crate::commands::vault::ExportInput {
                capability: "any".into(),
                password: None,
            },
            &env.state,
        )
    ));
    assert!(auth_required(crate::commands::backup::set_backup_config(
        &env.state,
        crate::commands::backup::BackupSetInput {
            directory_capability: Some("any".into()),
            frequency: "daily".into(),
        },
    )));

    // Hello и подтверждение копирования — тоже.
    env.enable_hello().await;
    assert!(auth_required(
        crate::commands::settings::set_step_up(&env.state, true).await
    ));
    assert!(auth_required(
        crate::commands::settings::set_hello(&env.state, false).await
    ));

    // Ничего из этого не изменилось.
    env.state.lock();
    assert!(env.opens_with_pin(PIN).await);
    let meta = env
        .state
        .open_meta()
        .unwrap()
        .vault_load()
        .unwrap()
        .unwrap();
    assert!(
        meta.recovery_wrapped_master.is_some(),
        "восстановление на месте"
    );
    assert!(!meta.require_auth_for_copy);
}

/// Частота копий — не политика безопасности, каталог — политика.
#[tokio::test]
async fn backup_frequency_does_not_need_authorization() {
    let env = unlocked().await;
    crate::commands::backup::set_backup_config(
        &env.state,
        crate::commands::backup::BackupSetInput {
            directory_capability: None,
            frequency: "weekly".into(),
        },
    )
    .unwrap();
}

#[tokio::test]
async fn authorization_is_single_use() {
    let env = unlocked().await;
    env.authorize(SecurityAction::ChangePin).await;
    change_pin(&env, NEW_PIN).await.expect("first use");
    assert!(auth_required(change_pin(&env, PIN).await));
}

/// Разрешение на A не годится для B — и сгорает при попытке.
#[tokio::test]
async fn authorization_is_scoped_to_one_action() {
    let env = unlocked().await;
    env.authorize(SecurityAction::EnableHello).await;
    assert!(auth_required(change_pin(&env, NEW_PIN).await));
    assert!(auth_required(
        crate::commands::settings::set_hello(&env.state, true).await
    ));
}

#[tokio::test]
async fn authorization_dies_with_the_session() {
    let env = unlocked().await;
    env.authorize(SecurityAction::ChangePin).await;
    env.state.lock();
    env.unlock(PIN).await.unwrap();
    assert!(
        auth_required(change_pin(&env, NEW_PIN).await),
        "после блокировки"
    );

    let mut env = unlocked().await;
    env.authorize(SecurityAction::ChangePin).await;
    env.restart();
    env.unlock(PIN).await.unwrap();
    assert!(
        auth_required(change_pin(&env, NEW_PIN).await),
        "после перезапуска"
    );
}

#[tokio::test]
async fn authorization_expires() {
    let env = unlocked().await;
    env.authorize(SecurityAction::ChangePin).await;
    security::expire_for_test(&env.state);
    assert!(auth_required(change_pin(&env, NEW_PIN).await));
}

#[tokio::test]
async fn authorization_needs_the_correct_pin_and_an_open_session() {
    let env = unlocked().await;
    assert!(matches!(
        security::authorize(&env.state, SecurityAction::ChangePin, WRONG_PIN).await,
        Err(VaultError::InvalidPin)
    ));
    assert_eq!(env.backoff().failures, 1, "неверный PIN учтён как попытка");
    assert!(auth_required(change_pin(&env, NEW_PIN).await));

    env.state.lock();
    assert!(matches!(
        security::authorize(&env.state, SecurityAction::ChangePin, PIN).await,
        Err(VaultError::Locked)
    ));
}

/// С включённым Hello подтверждение требует и PIN, и Hello.
#[tokio::test]
async fn authorization_requires_hello_when_enabled() {
    let env = unlocked().await;
    env.enable_hello().await;
    env.fake.refuse_next_hello();
    assert!(
        security::authorize(&env.state, SecurityAction::DisableHello, PIN)
            .await
            .is_err()
    );
    assert!(auth_required(
        crate::commands::settings::set_hello(&env.state, false).await
    ));
}

// ------------------------------------------------------------ смена PIN

#[tokio::test]
async fn change_pin_keeps_the_session_and_switches_the_pin() {
    let mut env = unlocked().await;
    env.authorize(SecurityAction::ChangePin).await;
    change_pin(&env, NEW_PIN).await.unwrap();
    assert_eq!(env.read_canary().as_deref(), Some(CANARY), "сессия та же");
    assert!(
        !env.opens_with_pin(PIN).await,
        "старый PIN больше не открывает"
    );
    assert!(env.opens_with_pin(NEW_PIN).await, "новый PIN открывает");
}

/// Смена PIN — не путь входа: в запертом хранилище она не работает и сессию
/// не открывает.
#[tokio::test]
async fn change_pin_never_opens_a_session() {
    let mut env = unlocked().await;
    env.state.lock();
    assert!(matches!(
        change_pin(&env, NEW_PIN).await,
        Err(VaultError::Locked)
    ));
    assert!(!env.state.session.lock().is_unlocked());
    assert!(env.opens_with_pin(PIN).await);
}

// ------------------------------------------------------------ задержки PIN

/// Часы ОС в сценариях задержек: остановлены, двигаются только тестом.
const T0: i64 = 1_800_000_000;

async fn fail(env: &Env, times: u32) {
    for _ in 0..times {
        assert!(matches!(
            env.unlock(WRONG_PIN).await,
            Err(VaultError::InvalidPin)
        ));
    }
}

#[tokio::test]
async fn pin_backoff_follows_the_schedule_and_never_locks_out() {
    let mut env = unlocked().await;
    env.fake.set_clock(T0);
    env.state.lock();
    fail(&env, 5).await;
    // 1–5: без задержки — шестая попытка принимается сразу.
    fail(&env, 1).await;
    // 6: 30 с. Даже верный PIN до срока не проверяется.
    assert!(matches!(
        env.unlock(PIN).await,
        Err(VaultError::PinBackoff(30))
    ));
    // Перезапуск задержку не снимает.
    env.restart();
    assert!(matches!(
        env.unlock(PIN).await,
        Err(VaultError::PinBackoff(30))
    ));
    env.fake.advance_clock(30);
    fail(&env, 1).await;
    // 7: 1 мин.
    assert!(matches!(
        env.unlock(WRONG_PIN).await,
        Err(VaultError::PinBackoff(60))
    ));
    env.fake.advance_clock(60);
    // После задержки верный PIN открывает и обнуляет счётчик.
    env.unlock(PIN).await.expect("correct PIN after the delay");
    assert_eq!(env.backoff().failures, 0);

    // 10+: час, но не вечная блокировка.
    env.state.lock();
    fail(&env, 6).await;
    for delay in [30, 60, 5 * 60, 15 * 60] {
        env.fake.advance_clock(delay);
        fail(&env, 1).await;
    }
    assert!(matches!(
        env.unlock(PIN).await,
        Err(VaultError::PinBackoff(MAX_DELAY_SECS))
    ));
    env.fake.advance_clock(MAX_DELAY_SECS);
    env.unlock(PIN).await.expect("no permanent lockout");
}

/// Откат часов назад относительно последней ошибки — максимальная задержка.
#[tokio::test]
async fn clock_rewind_applies_the_maximum_delay() {
    let env = unlocked().await;
    env.fake.set_clock(T0);
    env.state.lock();
    fail(&env, 6).await;
    env.fake.advance_clock(-10 * 60);
    assert!(matches!(
        env.unlock(PIN).await,
        Err(VaultError::PinBackoff(MAX_DELAY_SECS))
    ));
    // Вернуть часы «как было» задержку не снимает: она назначена от момента
    // обнаружения отката.
    env.fake.advance_clock(10 * 60 + 30);
    assert!(matches!(
        env.unlock(PIN).await,
        Err(VaultError::PinBackoff(_))
    ));
    env.fake.advance_clock(MAX_DELAY_SECS);
    env.unlock(PIN)
        .await
        .expect("correct PIN after the maximum delay");
}

// ------------------------------------------------------------ FIDO2

#[tokio::test]
async fn fido_key_opens_the_vault_and_unbind_revokes_it() {
    let mut env = unlocked().await;
    env.bind_fido().await;
    env.restart();
    crate::commands::vault::unlock_with_fido2(&env.state)
        .await
        .expect("bound key opens");
    assert_eq!(env.read_canary().as_deref(), Some(CANARY));

    let id = env.state.open_meta().unwrap().get_fido2_keys().unwrap()[0]
        .id
        .clone();
    env.authorize(SecurityAction::UnbindFido).await;
    crate::commands::settings::unbind_fido2(&env.state, &id)
        .await
        .unwrap();
    env.restart();
    assert!(crate::commands::vault::unlock_with_fido2(&env.state)
        .await
        .is_err());
    assert!(env.opens_with_pin(PIN).await);
}

/// Device binding: скопированное на другой компьютер хранилище вместе с тем
/// же токеном мастер-ключ не отдаёт — нужен Device Secret из TPM исходного
/// устройства.
#[tokio::test]
async fn fido_key_with_copied_vault_on_another_device_does_not_unlock() {
    let env = unlocked().await;
    env.bind_fido().await;
    env.state.lock();

    let other = env.copy_to_other_device();
    assert!(
        !other.fake.fido_credentials().is_empty(),
        "тот же токен поднесён к чужому компьютеру"
    );
    assert!(crate::commands::vault::unlock_with_fido2(&other.state)
        .await
        .is_err());
    assert!(!other.state.session.lock().is_unlocked());
}

/// Не привязанный к хранилищу токен его не открывает.
#[tokio::test]
async fn unknown_fido_token_does_not_unlock() {
    let env = unlocked().await;
    env.bind_fido().await;
    env.state.lock();
    let stranger = Env::new();
    stranger.create().await;
    let foreign = stranger.bind_fido().await;
    env.fake.share_tokens_with(&stranger.fake);
    env.fake.present(&foreign);
    assert!(crate::commands::vault::unlock_with_fido2(&env.state)
        .await
        .is_err());
}
