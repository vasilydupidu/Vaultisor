//! Повторная аутентификация для изменений политики безопасности.
//!
//! Открытая сессия сама по себе не даёт права менять факторы входа и
//! подтверждения: иначе их меняет любой, кто оказался у разблокированного
//! хранилища, — в том числе отключает защиту, поставленную именно против
//! него, или оставляет себе постоянный доступ (свой FIDO2-ключ, свои доли).
//!
//! Схема:
//!
//! ```text
//! security_authorize(действие, PIN)  → свежая проверка PIN (+ Hello, если
//!                                       включён) → разрешение в сессии
//! команда действия                   → consume(действие): разрешение
//!                                       изымается и проверяется
//! ```
//!
//! Разрешение живёт только на стороне backend, внутри разблокированной
//! сессии: блокировка, автоблокировка и перезапуск уничтожают его вместе с
//! сессией. Оно выдаётся на одно конкретное действие, действует
//! `AUTHORIZATION_TTL` и одноразово. Фронтенд не может ни передать признак
//! «разрешено», ни продлить разрешение, ни применить его к другому действию.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::error::{Result, VaultError};
use crate::state::{AppState, SessionState};

/// Сколько живёт разрешение. Достаточно, чтобы после ввода PIN пройти
/// системный диалог (Hello, токен), и мало, чтобы разрешение не лежало без дела.
pub const AUTHORIZATION_TTL: Duration = Duration::from_secs(120);

/// Действия, меняющие политику безопасности хранилища.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityAction {
    ChangePin,
    EnableHello,
    DisableHello,
    EnableStepUp,
    DisableStepUp,
    BindFido,
    UnbindFido,
    RegenerateRecovery,
    DisableRecovery,
    RestoreBackup,
    ChangeBackupDirectory,
    WeakenSettings,
}

impl SecurityAction {
    pub fn as_str(self) -> &'static str {
        match self {
            SecurityAction::ChangePin => "change_pin",
            SecurityAction::EnableHello => "enable_hello",
            SecurityAction::DisableHello => "disable_hello",
            SecurityAction::EnableStepUp => "enable_step_up",
            SecurityAction::DisableStepUp => "disable_step_up",
            SecurityAction::BindFido => "bind_fido",
            SecurityAction::UnbindFido => "unbind_fido",
            SecurityAction::RegenerateRecovery => "regenerate_recovery",
            SecurityAction::DisableRecovery => "disable_recovery",
            SecurityAction::RestoreBackup => "restore_backup",
            SecurityAction::ChangeBackupDirectory => "change_backup_directory",
            SecurityAction::WeakenSettings => "weaken_settings",
        }
    }
}

/// Разрешение на одно действие внутри текущей сессии.
#[derive(Debug, Clone, Copy)]
pub struct Authorization {
    action: SecurityAction,
    issued_at: Instant,
}

impl Authorization {
    /// Разрешение, выданное по уже проверенному PIN (например, при создании
    /// хранилища: PIN только что задан).
    pub(crate) fn fresh(action: SecurityAction) -> Self {
        Self {
            action,
            issued_at: Instant::now(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeInput {
    pub action: SecurityAction,
    pub pin: crate::auth::pin::Secret,
}

#[tauri::command]
pub async fn security_authorize(input: AuthorizeInput, state: State<'_, AppState>) -> Result<()> {
    authorize(&state, input.action, &input.pin).await
}

/// Проверить PIN (и Hello, если он включён) заново и выдать разрешение.
pub(crate) async fn authorize(state: &AppState, action: SecurityAction, pin: &str) -> Result<()> {
    let _auth_flow = state.auth_flow.lock().await;
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    let (session_master, integrity_key, stamp) = {
        let session = state.session.lock();
        match &*session {
            SessionState::Unlocked {
                master_key,
                integrity_key,
                unlocked_at,
                ..
            } => (master_key.clone(), integrity_key.clone(), *unlocked_at),
            SessionState::Locked => return Err(VaultError::Locked),
        }
    };

    let db = state.open_meta()?;
    db.verify_meta_integrity(&integrity_key)?;
    let meta = db.vault_load()?.ok_or(VaultError::NotInitialized)?;

    // Тот же путь, что при входе: задержки, счётчик, криптографическая
    // проверка PIN разворотом мастер-ключа.
    let proven = crate::commands::vault::verify_pin(state, &db, &meta, &integrity_key, pin).await?;
    // PIN обязан открывать именно ключ этой сессии.
    let same = proven.with_decrypted(|a| {
        session_master.with_decrypted(|b| bool::from(subtle::ConstantTimeEq::ct_eq(&a[..], &b[..])))
    });
    if !same {
        return Err(VaultError::InvalidPin);
    }

    if meta.use_windows_hello {
        let (Some(name), Some(public_key)) = (
            meta.hello_key_credential_name.clone(),
            meta.hello_key_credential_public_key.clone(),
        ) else {
            return Err(VaultError::HelloSetupRequired(
                "Windows Hello включён, но его credential отсутствует.".into(),
            ));
        };
        let os = state.os.clone();
        crate::blocking::run(move || os.hello_verify(&name, &public_key)).await?;
    }

    let mut session = state.session.lock();
    match &mut *session {
        SessionState::Unlocked {
            unlocked_at,
            authorization,
            ..
        } if *unlocked_at == stamp => {
            *authorization = Some(Authorization::fresh(action));
            Ok(())
        }
        _ => Err(VaultError::Locked),
    }
}

/// Изъять разрешение на действие. Без свежего разрешения именно на это
/// действие — отказ. Разрешение одноразовое: после изъятия его нет, даже если
/// само действие потом не удалось.
pub(crate) fn consume(state: &AppState, action: SecurityAction) -> Result<()> {
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    let mut session = state.session.lock();
    let SessionState::Unlocked { authorization, .. } = &mut *session else {
        return Err(VaultError::Locked);
    };
    match authorization.take() {
        Some(granted)
            if granted.action == action && granted.issued_at.elapsed() < AUTHORIZATION_TTL =>
        {
            Ok(())
        }
        _ => Err(VaultError::AuthorizationRequired(action.as_str())),
    }
}

/// Выдать разрешение в только что открытой сессии без повторного ввода PIN:
/// PIN был проверен мгновением раньше (создание хранилища).
pub(crate) fn grant_after_proof(state: &AppState, action: SecurityAction) {
    if let SessionState::Unlocked { authorization, .. } = &mut *state.session.lock() {
        *authorization = Some(Authorization::fresh(action));
    }
}

/// Состарить выданное разрешение до истечения срока (для тестов срока жизни).
#[cfg(test)]
pub(crate) fn expire_for_test(state: &AppState) {
    if let SessionState::Unlocked {
        authorization: Some(granted),
        ..
    } = &mut *state.session.lock()
    {
        granted.issued_at = Instant::now()
            .checked_sub(AUTHORIZATION_TTL)
            .expect("monotonic clock is past the TTL");
    }
}
