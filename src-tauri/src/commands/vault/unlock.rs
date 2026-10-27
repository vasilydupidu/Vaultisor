use serde::Deserialize;
use tauri::State;

use crate::auth::backoff::{BackoffState, Gate, MAX_DELAY_SECS};
use crate::crypto::master::MasterKey;
use crate::error::{Result, VaultError};
use crate::state::AppState;
use crate::storage::meta_db::{MetaDb, VaultMetaRow};

use super::*;
use crate::commands::vault::helpers::{
    apply_settings, load_device_secret_and_unwrap, open_session_with, unwrap_master_blob,
    unwrap_master_off_thread, DataRollback,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultUnlockInput {
    pub pin: String,
}

/// Разблокировка хранилища.
///
/// Сначала PIN Vaultisor, и только он даёт мастер-ключ. Windows Hello, если
/// включён, добавляется как второй фактор (логическое И) — это проверка
/// WebAuthn-подписи платформенного credential, которая не участвует в выводе
/// ключа и не может его заменить.
#[tauri::command]
pub async fn vault_unlock(input: VaultUnlockInput, state: State<'_, AppState>) -> Result<()> {
    unlock_with_pin(&state, input).await
}

/// Вход после `DATA_ROLLBACK` с явным решением владельца продолжить с
/// текущими (старыми) базами. Та же полная проверка PIN и Hello, что и при
/// обычном входе; по смыслу это восстановление из копии, которое тоже
/// требует PIN.
#[tauri::command]
pub async fn vault_unlock_accept_rollback(
    input: AcceptRollbackInput,
    state: State<'_, AppState>,
) -> Result<()> {
    unlock_with_pin_policy(
        &state,
        VaultUnlockInput { pin: input.pin },
        DataRollback::Accept {
            snapshot: input.snapshot,
        },
    )
    .await
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptRollbackInput {
    pub pin: String,
    /// Идентификатор снимка из `DATA_ROLLBACK`, который видел владелец.
    pub snapshot: String,
}

/// Метаданные после проверки DPAPI и целостности: integrity-ключ и строка,
/// прочитанная уже ПОСЛЕ проверки MAC и якорей.
pub(crate) fn verified_meta(db: &MetaDb) -> Result<(zeroize::Zeroizing<[u8; 32]>, VaultMetaRow)> {
    let entropy = db
        .vault_load()?
        .ok_or(VaultError::NotInitialized)?
        .dpapi_entropy;
    let integrity_key_dpapi = db
        .get_integrity_key_dpapi()?
        .ok_or(VaultError::DeviceMismatch)?;
    let integrity_key = unwrap_integrity_key(&integrity_key_dpapi, &entropy)?;
    db.verify_meta_integrity(&integrity_key)?;
    let meta = db.vault_load()?.ok_or(VaultError::NotInitialized)?;
    Ok((integrity_key, meta))
}

/// Проверить PIN: задержка после неверных попыток, затем разворот
/// мастер-ключа.
///
/// Попытка списывается до проверки: сначала надёжно записывается состояние
/// «эта попытка неверна», и только потом разворачивается мастер-ключ. Верный
/// PIN снимает списание. Поэтому ни сбой процесса, ни отказ записи не дают
/// попытки мимо счётчика: не удалось записать — PIN не проверяется вовсе.
///
/// PIN проверяется только криптографически: неверный PIN даёт неверный KEK, и
/// AEAD-разворот мастер-ключа не проходит. Хэша PIN нет — это был бы готовый
/// офлайн-оракул перебора из бэкапа.
pub(crate) async fn verify_pin(
    state: &AppState,
    db: &MetaDb,
    meta: &VaultMetaRow,
    integrity_key: &[u8; 32],
    pin: &str,
) -> Result<MasterKey> {
    let now = state.os.now_unix();
    // Внешний checkpoint хранит состояние задержек отдельно от метаданных:
    // откат файла метаданных (сбой, импорт, подмена) счётчик не уменьшает.
    let backoff = match db.checkpoint_backoff(integrity_key)? {
        Some(anchored) => meta.backoff.strictest(anchored),
        None => meta.backoff,
    };
    match backoff.gate(now) {
        Gate::Open => {}
        Gate::Wait(seconds) => return Err(VaultError::PinBackoff(seconds)),
        Gate::ClockRewound(next) => {
            log::warn!("verify_pin: system clock moved back, maximum delay applied");
            db.set_backoff(integrity_key, next)?;
            return Err(VaultError::PinBackoff(MAX_DELAY_SECS));
        }
    }

    let wrapped = unwrap_master_blob(&meta.wrapped_master_dpapi, &meta.dpapi_entropy)?;
    let params = crate::crypto::kdf::Argon2Params::from_stored(
        meta.argon2_m_cost,
        meta.argon2_t_cost,
        meta.argon2_p_cost,
    )?;
    let charged = backoff.after_failure(now);
    db.set_backoff(integrity_key, charged)?;

    let result = if meta.crypto_version >= 2 {
        load_device_secret_and_unwrap(&state.os, db, &wrapped, pin.as_bytes(), params).await
    } else {
        unwrap_master_off_thread(wrapped, pin.as_bytes(), None, params).await
    };
    match result {
        Ok(master) => {
            db.set_backoff(integrity_key, BackoffState::default())?;
            Ok(master)
        }
        Err(VaultError::InvalidPin) => {
            log::warn!(
                "verify_pin: invalid PIN, consecutive failures={}",
                charged.failures
            );
            Err(VaultError::InvalidPin)
        }
        // Ошибки TPM/DPAPI/ввода-вывода попыткой не считаются: пользователь не
        // виноват, что железо недоступно. Не удалось вернуть — попытка
        // остаётся списанной, это безопасная сторона.
        Err(error) => {
            if let Err(restore) = db.set_backoff(integrity_key, backoff) {
                log::warn!("verify_pin: attempt stays charged: {restore}");
            }
            Err(error)
        }
    }
}

pub(crate) async fn unlock_with_pin(state: &AppState, input: VaultUnlockInput) -> Result<()> {
    unlock_with_pin_policy(state, input, DataRollback::Refuse).await
}

pub(crate) async fn unlock_with_pin_policy(
    state: &AppState,
    input: VaultUnlockInput,
    rollback: DataRollback,
) -> Result<()> {
    let _auth_flow = state.auth_flow.lock().await;
    // До открытия метаданных: при пропавшем файле открытие создало бы пустую
    // базу, а вход закончился бы безликой ошибкой.
    crate::commands::system::require_complete_vault(state)?;
    let db = state.open_meta()?;
    let (integrity_key, meta) = verified_meta(&db)?;
    let master = verify_pin(state, &db, &meta, &integrity_key, &input.pin).await?;

    // Второй фактор. Верный PIN дал лишь временное значение мастер-ключа;
    // сессии нет, пока Windows не подтвердит владельца тем credential'ом, чей
    // публичный ключ защищён MAC-ом.
    if meta.use_windows_hello {
        let (Some(name), Some(public_key)) = (
            meta.hello_key_credential_name.clone(),
            meta.hello_key_credential_public_key.clone(),
        ) else {
            return Err(VaultError::HelloSetupRequired(
                "Windows Hello включён, но его credential отсутствует.".into(),
            ));
        };
        // Отказ Windows чаще всего означает «ключа больше нет» (его удалили в
        // Параметрах). Подставить вместо второго фактора один PIN нельзя — это
        // и был бы обход фактора, — поэтому объясняем, куда идти дальше.
        let os = state.os.clone();
        if let Err(error) = crate::blocking::run(move || os.hello_verify(&name, &public_key)).await
        {
            return Err(match error {
                VaultError::HelloCancelled => VaultError::HelloCancelled,
                other => {
                    log::warn!("vault_unlock: Hello second factor failed ({other})");
                    VaultError::HelloOsError(format!(
                        "{other}. Если ключ Windows Hello был удалён в Параметрах → Учётные записи → Ключи доступа, восстановите доступ по долям B и C."
                    ))
                }
            });
        }

        // Системный диалог может длиться долго. За это время восстановление
        // или другая защищённая мутация могли изменить состояние.
        let current = db.vault_load()?.ok_or(VaultError::NotInitialized)?;
        if current.security_epoch < meta.security_epoch || !current.use_windows_hello {
            return Err(VaultError::Locked);
        }
    }

    open_session_with(state, master, integrity_key, rollback)?;
    after_unlock(state, &meta, Proof::Pin);
    log::info!("vault_unlock: success");
    Ok(())
}

/// Чем вход доказал владение хранилищем.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Proof {
    /// PIN Vaultisor (и Hello, если он включён).
    Pin,
    /// FIDO2-ключ — самостоятельный путь входа без PIN.
    Fido,
}

/// Общее для всех путей входа после открытия сессии.
///
/// Незавершённое восстановление (`pending`: части выданы, но не подтверждены,
/// израсходованы или хранилище импортировано) ведёт к выдаче нового
/// комплекта. Части B и C — переносимый доступ к хранилищу, поэтому без
/// повторного ввода их выдаёт только вход, доказавший PIN. После входа по
/// FIDO2 интерфейс спросит PIN при выдаче: иначе ключ «только касание» на
/// этом ПК давал бы части, открывающие хранилище где угодно.
pub(crate) fn after_unlock(state: &AppState, meta: &VaultMetaRow, proof: Proof) {
    apply_settings(state, meta);
    if proof == Proof::Pin && meta.recovery_state == crate::storage::meta_db::RecoveryState::Pending
    {
        crate::commands::security::grant_after_proof(
            state,
            crate::commands::security::SecurityAction::RegenerateRecovery,
        );
    }
}
