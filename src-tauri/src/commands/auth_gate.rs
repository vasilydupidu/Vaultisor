// Единый гейт «доступ к секрету» для копирования И просмотра.
//
// Если включена настройка require_auth_for_copy («Подтверждение для копирования
// и просмотра»), то перед раскрытием секрета (reveal на экране) и перед
// копированием в буфер требуется свежее подтверждение Windows Hello.
//
// Чтобы это не превращалось в бесконечные запросы при работе с несколькими
// полями, после успешного Hello действует «окно доверия» AUTH_GRACE: в течение
// этого времени повторный Hello не запрашивается. Метка времени живёт внутри
// SessionState::Unlocked, поэтому автоматически сбрасывается при любой блокировке
// сессии (autolock / ручной lock / закрытие окна).

use std::time::{Duration, Instant};

use crate::error::{Result, VaultError};
use crate::state::{AppState, SessionState};

/// Окно доверия после успешного Hello (повтор не спрашиваем).
const AUTH_GRACE: Duration = Duration::from_secs(60);

/// Проверить право на доступ к секрету (копирование/просмотр).
///
/// - настройка выключена → Ok сразу;
/// - в пределах окна доверия → Ok без запроса;
/// - иначе → Windows Hello; при успехе продлеваем окно доверия.
pub(crate) async fn require_copy_view_auth(state: &AppState) -> Result<()> {
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    let initial =
        super::file_grants::session_stamp(&state.session.lock()).ok_or(VaultError::Locked)?;
    let require_auth = state.settings.lock().require_auth_for_copy;
    if !require_auth {
        return Ok(());
    }

    // Внутри окна доверия — пропускаем без запроса.
    {
        let s = state.session.lock();
        if let SessionState::Unlocked {
            auth_verified_at: Some(t),
            ..
        } = &*s
        {
            if t.elapsed() < AUTH_GRACE {
                return Ok(());
            }
        }
    }

    let meta = state
        .open_meta()?
        .vault_load()?
        .ok_or(VaultError::NotInitialized)?;
    let name = meta
        .hello_key_credential_name
        .as_deref()
        .ok_or(VaultError::CorruptedWrapper)?;
    let public_key = meta
        .hello_key_credential_public_key
        .as_deref()
        .ok_or(VaultError::CorruptedWrapper)?;
    let os = state.os.clone();
    let (name, public_key) = (name.to_owned(), public_key.to_vec());
    crate::blocking::run(move || os.hello_verify(&name, &public_key)).await?;
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    // Успех → продлеваем окно доверия.
    let mut s = state.session.lock();
    if super::file_grants::session_stamp(&s) != Some(initial) {
        return Err(VaultError::Locked);
    }
    if let SessionState::Unlocked {
        auth_verified_at, ..
    } = &mut *s
    {
        *auth_verified_at = Some(Instant::now());
    }
    Ok(())
}
