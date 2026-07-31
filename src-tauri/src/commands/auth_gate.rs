// N-03 (вариант B): единый гейт «доступ к секрету» для копирования И просмотра.
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

use tauri::AppHandle;

use crate::error::Result;
use crate::state::{AppState, SessionState};

/// Окно доверия после успешного Hello (повтор не спрашиваем).
const AUTH_GRACE: Duration = Duration::from_secs(60);

/// Проверить право на доступ к секрету (копирование/просмотр).
///
/// - настройка выключена → Ok сразу;
/// - в пределах окна доверия → Ok без запроса;
/// - иначе → Windows Hello; при успехе продлеваем окно доверия.
pub(crate) async fn require_copy_view_auth(state: &AppState, app: &AppHandle) -> Result<()> {
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

    let hwnd = crate::windows_api::hello::main_window_hwnd(app)?;
    crate::windows_api::hello::verify_with_window(
        app,
        hwnd,
        "Подтвердите Windows Hello для доступа к секрету",
    )
    .await?;
    // Успех → продлеваем окно доверия.
    let mut s = state.session.lock();
    if let SessionState::Unlocked {
        auth_verified_at, ..
    } = &mut *s
    {
        *auth_verified_at = Some(Instant::now());
    }
    Ok(())
}
