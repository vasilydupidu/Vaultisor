// Блокировка хранилища по событиям сеанса Windows.
//
// Раньше этот модуль содержал только обёртки над
// WTSRegisterSessionNotification, которые нигде не вызывались, а обработчика
// WM_WTSSESSION_CHANGE не существовало вовсе. Практический результат: Win+L,
// закрытие крышки ноутбука, уход в сон и переключение пользователя НЕ
// блокировали хранилище — сессия оставалась открытой до срабатывания
// idle-таймера (а при autolock_seconds = 0 не блокировалась никогда).
//
// Теперь в отдельном потоке живёт message-only окно, подписанное на
// уведомления сеанса и питания. При блокировке/отключении/засыпании оно
// вызывает AppState::lock() (это же чистит file-grants и буфер обмена) и
// сообщает интерфейсу событием, чтобы тот сразу ушёл на экран блокировки.

use std::sync::OnceLock;

use tauri::{AppHandle, Emitter, Manager};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::RemoteDesktop::{
    WTSRegisterSessionNotification, WTSUnRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW,
    TranslateMessage, CW_USEDEFAULT, HWND_MESSAGE, MSG, WINDOW_EX_STYLE, WINDOW_STYLE, WNDCLASSW,
};

use crate::state::AppState;

/// Событие для фронтенда: сессия закрыта не пользователем, а системой.
pub const SESSION_LOCKED_EVENT: &str = "vault://session-locked";

const WM_WTSSESSION_CHANGE: u32 = 0x02B1;
const WM_POWERBROADCAST: u32 = 0x0218;
const WM_ENDSESSION: u32 = 0x0016;

const WTS_CONSOLE_DISCONNECT: usize = 0x2;
const WTS_REMOTE_DISCONNECT: usize = 0x4;
const WTS_SESSION_LOCK: usize = 0x7;
const PBT_APMSUSPEND: usize = 0x4;

static WATCHER_APP: OnceLock<AppHandle> = OnceLock::new();

/// Запустить наблюдатель за событиями сеанса. Вызывается один раз при старте.
/// Ошибки не фатальны: без наблюдателя остаётся idle-автоблокировка.
pub fn spawn_session_lock_watcher(app: AppHandle) {
    if WATCHER_APP.set(app).is_err() {
        log::warn!("session watcher already started");
        return;
    }
    std::thread::Builder::new()
        .name("vaultisor-session-watcher".into())
        .spawn(|| {
            if let Err(error) = run_watcher() {
                log::warn!("session lock watcher stopped: {error}");
            }
        })
        .ok();
}

fn lock_reason(message: u32, wparam: WPARAM) -> Option<&'static str> {
    match message {
        WM_WTSSESSION_CHANGE => match wparam.0 {
            WTS_SESSION_LOCK => Some("session lock"),
            WTS_CONSOLE_DISCONNECT => Some("console disconnect"),
            WTS_REMOTE_DISCONNECT => Some("remote disconnect"),
            _ => None,
        },
        WM_POWERBROADCAST if wparam.0 == PBT_APMSUSPEND => Some("system suspend"),
        WM_ENDSESSION => Some("session end"),
        _ => None,
    }
}

fn lock_now(reason: &str) {
    let Some(app) = WATCHER_APP.get() else {
        return;
    };
    if let Some(state) = app.try_state::<AppState>() {
        let was_unlocked = state.session.lock().is_unlocked();
        state.lock();
        if was_unlocked {
            log::warn!("vault locked by Windows event: {reason}");
        }
    }
    let _ = app.emit(SESSION_LOCKED_EVENT, reason);
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if let Some(reason) = lock_reason(message, wparam) {
        lock_now(reason);
    }
    // SAFETY: forwarding an unhandled message to the default handler.
    unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
}

fn run_watcher() -> crate::error::Result<()> {
    use crate::error::VaultError;

    let class_name: Vec<u16> = "VaultisorSessionWatcher\0".encode_utf16().collect();

    // SAFETY: all pointers reference buffers that outlive the calls below; the
    // window is message-only and owned solely by this thread.
    unsafe {
        let class = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            lpszClassName: PCWSTR(class_name.as_ptr()),
            hInstance: HINSTANCE::default(),
            ..Default::default()
        };
        if RegisterClassW(&class) == 0 {
            return Err(VaultError::System("RegisterClassW failed".into()));
        }

        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            PCWSTR(class_name.as_ptr()),
            PCWSTR(class_name.as_ptr()),
            WINDOW_STYLE(0),
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            None,
            None,
        )
        .map_err(|e| VaultError::System(format!("CreateWindowExW: {e}")))?;

        WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION)
            .map_err(|e| VaultError::System(format!("WTSRegisterSessionNotification: {e}")))?;
        log::info!("session lock watcher registered");

        let mut message = MSG::default();
        while GetMessageW(&mut message, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }

        let _ = WTSUnRegisterSessionNotification(hwnd);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locking_events_are_recognised() {
        assert_eq!(
            lock_reason(WM_WTSSESSION_CHANGE, WPARAM(WTS_SESSION_LOCK)),
            Some("session lock")
        );
        assert_eq!(
            lock_reason(WM_WTSSESSION_CHANGE, WPARAM(WTS_CONSOLE_DISCONNECT)),
            Some("console disconnect")
        );
        assert_eq!(
            lock_reason(WM_WTSSESSION_CHANGE, WPARAM(WTS_REMOTE_DISCONNECT)),
            Some("remote disconnect")
        );
        assert_eq!(
            lock_reason(WM_POWERBROADCAST, WPARAM(PBT_APMSUSPEND)),
            Some("system suspend")
        );
        assert_eq!(lock_reason(WM_ENDSESSION, WPARAM(0)), Some("session end"));
    }

    #[test]
    fn unlock_and_unrelated_events_do_not_lock() {
        // WTS_SESSION_UNLOCK (0x8) и WTS_SESSION_LOGON (0x5) не должны запирать
        // хранилище: пользователь как раз вернулся за компьютер.
        assert_eq!(lock_reason(WM_WTSSESSION_CHANGE, WPARAM(0x8)), None);
        assert_eq!(lock_reason(WM_WTSSESSION_CHANGE, WPARAM(0x5)), None);
        // PBT_APMRESUMEAUTOMATIC (0x12) — возобновление, не засыпание.
        assert_eq!(lock_reason(WM_POWERBROADCAST, WPARAM(0x12)), None);
        assert_eq!(lock_reason(0x0001, WPARAM(WTS_SESSION_LOCK)), None);
    }
}
