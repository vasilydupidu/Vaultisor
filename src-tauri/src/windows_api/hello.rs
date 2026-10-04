// Доступность Windows Hello и HWND главного окна для системных диалогов.
//
// Сама проверка Hello выполняется WebAuthn-assertion платформенного
// credential (key_credential.rs); здесь только вспомогательные вещи.

use windows::Security::Credentials::UI::{UserConsentVerifier, UserConsentVerifierAvailability};

use crate::error::{Result, VaultError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum HelloAvailability {
    Available,
    DeviceNotPresent,
    NotConfiguredForUser,
    DisabledByPolicy,
    DeviceBusy,
    Unknown,
}

impl From<UserConsentVerifierAvailability> for HelloAvailability {
    fn from(v: UserConsentVerifierAvailability) -> Self {
        match v {
            UserConsentVerifierAvailability::Available => HelloAvailability::Available,
            UserConsentVerifierAvailability::DeviceNotPresent => {
                HelloAvailability::DeviceNotPresent
            }
            UserConsentVerifierAvailability::NotConfiguredForUser => {
                HelloAvailability::NotConfiguredForUser
            }
            UserConsentVerifierAvailability::DisabledByPolicy => {
                HelloAvailability::DisabledByPolicy
            }
            UserConsentVerifierAvailability::DeviceBusy => HelloAvailability::DeviceBusy,
            _ => HelloAvailability::Unknown,
        }
    }
}

pub fn is_available() -> bool {
    matches!(check_availability(), Ok(HelloAvailability::Available))
}

pub fn check_availability() -> Result<HelloAvailability> {
    run_in_sta(|| {
        let op = UserConsentVerifier::CheckAvailabilityAsync()
            .map_err(|e| VaultError::System(format!("UserConsentVerifier: {e}")))?;
        let avail = pump_wait(&op)
            .map_err(|e| VaultError::System(format!("UserConsentVerifier.get: {e}")))?;
        Ok(HelloAvailability::from(avail))
    })
}

pub fn main_window_hwnd(app: &tauri::AppHandle) -> Result<isize> {
    use tauri::Manager;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        BringWindowToTop, SetForegroundWindow, ShowWindow, SW_SHOWNORMAL,
    };

    let window = app
        .get_webview_window("main")
        .ok_or_else(|| VaultError::System("Main window is not available".into()))?;

    let _ = window.show();
    let _ = window.unminimize();
    let _ = window.set_focus();

    let hwnd = window
        .hwnd()
        .map_err(|e| VaultError::System(format!("Main window HWND: {e}")))?;
    let hwnd_raw = hwnd.0 as isize;
    let hwnd = HWND(hwnd_raw as *mut _);

    // SAFETY: Passing a valid window handle obtained from Tauri to standard Win32 UI functions.
    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOWNORMAL);
        let _ = BringWindowToTop(hwnd);
        let _ = SetForegroundWindow(hwnd);
    }

    Ok(hwnd_raw)
}

pub(crate) fn run_in_sta<F, R>(f: F) -> Result<R>
where
    F: FnOnce() -> Result<R> + Send + 'static,
    R: Send + 'static,
{
    let handle = std::thread::spawn(move || -> Result<R> {
        // SAFETY: Initializes COM for the newly spawned thread using the standard STA model. Safe to call as it does not operate on shared states.
        unsafe {
            use windows::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED};
            CoInitializeEx(None, COINIT_APARTMENTTHREADED)
                .ok()
                .map_err(|_| VaultError::HelloUnavailable)?;
        }
        let result = f();
        // SAFETY: balances successful initialization on this same thread.
        unsafe {
            windows::Win32::System::Com::CoUninitialize();
        }
        result
    });
    handle
        .join()
        .map_err(|_| VaultError::System("Hello-thread panicked".into()))?
}

/// Сколько ждём ответа системного диалога Windows Hello, прежде чем считать
/// операцию зависшей.
///
/// AUDIT 3.1.1: цикл был бесконечным. Если диалог согласия не отвечал
/// (заблокированный экран, зависший CredentialUIBroker), поток blocking-пула и
/// STA-поток оставались занятыми навсегда, а интерфейс «висел» без объяснения.
const HELLO_PROMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

pub(crate) fn pump_wait<T>(op: &windows_future::IAsyncOperation<T>) -> windows::core::Result<T>
where
    T: windows::core::RuntimeType,
{
    let deadline = std::time::Instant::now() + HELLO_PROMPT_TIMEOUT;
    loop {
        if std::time::Instant::now() >= deadline {
            log::warn!("Windows Hello prompt timed out; cancelling");
            let _ = op.Cancel();
            break;
        }
        // SAFETY: Safely invoking the Windows message loop with a zero-initialized MSG structure. Message processing functions use valid pointers.
        unsafe {
            let mut msg = std::mem::zeroed();
            while windows::Win32::UI::WindowsAndMessaging::PeekMessageW(
                &mut msg,
                None,
                0,
                0,
                windows::Win32::UI::WindowsAndMessaging::PM_REMOVE,
            )
            .into()
            {
                let _ = windows::Win32::UI::WindowsAndMessaging::TranslateMessage(&msg);
                windows::Win32::UI::WindowsAndMessaging::DispatchMessageW(&msg);
            }
        }

        if let Ok(status) = op.Status() {
            if status != windows_future::AsyncStatus::Started {
                break;
            }
        } else {
            break;
        }

        // SAFETY: Safely waiting for message queue events using Win32 API. No handles are passed, just waiting for input.
        unsafe {
            windows::Win32::UI::WindowsAndMessaging::MsgWaitForMultipleObjects(
                None,
                false,
                10,
                windows::Win32::UI::WindowsAndMessaging::QS_ALLINPUT,
            );
        }
    }
    op.GetResults()
}
