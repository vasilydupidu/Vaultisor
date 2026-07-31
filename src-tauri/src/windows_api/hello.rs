// Windows Hello availability and HWND-bound verification.
//
// Important: UserConsentVerifier is a user-consent gate used before the CNG TPM
// key path. The non-exportable key lives in cng_hello.rs; this module owns
// availability checks and HWND-bound Windows Hello prompts.

use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};

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

pub fn hide_main_window_for_system_prompt(app: &tauri::AppHandle) -> Result<()> {
    use tauri::Manager;

    let window = app
        .get_webview_window("main")
        .ok_or_else(|| VaultError::System("Main window is not available".into()))?;
    let _ = window.set_focus();
    let _ = window.hide();
    std::thread::sleep(std::time::Duration::from_millis(180));
    Ok(())
}

pub fn restore_main_window_after_system_prompt(app: &tauri::AppHandle) {
    if let Err(e) = restore_main_window_after_system_prompt_inner(app) {
        log::warn!("Failed to restore main window after Hello prompt: {}", e);
    }
}

fn restore_main_window_after_system_prompt_inner(app: &tauri::AppHandle) -> Result<()> {
    use tauri::Manager;

    let window = app
        .get_webview_window("main")
        .ok_or_else(|| VaultError::System("Main window is not available".into()))?;
    let _ = window.show();
    let _ = window.unminimize();
    let _ = window.set_focus();
    let _ = main_window_hwnd(app);
    Ok(())
}

pub async fn verify_with_window(
    _app: &tauri::AppHandle,
    hwnd_raw: isize,
    message: &str,
) -> Result<()> {
    let message = message.to_owned();
    tauri::async_runtime::spawn_blocking(move || verify_with_window_blocking(hwnd_raw, &message))
        .await
        .map_err(|e| VaultError::System(format!("Hello verification task failed: {e}")))?
}

fn verify_with_window_blocking(hwnd_raw: isize, message: &str) -> Result<()> {
    let message = message.to_owned();
    run_in_sta(move || {
        use windows::Win32::Foundation::HWND;

        let hwnd = HWND(hwnd_raw as *mut _);
        let msg = windows::core::HSTRING::from(&message);

        let interop: windows::Win32::System::WinRT::IUserConsentVerifierInterop =
            windows::core::factory::<
                windows::Security::Credentials::UI::UserConsentVerifier,
                windows::Win32::System::WinRT::IUserConsentVerifierInterop,
            >()
            .map_err(|e| {
                VaultError::System(format!("IUserConsentVerifierInterop unavailable: {e}"))
            })?;

        log::info!(
            "Hello verify_with_window: RequestVerificationForWindowAsync(HWND={:x})",
            hwnd_raw
        );
        // SAFETY: RequestVerificationForWindowAsync takes a valid HWND and an HSTRING. The lifetimes are managed correctly and thread context is valid for COM.
        let op = unsafe {
            interop
                .RequestVerificationForWindowAsync(hwnd, &msg)
                .map_err(|e| VaultError::System(format!("Hello HWND verify: {e}")))?
        };
        let result =
            pump_wait(&op).map_err(|e| VaultError::System(format!("Hello verify results: {e}")))?;
        verification_result_to_result(result)
    })
}

fn verification_result_to_result(result: UserConsentVerificationResult) -> Result<()> {
    match result {
        UserConsentVerificationResult::Verified => {
            log::info!("Hello verify_with_window: verified");
            Ok(())
        }
        UserConsentVerificationResult::Canceled => Err(VaultError::BadInput(
            "Hello confirmation was canceled by the user".into(),
        )),
        UserConsentVerificationResult::DeviceNotPresent => Err(VaultError::System(
            "Windows Hello device is not present".into(),
        )),
        UserConsentVerificationResult::NotConfiguredForUser => Err(VaultError::System(
            "Windows Hello is not configured for this user".into(),
        )),
        UserConsentVerificationResult::DisabledByPolicy => Err(VaultError::System(
            "Windows Hello is disabled by policy".into(),
        )),
        UserConsentVerificationResult::DeviceBusy => {
            Err(VaultError::System("Windows Hello device is busy".into()))
        }
        UserConsentVerificationResult::RetriesExhausted => Err(VaultError::System(
            "Windows Hello retries were exhausted".into(),
        )),
        other => Err(VaultError::System(format!(
            "Windows Hello verification returned {:?}",
            other
        ))),
    }
}

fn run_in_sta<F, R>(f: F) -> Result<R>
where
    F: FnOnce() -> Result<R> + Send + 'static,
    R: Send + 'static,
{
    let handle = std::thread::spawn(move || -> Result<R> {
        // SAFETY: Initializes COM for the newly spawned thread using the standard STA model. Safe to call as it does not operate on shared states.
        unsafe {
            use windows::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED};
            let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        }
        f()
    });
    handle
        .join()
        .map_err(|_| VaultError::System("Hello-thread panicked".into()))?
}

pub(crate) fn pump_wait<T>(op: &windows_future::IAsyncOperation<T>) -> windows::core::Result<T>
where
    T: windows::core::RuntimeType,
{
    loop {
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
