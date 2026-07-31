// Регистрация на Windows Session Notifications (lock/unlock/sleep/user-switch).
//
// Используется для мгновенной авто-блокировки Vaultisor, когда пользователь
// блокирует Windows (Win+L), уходит в sleep или переключает учётную запись.
//
// Технически: WTSRegisterSessionNotification + window proc для WM_WTSSESSION_CHANGE.
// Нам нужен HWND главного окна Tauri (передаётся при настройке).
//
// Tauri-окно само обрабатывает оконные сообщения, поэтому самый простой и
// надёжный путь — использовать tauri::Window::on_window_event и плагин
// tauri-plugin-os в комбинации с idle-проверкой. Полноценный регистратор
// WTS_NOTIFICATION тоже возможен через RegisterClassEx, но это
// усложнение, не оправданное для MVP.
//
// В этом модуле — функции-обёртки регистрации, готовые к использованию,
// если в будущем мы решим хукать WM_WTSSESSION_CHANGE напрямую.

use windows::Win32::Foundation::HWND;
use windows::Win32::System::RemoteDesktop::{
    WTSRegisterSessionNotification, WTSUnRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
};

use crate::error::{Result, VaultError};

/// Зарегистрировать окно на получение WM_WTSSESSION_CHANGE.
pub fn register(hwnd: HWND) -> Result<()> {
    // SAFETY: WTSRegisterSessionNotification relies on a valid HWND. The OS handles invalid HWNDs gracefully.
    unsafe {
        WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION)
            .map_err(|e| VaultError::System(format!("WTSRegister: {e}")))?;
    }
    Ok(())
}

/// Снять регистрацию.
pub fn unregister(hwnd: HWND) -> Result<()> {
    // SAFETY: WTSUnRegisterSessionNotification takes a HWND to unregister. Safe even if already unregistered or if HWND is invalid.
    unsafe {
        WTSUnRegisterSessionNotification(hwnd)
            .map_err(|e| VaultError::System(format!("WTSUnRegister: {e}")))?;
    }
    Ok(())
}
