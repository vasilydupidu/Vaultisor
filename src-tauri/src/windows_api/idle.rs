// Системный idle-time через GetLastInputInfo.
//
// Возвращает количество миллисекунд с момента последней активности
// клавиатуры/мыши на текущей сессии. На lock-screen / sleep
// значение перестаёт расти — это ожидаемое поведение, дополнительно
// мы обрабатываем session-events (см. session.rs).

use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

use crate::error::{Result, VaultError};

/// Секунды простоя (с округлением вниз).
pub fn idle_seconds() -> Result<u64> {
    // SAFETY: GetLastInputInfo takes a valid pointer to a LASTINPUTINFO structure initialized with its size. GetTickCount64 is a simple system call with no memory unsafety.
    unsafe {
        let mut lii = LASTINPUTINFO {
            cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
            dwTime: 0,
        };
        if !GetLastInputInfo(&mut lii).as_bool() {
            return Err(VaultError::System("GetLastInputInfo failed".into()));
        }
        // GetTickCount: количество мс с момента старта системы (32 бит, wraparound каждые 49 дней).
        // Для надёжности возьмём GetTickCount64.
        use windows::Win32::System::SystemInformation::GetTickCount64;
        let now = GetTickCount64();
        let last = lii.dwTime as u64;
        // Учитываем возможный wrap dwTime (32-битный счётчик):
        let delta_ms = if now < last { 0 } else { now - last };
        Ok(delta_ms / 1000)
    }
}
