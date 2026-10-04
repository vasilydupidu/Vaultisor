// Контролируемое копирование секретов в буфер обмена.
//
// AUDIT 3.1.1 (HIGH): раньше текст писался плагином clipboard-manager, буфер
// закрывался, Windows рассылала WM_CLIPBOARDUPDATE — и только ПОСЛЕ этого
// вторым `OpenClipboard` добавлялся формат-исключение. Служба истории буфера
// (cbdhsvc) и облачная синхронизация успевали прочитать секрет по первому
// уведомлению, поэтому заявленная защита от Win+V фактически не работала.
//
// Теперь запись выполняется одной атомарной clipboard-сессией:
//   OpenClipboard(hwnd) → EmptyClipboard → CF_UNICODETEXT → три служебных
//   формата-исключения → CloseClipboard
// и только при закрытии буфера Windows рассылает уведомление — к этому моменту
// маркеры исключения уже на месте.
//
// Форматы-исключения (документированы Microsoft для Windows 10 1809+):
//   ExcludeClipboardContentFromMonitorProcessing — не обрабатывать вообще;
//   CanIncludeInClipboardHistory = 0             — не сохранять в Win+V;
//   CanUploadToCloudClipboard   = 0              — не синхронизировать в облако.
//
// Очистка по таймеру больше НЕ читает содержимое буфера обратно (это затягивало
// plaintext в процесс). Вместо этого запоминается GetClipboardSequenceNumber():
// если пользователь скопировал что-то своё, номер изменится и мы не тронем его
// данные; если номер тот же — в буфере всё ещё наш секрет.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tauri::AppHandle;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL, HWND};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard,
    RegisterClipboardFormatW, SetClipboardData,
};
use windows::Win32::System::Memory::{
    GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE, GMEM_ZEROINIT,
};
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

/// CF_UNICODETEXT из winuser.h. Константу объявляем сами, чтобы не тянуть
/// feature `Win32_System_Ole` ради одного числа.
const CF_UNICODETEXT: u32 = 13;

/// Сколько раз пробуем открыть буфер, если его держит другое приложение.
const OPEN_ATTEMPTS: usize = 10;
const OPEN_RETRY_DELAY: Duration = Duration::from_millis(20);

/// Сохраняем не хеш секрета (для коротких значений это словарный оракул в
/// дампе памяти), а номер версии буфера обмена — он не является секретом.
#[derive(Default)]
pub struct ClipboardGuard {
    last_sequence: Mutex<Option<u32>>,
}

impl ClipboardGuard {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Записать секрет в буфер и поставить таймер на очистку через `seconds`.
    /// `seconds == 0` — не очищать по таймеру (но очистка при блокировке
    /// хранилища всё равно сработает).
    pub fn copy_with_autoclear(
        self: &Arc<Self>,
        app: AppHandle,
        secret: &str,
        seconds: u32,
    ) -> Result<()> {
        let hwnd = main_window_handle(&app)?;
        let sequence = write_protected_text(hwnd, secret)?;
        {
            let mut last = self.last_sequence.lock();
            *last = Some(sequence);
        }

        if seconds == 0 {
            return Ok(());
        }

        let guard = self.clone();
        let app_clone = app.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(seconds as u64));
            guard.clear_if_unchanged(&app_clone, sequence);
        });

        Ok(())
    }

    /// Очистить буфер, только если в нём всё ещё наш секрет.
    pub fn clear_if_unchanged(&self, app: &AppHandle, expected_sequence: u32) {
        let hwnd = match main_window_handle(app) {
            Ok(hwnd) => hwnd,
            Err(_) => return,
        };
        match empty_clipboard_if_unchanged(hwnd, expected_sequence) {
            Ok(cleared) => {
                let mut last = self.last_sequence.lock();
                if *last == Some(expected_sequence) && cleared {
                    *last = None;
                }
            }
            Err(error) => {
                log::warn!("clipboard auto-clear failed: {error}");
            }
        }
    }

    /// Очистка при блокировке хранилища: трогаем буфер только если там лежит
    /// именно наш секрет, чтобы не стереть данные пользователя.
    pub fn clear_on_lock(&self, app: &AppHandle) {
        let expected = *self.last_sequence.lock();
        if let Some(sequence) = expected {
            self.clear_if_unchanged(app, sequence);
        }
    }

    /// Безусловная очистка по явной команде пользователя.
    pub fn force_clear(&self, app: &AppHandle) -> Result<()> {
        let hwnd = main_window_handle(app)?;
        let _session = ClipboardSession::open(hwnd)?;
        // SAFETY: the clipboard is open for this thread until `_session` drops.
        unsafe { EmptyClipboard() }
            .map_err(|e| VaultError::System(format!("EmptyClipboard: {e}")))?;
        let mut last = self.last_sequence.lock();
        *last = None;
        Ok(())
    }
}

/// HWND главного окна без побочных эффектов фокуса: `EmptyClipboard` с
/// владельцем NULL переводит владельца в NULL, после чего `SetClipboardData`
/// начинает возвращать ошибку. Поэтому владелец обязателен.
fn main_window_handle(app: &AppHandle) -> Result<HWND> {
    use tauri::Manager;
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| VaultError::System("Main window is not available".into()))?;
    let handle = window
        .hwnd()
        .map_err(|e| VaultError::System(format!("Main window HWND: {e}")))?;
    Ok(HWND(handle.0 as *mut _))
}

/// RAII-обёртка: буфер обмена обязан быть закрыт на любом пути выхода, иначе
/// он останется заблокированным для всей системы.
struct ClipboardSession;

impl ClipboardSession {
    fn open(hwnd: HWND) -> Result<Self> {
        let mut last_error = None;
        for attempt in 0..OPEN_ATTEMPTS {
            // SAFETY: `hwnd` belongs to this process and stays valid; the API
            // either takes ownership of the clipboard or reports failure.
            match unsafe { OpenClipboard(Some(hwnd)) } {
                Ok(()) => return Ok(Self),
                Err(error) => {
                    last_error = Some(error);
                    if attempt + 1 < OPEN_ATTEMPTS {
                        std::thread::sleep(OPEN_RETRY_DELAY);
                    }
                }
            }
        }
        Err(VaultError::System(format!(
            "OpenClipboard failed after {OPEN_ATTEMPTS} attempts: {}",
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown".into())
        )))
    }
}

impl Drop for ClipboardSession {
    fn drop(&mut self) {
        // SAFETY: this thread owns the clipboard for the lifetime of the guard.
        unsafe {
            let _ = CloseClipboard();
        }
    }
}

/// Выделить moveable-блок и скопировать в него байты.
/// При любой ошибке блок освобождается — утечки HGLOBAL нет.
///
/// # Safety
/// Возвращённый HANDLE передаётся `SetClipboardData`; при успехе владение
/// переходит системе, при ошибке вызывающий обязан освободить блок.
unsafe fn alloc_global(bytes: &[u8]) -> Result<HANDLE> {
    let handle = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, bytes.len())
        .map_err(|e| VaultError::System(format!("GlobalAlloc: {e}")))?;
    let pointer = GlobalLock(handle);
    if pointer.is_null() {
        let _ = GlobalFree(Some(handle));
        return Err(VaultError::System("GlobalLock returned null".into()));
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer as *mut u8, bytes.len());
    let _ = GlobalUnlock(handle);
    Ok(HANDLE(handle.0 as *mut _))
}

/// Положить в открытый буфер формат с заданным содержимым.
///
/// # Safety
/// Вызывать только при открытом буфере обмена.
unsafe fn put_format(format_name: &str, payload: &[u8]) -> Result<()> {
    let wide: Vec<u16> = format_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let format = RegisterClipboardFormatW(PCWSTR(wide.as_ptr()));
    if format == 0 {
        return Err(VaultError::System(format!(
            "RegisterClipboardFormatW({format_name}) failed"
        )));
    }
    let handle = alloc_global(payload)?;
    if let Err(error) = SetClipboardData(format, Some(handle)) {
        let _ = GlobalFree(Some(HGLOBAL(handle.0)));
        return Err(VaultError::System(format!(
            "SetClipboardData({format_name}): {error}"
        )));
    }
    Ok(())
}

/// Записать секрет одной сессией вместе со всеми маркерами исключения.
/// Возвращает номер версии буфера обмена после записи.
fn write_protected_text(hwnd: HWND, secret: &str) -> Result<u32> {
    // UTF-16 с завершающим нулём; буфер зачищается при выходе из функции.
    let wide: Zeroizing<Vec<u16>> =
        Zeroizing::new(secret.encode_utf16().chain(std::iter::once(0)).collect());
    let mut bytes: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(wide.len() * 2));
    for unit in wide.iter() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }

    let session = ClipboardSession::open(hwnd)?;
    // SAFETY: the clipboard is open and owned by `hwnd` until `session` drops.
    unsafe {
        EmptyClipboard().map_err(|e| VaultError::System(format!("EmptyClipboard: {e}")))?;

        let text = alloc_global(&bytes)?;
        if let Err(error) = SetClipboardData(CF_UNICODETEXT, Some(text)) {
            let _ = GlobalFree(Some(HGLOBAL(text.0)));
            return Err(VaultError::System(format!(
                "SetClipboardData(CF_UNICODETEXT): {error}"
            )));
        }

        // Маркеры исключения обязаны попасть в ту же сессию, что и текст.
        put_format("ExcludeClipboardContentFromMonitorProcessing", &[0u8])?;
        put_format("CanIncludeInClipboardHistory", &0u32.to_le_bytes())?;
        put_format("CanUploadToCloudClipboard", &0u32.to_le_bytes())?;
    }
    drop(session);

    // SAFETY: simple counter read, no pointers involved.
    Ok(unsafe { GetClipboardSequenceNumber() })
}

/// Очистить буфер, если его версия не изменилась с момента нашей записи.
/// Возвращает true, если очистка выполнена.
fn empty_clipboard_if_unchanged(hwnd: HWND, expected_sequence: u32) -> Result<bool> {
    // SAFETY: simple counter read, no pointers involved.
    if unsafe { GetClipboardSequenceNumber() } != expected_sequence {
        return Ok(false);
    }
    let _session = ClipboardSession::open(hwnd)?;
    // Повторная проверка под открытым буфером закрывает гонку между чтением
    // счётчика и захватом буфера.
    // SAFETY: the clipboard is open for this thread until `_session` drops.
    unsafe {
        if GetClipboardSequenceNumber() != expected_sequence {
            return Ok(false);
        }
        EmptyClipboard().map_err(|e| VaultError::System(format!("EmptyClipboard: {e}")))?;
    }
    Ok(true)
}
