// Контролируемое копирование секретов в буфер обмена.
//
// Логика:
//  - устанавливаем формат CF_UNICODETEXT;
//  - дополнительно регистрируем формат "ExcludeClipboardContentFromMonitorProcessing"
//    как сигнал Windows Clipboard History / Cloud Clipboard НЕ сохранять копию;
//  - запускаем таймер на N секунд, по истечении — перезаписываем буфер
//    (только если содержимое не было заменено пользователем).
//
// Tauri 2.x имеет clipboard-manager plugin, мы используем его как основной
// канал записи; здесь — добавочные WinAPI-вызовы для CF_HTML/CF_PRIVATE.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use tauri::AppHandle;
use tauri_plugin_clipboard_manager::ClipboardExt;

use crate::error::{Result, VaultError};

/// Хранилище хеша последнего записанного нами значения. Plaintext НЕ хранится —
/// раньше мы держали Option<String> с самим секретом, что оставляло копию
/// в памяти процесса и противоречило нашей же zeroize-политике (MED-04).
/// Теперь сравниваем по SHA-256, а сам секрет существует только в момент записи.
#[derive(Default)]
pub struct ClipboardGuard {
    last_hash: Mutex<Option<[u8; 32]>>,
}

fn hash(s: &str) -> [u8; 32] {
    Sha256::digest(s.as_bytes()).into()
}

impl ClipboardGuard {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Записать секрет в буфер и поставить таймер на очистку через `seconds`.
    pub fn copy_with_autoclear(
        self: &Arc<Self>,
        app: AppHandle,
        secret: &str,
        seconds: u32,
    ) -> Result<()> {
        {
            let mut g = self.last_hash.lock();
            *g = Some(hash(secret));
        }

        app.clipboard()
            .write_text(secret.to_string())
            .map_err(|e| VaultError::System(format!("clipboard.write_text: {e}")))?;

        #[cfg(windows)]
        let _ = mark_exclude_from_history();

        if seconds == 0 {
            return Ok(());
        }

        let guard = self.clone();
        let app_clone = app.clone();
        let expected_hash = hash(secret);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(seconds as u64));
            guard.maybe_clear(&app_clone, &expected_hash);
        });

        Ok(())
    }

    /// Очистить буфер, ТОЛЬКО если в нём всё ещё то, что мы туда положили.
    /// Сравнение по hash — plaintext в этой структуре не хранится.
    pub fn maybe_clear(&self, app: &AppHandle, expected_hash: &[u8; 32]) {
        let mut cur = match app.clipboard().read_text() {
            Ok(t) => t,
            Err(_) => return,
        };
        let cur_hash = hash(&cur);
        // MED-13: zeroize the plaintext read-back to avoid leaving secrets in heap.
        // SAFETY: Safely accessing the underlying vector of the string to overwrite memory. String is dropped immediately after, so no invalid UTF-8 is observed.
        zeroize::Zeroize::zeroize(unsafe { cur.as_mut_vec() });
        // Constant-time-сравнение не нужно (хеши не секретные), но
        // защищаемся от случайной утечки plaintext через дебаг.
        if &cur_hash == expected_hash {
            let _ = app.clipboard().clear();
        }
        let mut g = self.last_hash.lock();
        if g.as_ref() == Some(expected_hash) {
            *g = None;
        }
    }

    /// Принудительная очистка (вызывается из UI / при автолоке).
    pub fn force_clear(&self, app: &AppHandle) {
        let _ = app.clipboard().clear();
        let mut g = self.last_hash.lock();
        *g = None;
    }
}

/// Регистрирует формат "ExcludeClipboardContentFromMonitorProcessing"
/// и кладёт пустой блок — это вежливая просьба к Cloud Clipboard
/// и Clipboard History не сохранять последнее значение.
#[cfg(windows)]
fn mark_exclude_from_history() -> Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{GetLastError, HANDLE};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
    };
    use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};

    // Эту магическую строку Windows распознаёт и не помещает контент в History.
    let fmt_name: Vec<u16> = "ExcludeClipboardContentFromMonitorProcessing\0"
        .encode_utf16()
        .collect();

    // SAFETY: Interacting with Windows clipboard APIs. Pointers to fmt_name are valid. GlobalAlloc and GlobalLock allocate and lock a 1-byte sentinel safely.
    unsafe {
        let cf = RegisterClipboardFormatW(PCWSTR(fmt_name.as_ptr()));
        if cf == 0 {
            return Err(VaultError::System(format!(
                "RegisterClipboardFormatW: {:?}",
                GetLastError()
            )));
        }
        if OpenClipboard(None).is_err() {
            return Err(VaultError::System("OpenClipboard failed".into()));
        }
        // НЕ вызываем EmptyClipboard здесь — он бы стёр текст, который только что записали.

        // Кладём 1-байтовый sentinel.
        let h = GlobalAlloc(GMEM_MOVEABLE, 1)
            .map_err(|e| VaultError::System(format!("GlobalAlloc: {e}")))?;
        let p = GlobalLock(h);
        if !p.is_null() {
            *(p as *mut u8) = 0;
            let _ = GlobalUnlock(h);
        }
        let _ = SetClipboardData(cf as u32, Some(HANDLE(h.0 as *mut _)));
        let _ = CloseClipboard();
    }
    Ok(())
}
