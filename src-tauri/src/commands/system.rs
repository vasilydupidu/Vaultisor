// Системные команды.

use serde::Serialize;
use tauri::State;

use crate::error::{Result, VaultError};
use crate::state::AppState;

#[derive(Debug, Clone, Serialize)]
pub struct SystemCheck {
    pub dpapi_available: bool,
    pub windows_hello_available: bool,
    pub tpm_available: bool,
    pub windows_version: String,
}

#[tauri::command]
pub fn system_check() -> SystemCheck {
    let c = crate::windows_api::capabilities();
    SystemCheck {
        dpapi_available: c.dpapi_available,
        windows_hello_available: c.windows_hello_available,
        tpm_available: c.tpm_available,
        windows_version: c.windows_version,
    }
}

/// Проверка существования инициализированного хранилища на диске.
/// Используется фронтом, чтобы решить — показывать онбординг или экран разблокировки.
#[tauri::command]
pub fn vault_exists(state: State<'_, AppState>) -> Result<bool> {
    vault_exists_at(&state)
}

/// Хранилище есть, если на диске лежит ХОТЬ ОДИН из трёх его файлов.
///
/// Создание и импорт отказываются работать при любом из них, поэтому ответ
/// «нет» при остатках файлов отправил бы пользователя на онбординг, где оба
/// действия упрутся в отказ. С остатками показывается экран входа, а вход
/// объясняет, что именно не так (см. `require_complete_vault`).
pub(crate) fn vault_exists_at(state: &AppState) -> Result<bool> {
    let present = vault_files_present(state);
    log::info!(
        "vault_exists: meta={}, records={}, web={}",
        present.meta,
        present.records,
        present.web,
    );
    Ok(present.meta || present.records || present.web)
}

struct VaultFiles {
    meta: bool,
    records: bool,
    web: bool,
}

fn vault_files_present(state: &AppState) -> VaultFiles {
    VaultFiles {
        meta: state.meta_path().exists(),
        records: state.records_path().exists(),
        web: state.web_path().exists(),
    }
}

/// Вход в неполное хранилище должен объяснять, что делать, а не падать
/// безликой ошибкой (а `open_meta` ещё и создал бы пустые метаданные на месте
/// пропавших). Нет файла метаданных — по долям B и C восстановить нельзя: в
/// них лежит конверт мастер-ключа, и остаётся только импорт резервной копии.
pub(crate) fn require_complete_vault(state: &AppState) -> Result<()> {
    let present = vault_files_present(state);
    if present.meta && present.records && present.web {
        return Ok(());
    }
    if !present.meta && !present.records && !present.web {
        return Err(VaultError::NotInitialized);
    }
    let missing: Vec<&str> = [
        (present.meta, "vault.meta.db"),
        (present.records, "vault.records.db"),
        (present.web, "vault.web.db"),
    ]
    .iter()
    .filter(|(exists, _)| !exists)
    .map(|(_, name)| *name)
    .collect();
    let advice = if present.meta {
        "Переместите оставшиеся файлы vault.*.db из папки данных в другое место и \
         импортируйте резервную копию на чистую установку."
    } else {
        "Восстановление по частям B и C здесь невозможно: данные для него хранятся в \
         vault.meta.db. Переместите оставшиеся файлы vault.*.db из папки данных в другое \
         место и импортируйте резервную копию на чистую установку."
    };
    Err(VaultError::BadInput(format!(
        "Хранилище неполное: нет файлов {}. {advice}",
        missing.join(", ")
    )))
}

/// Heartbeat сессии из фронтенда для корректного авто-лока.
///
/// `active` = была ли активность пользователя В ОКНЕ приложения с прошлого
/// вызова (движение мыши / клавиатура, включая набор в формах — где обычных
/// команд нет). Если активна — продлеваем сессию (touch). Затем проверяем
/// autolock (залочит при превышении простоя) и возвращаем, разблокирована ли
/// сессия ещё. Фронт при `false` уходит на lock-экран.
///
/// Это чинит рассинхрон: раньше фронт мерил СИСТЕМНЫЙ простой (ввод по всему
/// ПК), а бэкенд — активность в приложении; работа в других окнах приводила к
/// тому, что бэкенд лочил сессию, а UI оставался «разблокированным».
#[tauri::command]
pub fn session_heartbeat(state: State<AppState>, active: bool) -> Result<bool> {
    if state.check_autolock() {
        return Ok(false);
    }
    if active {
        state.touch();
    }
    Ok(state.session.lock().is_unlocked())
}

/// Открыть системный мастер настройки ключа безопасности Windows.
///
/// Задать ПИН на самом токене можно только командой CTAP2 `authenticatorClientPIN`,
/// а она требует прямого доступа к USB-HID устройству с usage page 0xF1D0.
/// Windows намеренно закрывает такой доступ непривилегированным процессам, чтобы
/// вредоносный код не мог молча перенастроить ключ. Тащить в менеджер секретов
/// собственный CTAP2-стек и требовать прав администратора ради этого нельзя —
/// поэтому отдаём пользователя в штатный мастер самой Windows.
///
/// Аргументов нет и быть не должно: URI зашит здесь, webview не получает
/// возможности открыть произвольный ms-settings или внешнюю ссылку.
#[tauri::command]
pub fn open_security_key_settings() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use windows::core::w;
        use windows::Win32::UI::Shell::ShellExecuteW;
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

        // SAFETY: все аргументы — статические строки либо нули; HWND(0)
        // означает «без родительского окна».
        let result = unsafe {
            ShellExecuteW(
                None,
                w!("open"),
                w!("ms-settings:signinoptions-launchsecuritykeyenrollment"),
                None,
                None,
                SW_SHOWNORMAL,
            )
        };
        // ShellExecuteW возвращает значение > 32 при успехе — это наследие
        // 16-битного API, а не дескриптор.
        if result.0 as isize <= 32 {
            return Err(crate::error::VaultError::System(format!(
                "ShellExecuteW(ms-settings) failed: {}",
                result.0 as isize
            )));
        }
        log::info!("open_security_key_settings: launched Windows security key enrollment");
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err(crate::error::VaultError::System(
            "Настройка ключа безопасности доступна только в Windows".into(),
        ))
    }
}
