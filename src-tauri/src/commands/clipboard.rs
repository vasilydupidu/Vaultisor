// Команды буфера обмена с авто-очисткой.

use serde::Deserialize;
use tauri::{AppHandle, State};

use crate::error::{Result, VaultError};
use crate::state::{AppState, SessionState};
use crate::storage::records::reveal_field;

use {crate::windows_api::clipboard::ClipboardGuard, once_cell::sync::Lazy, std::sync::Arc};

static GUARD: Lazy<Arc<ClipboardGuard>> = Lazy::new(ClipboardGuard::new);

#[derive(Debug, Deserialize)]
pub struct ClipboardCopyInput {
    pub record_id: String,
    pub field_id: String,
    /// Опциональное переопределение времени автоочистки (сек).
    /// 0 — не очищать. Если None — берём из настроек.
    pub clear_after_seconds: Option<u32>,
    pub db_type: String,
}

#[tauri::command]
pub async fn clipboard_copy_secret(
    input: ClipboardCopyInput,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<()> {
    // Авто-блокировка по простою проверяется и здесь, а не только в
    // record-CRUD — иначе простаивающая сессия могла бы копировать секрет.
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    state.touch();

    // Единый гейт «копирование/просмотр» с окном доверия 60с.
    // Проверку делаем до захвата мьютекса сессии — Hello async и показывает prompt.
    crate::commands::auth_gate::require_copy_view_auth(&state).await?;

    // reveal под мьютексом сессии; сразу отпускаем перед clipboard-операциями.
    let value = {
        let s = state.session.lock();
        let (master, db) = match &*s {
            SessionState::Locked => return Err(VaultError::Locked),
            SessionState::Unlocked {
                master_key,
                records_db,
                web_db,
                ..
            } => {
                let target_db = match input.db_type.as_str() {
                    "web" => web_db,
                    _ => records_db,
                };
                (master_key, target_db)
            }
        };
        reveal_field(db, master, &input.record_id, &input.field_id)?
    };

    let clear_after = input
        .clear_after_seconds
        .unwrap_or_else(|| state.settings.lock().clipboard_clear_seconds);

    GUARD.copy_with_autoclear(app, &value, clear_after)?;
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct ClipboardCopyTextInput {
    pub text: String,
    /// Время автоочистки (сек). 0 → применяется дефолт 30с (не «без очистки»),
    /// т.к. это ключевой материал восстановления.
    pub clear_after_seconds: u32,
}

/// Скопировать произвольный текст (Shamir-доля восстановления) с
/// авто-очисткой и исключением из истории буфера (Win+V) — как для секретов.
/// Раньше доля копировалась напрямую navigator.clipboard без очистки и висела
/// в буфере бесконечно (доля C + любая вторая = master-key).
#[tauri::command]
pub fn clipboard_copy_text(
    input: ClipboardCopyTextInput,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<()> {
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    if !state.session.lock().is_unlocked() {
        return Err(VaultError::Locked);
    }
    let clear_after = if input.clear_after_seconds == 0 {
        30
    } else {
        input.clear_after_seconds.min(120)
    };
    GUARD.copy_with_autoclear(app, &input.text, clear_after)?;
    Ok(())
}

#[tauri::command]
pub fn clipboard_clear(app: AppHandle, state: State<'_, AppState>) -> Result<()> {
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    // Очистка буфера — операция, доступная только при разблокированной сессии.
    // Запрет на anonymous-вызов закрывает LOW-04 из аудита.
    let session = state.session.lock();
    if !session.is_unlocked() {
        return Err(VaultError::Locked);
    }
    drop(session);
    GUARD.force_clear(&app)
}

/// Положить уже расшифрованное значение в буфер с авто-очисткой.
/// Используется командами, которые не выпускают plaintext в webview.
pub fn copy_secret_text(app: &AppHandle, value: &str, clear_after_seconds: u32) -> Result<()> {
    GUARD.copy_with_autoclear(app.clone(), value, clear_after_seconds)
}

/// Очистка буфера при блокировке хранилища. Трогает буфер только если в нём
/// всё ещё лежит секрет, который положили мы (см. ClipboardGuard).
pub fn clear_on_lock(app: &AppHandle) {
    GUARD.clear_on_lock(app);
}
