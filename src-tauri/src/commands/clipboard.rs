// Команды буфера обмена с авто-очисткой.

use serde::Deserialize;
use tauri::{AppHandle, State};

use crate::error::{Result, VaultError};
use crate::state::{AppState, SessionState};
use crate::storage::records::reveal_field;

use {crate::windows_api::clipboard::ClipboardGuard, once_cell::sync::Lazy, std::sync::Arc};

static GUARD: Lazy<Arc<ClipboardGuard>> = Lazy::new(ClipboardGuard::new);

/// Срок автоочистки здесь не передаётся: его задают только сохранённые
/// настройки. Иначе webview мог бы оставить секрет в буфере навсегда (0).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardCopyInput {
    pub record_id: String,
    pub field_id: String,
    pub db_type: String,
}

/// Самый длинный текст, который принимает `clipboard_copy_text`: доля
/// восстановления — десятки символов, больше этого не нужно никому.
pub(crate) const COPY_TEXT_MAX_CHARS: usize = 8192;

#[tauri::command]
pub async fn clipboard_copy_secret(
    input: ClipboardCopyInput,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<()> {
    let db_type = crate::commands::records::DbType::parse(&input.db_type)?;
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
            } => (master_key, db_type.pick(records_db, web_db)),
        };
        reveal_field(db, master, &input.record_id, &input.field_id)?
    };

    let clear_after = state.settings.lock().clipboard_clear_seconds;

    GUARD.copy_with_autoclear(app, &value, clear_after)?;
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
    check_copy_text(&input.text)?;
    // Это действие пользователя: оно продлевает сессию, как и копирование секрета.
    state.touch();
    let clear_after = if input.clear_after_seconds == 0 {
        30
    } else {
        input.clear_after_seconds.min(120)
    };
    GUARD.copy_with_autoclear(app, &input.text, clear_after)?;
    Ok(())
}

pub(crate) fn check_copy_text(text: &str) -> Result<()> {
    if text.chars().count() > COPY_TEXT_MAX_CHARS {
        return Err(VaultError::BadInput(format!(
            "Текст для копирования длиннее {COPY_TEXT_MAX_CHARS} символов"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_secret_input_has_no_client_controlled_clear_period() {
        use serde_json::json;
        let ok = json!({"record_id": "r", "field_id": "f", "db_type": "records"});
        assert!(serde_json::from_value::<ClipboardCopyInput>(ok).is_ok());
        let with_period = json!({
            "record_id": "r", "field_id": "f", "db_type": "records", "clear_after_seconds": 0
        });
        assert!(
            serde_json::from_value::<ClipboardCopyInput>(with_period).is_err(),
            "срок автоочистки из webview не принимается"
        );
    }

    #[test]
    fn copy_text_is_length_limited() {
        assert!(check_copy_text(&"a".repeat(COPY_TEXT_MAX_CHARS)).is_ok());
        assert!(matches!(
            check_copy_text(&"a".repeat(COPY_TEXT_MAX_CHARS + 1)),
            Err(VaultError::BadInput(_))
        ));
        // Считаются символы, а не байты.
        assert!(check_copy_text(&"ж".repeat(COPY_TEXT_MAX_CHARS)).is_ok());
    }

    #[test]
    fn copy_text_input_rejects_unknown_keys() {
        let value = serde_json::json!({"text": "t", "clear_after_seconds": 5, "x": 1});
        assert!(serde_json::from_value::<ClipboardCopyTextInput>(value).is_err());
    }
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
