// Команды CRUD для записей.
//
// Команды, которые трогают диск, асинхронные и выполняют работу в
// blocking-пуле: синхронная команда исполняется в главном потоке Tauri и
// замораживает интерфейс на время запроса (список с проверкой паролей, запись
// транзакции с fsync).

use serde::Deserialize;
use tauri::State;

use crate::error::{Result, VaultError};
use crate::state::{AppState, SessionState};
use crate::storage::records::{
    create_record, delete_record, get_record, list_records, reorder_records, reveal_field,
    update_record, Record, RecordInput,
};

/// Какая из двух баз имеется в виду. Значение приходит из webview, поэтому
/// незнакомое отвергается: молчаливое «иначе — records» направило бы запись
/// не в ту базу.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DbType {
    Records,
    Web,
}

impl DbType {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "records" => Ok(DbType::Records),
            "web" => Ok(DbType::Web),
            _ => Err(VaultError::BadInput("Неизвестный тип базы".into())),
        }
    }

    pub(crate) fn pick<'a, T>(self, records: &'a T, web: &'a T) -> &'a T {
        match self {
            DbType::Records => records,
            DbType::Web => web,
        }
    }
}

fn with_unlocked_db<F, R>(state: &AppState, db_type: &str, f: F) -> Result<R>
where
    F: FnOnce(
        &crate::crypto::master::MasterKey,
        &crate::storage::records_db::RecordsDb,
    ) -> Result<R>,
{
    let db_type = DbType::parse(db_type)?;
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    state.touch();
    let s = state.session.lock();
    match &*s {
        SessionState::Locked => Err(VaultError::Locked),
        SessionState::Unlocked {
            master_key,
            records_db,
            web_db,
            ..
        } => f(master_key, db_type.pick(records_db, web_db)),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListInput {
    pub query: Option<String>,
    /// None/"all" — все; "work"/"personal" — фильтр.
    pub category: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub db_type: String,
}

#[tauri::command]
pub async fn record_list(input: ListInput, state: State<'_, AppState>) -> Result<Vec<Record>> {
    let state = state.inner().clone();
    crate::blocking::run(move || list_entries(&state, input)).await
}

pub(crate) fn list_entries(state: &AppState, input: ListInput) -> Result<Vec<Record>> {
    let limit = input.limit.unwrap_or(100).clamp(1, 500);
    let offset = input.offset.unwrap_or(0).max(0);
    let enable_health = state
        .open_meta()
        .and_then(|m| m.get_enable_health_check())
        .unwrap_or(true);
    with_unlocked_db(state, &input.db_type, |mk, db| {
        list_records(
            db,
            Some(mk),
            enable_health,
            input.query.as_deref(),
            input.category.as_deref(),
            limit,
            offset,
        )
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReorderInput {
    pub ordered_ids: Vec<String>,
    pub db_type: String,
}

#[tauri::command]
pub async fn record_reorder(input: ReorderInput, state: State<'_, AppState>) -> Result<()> {
    let state = state.inner().clone();
    crate::blocking::run(move || reorder_entries(&state, input)).await
}

pub(crate) fn reorder_entries(state: &AppState, input: ReorderInput) -> Result<()> {
    with_unlocked_db(state, &input.db_type, |_mk, db| {
        reorder_records(db, &input.ordered_ids)
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetInput {
    pub id: String,
    pub db_type: String,
}

#[tauri::command]
pub async fn record_get(input: GetInput, state: State<'_, AppState>) -> Result<Record> {
    let state = state.inner().clone();
    crate::blocking::run(move || get_entry(&state, input)).await
}

pub(crate) fn get_entry(state: &AppState, input: GetInput) -> Result<Record> {
    with_unlocked_db(state, &input.db_type, |_mk, db| get_record(db, &input.id))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateInput {
    pub data: RecordInput,
    pub db_type: String,
    /// Один на намерение пользователя; повтор с ним не создаёт дубликат.
    pub request_id: String,
}

#[tauri::command]
pub async fn record_create(input: CreateInput, state: State<'_, AppState>) -> Result<String> {
    let state = state.inner().clone();
    crate::blocking::run(move || create_entry(&state, input)).await
}

pub(crate) fn create_entry(state: &AppState, input: CreateInput) -> Result<String> {
    let request_id = crate::commands::request::parse(&input.request_id)?;
    with_unlocked_db(state, &input.db_type, |mk, db| {
        create_record(db, mk, &input.data, Some(&request_id))
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateInput {
    pub id: String,
    pub data: RecordInput,
    pub db_type: String,
}

#[tauri::command]
pub async fn record_update(input: UpdateInput, state: State<'_, AppState>) -> Result<()> {
    update_entry(&state, input).await
}

pub(crate) async fn update_entry(state: &AppState, input: UpdateInput) -> Result<()> {
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    crate::commands::auth_gate::require_copy_view_auth(state).await?;
    let enable_history = state.open_meta()?.get_enable_password_history()?;
    let state = state.clone();
    crate::blocking::run(move || {
        with_unlocked_db(&state, &input.db_type, |mk, db| {
            update_record(db, mk, &input.id, &input.data, enable_history)
        })
    })
    .await
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteInput {
    pub id: String,
    pub db_type: String,
}

#[tauri::command]
pub async fn record_delete(input: DeleteInput, state: State<'_, AppState>) -> Result<()> {
    let state = state.inner().clone();
    crate::blocking::run(move || delete_entry(&state, input)).await
}

pub(crate) fn delete_entry(state: &AppState, input: DeleteInput) -> Result<()> {
    with_unlocked_db(state, &input.db_type, |_mk, db| {
        delete_record(db, &input.id)
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevealInput {
    pub record_id: String,
    pub field_id: String,
    pub db_type: String,
}

#[tauri::command]
pub async fn record_reveal_field(input: RevealInput, state: State<'_, AppState>) -> Result<String> {
    let db_type = DbType::parse(&input.db_type)?;
    // Просмотр секрета на экране — под тем же гейтом
    // «копирование/просмотр» (require_auth_for_copy) с окном доверия 60с.
    // Hello (async) вызываем ДО захвата мьютекса сессии.
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    state.touch();
    crate::commands::auth_gate::require_copy_view_auth(&state).await?;

    // reveal под session-lock; внутри нет await.
    let s = state.session.lock();
    match &*s {
        SessionState::Locked => Err(VaultError::Locked),
        SessionState::Unlocked {
            master_key,
            records_db,
            web_db,
            ..
        } => {
            let db = db_type.pick(records_db, web_db);
            let value = reveal_field(db, master_key, &input.record_id, &input.field_id)?;
            // SECURITY: IPC boundary — Zeroizing<String> → plain String (Tauri
            // сериализует результат в JSON). Промежуточная Zeroizing зачистится.
            Ok((*value).clone())
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchDeleteInput {
    pub db_type: String,
    pub record_ids: Vec<String>,
}

#[tauri::command]
pub async fn records_batch_delete(
    input: BatchDeleteInput,
    state: State<'_, AppState>,
) -> Result<usize> {
    let state = state.inner().clone();
    crate::blocking::run(move || batch_delete_entries(&state, input)).await
}

pub(crate) fn batch_delete_entries(state: &AppState, input: BatchDeleteInput) -> Result<usize> {
    // Одной транзакцией: сбой посередине не оставляет удалённой часть
    // выбранного при ответе «успешно».
    with_unlocked_db(state, &input.db_type, |_master, db| {
        crate::storage::records::delete_records(db, &input.record_ids)
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryInput {
    pub record_id: String,
    pub db_type: String,
}

#[tauri::command]
pub async fn record_get_password_history(
    input: HistoryInput,
    state: State<'_, AppState>,
) -> Result<Vec<crate::storage::records::PasswordHistoryEntry>> {
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    crate::commands::auth_gate::require_copy_view_auth(&state).await?;
    with_unlocked_db(&state, &input.db_type, |_mk, db| {
        crate::storage::records::get_password_history(db, &input.record_id)
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntryInput {
    pub record_id: String,
    pub history_id: String,
    pub db_type: String,
}

/// Копирование архивного пароля без выдачи значения в webview.
#[tauri::command]
pub async fn record_copy_password_history(
    input: HistoryEntryInput,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<()> {
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    state.touch();
    crate::commands::auth_gate::require_copy_view_auth(&state).await?;
    let value = with_unlocked_db(&state, &input.db_type, |mk, db| {
        crate::storage::records::reveal_password_history_value(
            db,
            mk,
            &input.record_id,
            &input.history_id,
        )
    })?;
    let clear_after = state.settings.lock().clipboard_clear_seconds;
    crate::commands::clipboard::copy_secret_text(&app, &value, clear_after)
}

/// Восстановление значения из истории целиком на backend —
/// раньше фронтенд собирал record_update из полученного plaintext.
#[tauri::command]
pub async fn record_restore_password_history(
    input: HistoryEntryInput,
    state: State<'_, AppState>,
) -> Result<()> {
    restore_history_entry(&state, input).await
}

pub(crate) async fn restore_history_entry(
    state: &AppState,
    input: HistoryEntryInput,
) -> Result<()> {
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    crate::commands::auth_gate::require_copy_view_auth(state).await?;
    let enable_history = state.open_meta()?.get_enable_password_history()?;
    let state = state.clone();
    crate::blocking::run(move || {
        with_unlocked_db(&state, &input.db_type, |mk, db| {
            crate::storage::records::restore_password_history(
                db,
                mk,
                &input.record_id,
                &input.history_id,
                enable_history,
            )
        })
    })
    .await
}

#[tauri::command]
pub async fn record_clear_password_history(
    input: HistoryInput,
    state: State<'_, AppState>,
) -> Result<()> {
    let state = state.inner().clone();
    crate::blocking::run(move || clear_history(&state, input)).await
}

pub(crate) fn clear_history(state: &AppState, input: HistoryInput) -> Result<()> {
    with_unlocked_db(state, &input.db_type, |_mk, db| {
        crate::storage::records::clear_password_history(db, &input.record_id)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_db_type_is_rejected_not_routed_to_records() {
        assert_eq!(DbType::parse("records").unwrap(), DbType::Records);
        assert_eq!(DbType::parse("web").unwrap(), DbType::Web);
        for bad in ["", "Web", "WEB", "other", "records ", "web\0"] {
            assert!(
                matches!(DbType::parse(bad), Err(VaultError::BadInput(_))),
                "{bad:?} должен отвергаться"
            );
        }
    }

    #[test]
    fn input_structs_reject_unknown_keys() {
        use serde_json::json;
        let extra = json!({"db_type": "records", "extra": 1});
        assert!(serde_json::from_value::<ListInput>(extra.clone()).is_err());
        assert!(serde_json::from_value::<ListInput>(json!({"db_type": "records"})).is_ok());
        assert!(
            serde_json::from_value::<GetInput>(json!({"id": "a", "db_type": "web", "x": 1}))
                .is_err()
        );
        assert!(serde_json::from_value::<DeleteInput>(
            json!({"id": "a", "db_type": "web", "x": 1})
        )
        .is_err());
        assert!(serde_json::from_value::<ReorderInput>(
            json!({"ordered_ids": [], "db_type": "web", "x": 1})
        )
        .is_err());
        assert!(serde_json::from_value::<BatchDeleteInput>(
            json!({"record_ids": [], "db_type": "web", "x": 1})
        )
        .is_err());
        assert!(serde_json::from_value::<RevealInput>(
            json!({"record_id": "a", "field_id": "b", "db_type": "web", "x": 1})
        )
        .is_err());
        assert!(serde_json::from_value::<HistoryInput>(
            json!({"record_id": "a", "db_type": "web", "x": 1})
        )
        .is_err());
        assert!(serde_json::from_value::<HistoryEntryInput>(
            json!({"record_id": "a", "history_id": "b", "db_type": "web", "x": 1})
        )
        .is_err());
        let record = json!({"name": "n", "fields": []});
        assert!(serde_json::from_value::<CreateInput>(
            json!({"data": record, "db_type": "web", "request_id": "r"})
        )
        .is_ok());
        assert!(serde_json::from_value::<CreateInput>(
            json!({"data": record, "db_type": "web", "request_id": "r", "x": 1})
        )
        .is_err());
        assert!(serde_json::from_value::<UpdateInput>(
            json!({"id": "a", "data": record, "db_type": "web", "x": 1})
        )
        .is_err());
        // Вложенные структуры записи тоже закрыты для лишних ключей.
        assert!(
            serde_json::from_value::<RecordInput>(json!({"name": "n", "fields": [], "x": 1}))
                .is_err()
        );
        assert!(serde_json::from_value::<RecordInput>(json!({
            "name": "n",
            "fields": [{"field_type": "secret", "label": "l", "is_secret": true,
                        "sort_order": 0, "value": "v", "x": 1}]
        }))
        .is_err());
    }
}
