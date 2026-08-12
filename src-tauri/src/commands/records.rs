// Команды CRUD для записей.

use serde::Deserialize;
use tauri::State;

use crate::error::{Result, VaultError};
use crate::state::{AppState, SessionState};
use crate::storage::records::{
    create_record, delete_record, get_record, list_records, reorder_records, reveal_field,
    update_record, Record, RecordInput,
};

fn with_unlocked_db<F, R>(state: &AppState, db_type: &str, f: F) -> Result<R>
where
    F: FnOnce(
        &crate::crypto::master::MasterKey,
        &crate::storage::records_db::RecordsDb,
    ) -> Result<R>,
{
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
        } => {
            let target_db = match db_type {
                "web" => web_db,
                _ => records_db,
            };
            // N-05: убеждаемся, что БД реально прошла v2-миграцию полей до любых
            // операций с полями (защита от будущего рефактора, открывшего БД
            // в обход migrate_field_encryption). В нормальном flow миграция
            // выполняется при открытии сессии, поэтому это дешёвая перестраховка.
            crate::storage::records::ensure_field_crypto_ready(target_db)?;
            f(master_key, target_db)
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ListInput {
    pub query: Option<String>,
    /// None/"all" — все; "work"/"personal" — фильтр.
    pub category: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub db_type: String,
}

#[tauri::command]
pub fn record_list(input: ListInput, state: State<'_, AppState>) -> Result<Vec<Record>> {
    let limit = input.limit.unwrap_or(100).clamp(1, 500);
    let offset = input.offset.unwrap_or(0).max(0);
    let enable_health = state.open_meta().and_then(|m| m.get_enable_health_check()).unwrap_or(true);
    with_unlocked_db(&state, &input.db_type, |mk, db| {
        list_records(db, Some(mk), enable_health, input.query.as_deref(), input.category.as_deref(), limit, offset)
    })
}

#[derive(Debug, Deserialize)]
pub struct ReorderInput {
    pub ordered_ids: Vec<String>,
    pub db_type: String,
}

#[tauri::command]
pub fn record_reorder(input: ReorderInput, state: State<'_, AppState>) -> Result<()> {
    with_unlocked_db(&state, &input.db_type, |_mk, db| {
        reorder_records(db, &input.ordered_ids)
    })
}

#[derive(Debug, Deserialize)]
pub struct GetInput {
    pub id: String,
    pub db_type: String,
}

#[tauri::command]
pub fn record_get(input: GetInput, state: State<'_, AppState>) -> Result<Record> {
    with_unlocked_db(&state, &input.db_type, |_mk, db| get_record(db, &input.id))
}

#[derive(Debug, Deserialize)]
pub struct CreateInput {
    pub data: RecordInput,
    pub db_type: String,
}

#[tauri::command]
pub fn record_create(input: CreateInput, state: State<'_, AppState>) -> Result<String> {
    with_unlocked_db(&state, &input.db_type, |mk, db| create_record(db, mk, &input.data))
}

#[derive(Debug, Deserialize)]
pub struct UpdateInput {
    pub id: String,
    pub data: RecordInput,
    pub db_type: String,
}

#[tauri::command]
pub fn record_update(input: UpdateInput, state: State<'_, AppState>) -> Result<()> {
    with_unlocked_db(&state, &input.db_type, |mk, db| {
        update_record(db, mk, &input.id, &input.data)
    })
}

#[derive(Debug, Deserialize)]
pub struct DeleteInput {
    pub id: String,
    pub db_type: String,
}

#[tauri::command]
pub fn record_delete(input: DeleteInput, state: State<'_, AppState>) -> Result<()> {
    with_unlocked_db(&state, &input.db_type, |_mk, db| delete_record(db, &input.id))
}

#[derive(Debug, Deserialize)]
pub struct RevealInput {
    pub record_id: String,
    pub field_id: String,
    pub db_type: String,
}

#[tauri::command]
pub async fn record_reveal_field(
    input: RevealInput,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<String> {
    // N-03 (вариант B): просмотр секрета на экране — под тем же гейтом
    // «копирование/просмотр» (require_auth_for_copy) с окном доверия 60с.
    // Hello (async) вызываем ДО захвата мьютекса сессии.
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    state.touch();
    crate::commands::auth_gate::require_copy_view_auth(&state, &app).await?;

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
            let db = match input.db_type.as_str() {
                "web" => web_db,
                _ => records_db,
            };
            crate::storage::records::ensure_field_crypto_ready(db)?;
            let value = reveal_field(db, master_key, &input.record_id, &input.field_id)?;
            // SECURITY: IPC boundary — Zeroizing<String> → plain String (Tauri
            // сериализует результат в JSON). Промежуточная Zeroizing зачистится.
            Ok((*value).clone())
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct BatchDeleteInput {
    pub db_type: String,
    pub record_ids: Vec<String>,
}

#[tauri::command]
pub async fn records_batch_delete(
    input: BatchDeleteInput,
    state: State<'_, AppState>,
) -> Result<usize> {
    with_unlocked_db(&state, &input.db_type, |_master, db| {
        let mut deleted_count = 0;
        for id in &input.record_ids {
            if delete_record(db, id).is_ok() {
                deleted_count += 1;
            }
        }
        Ok(deleted_count)
    })
}

#[derive(Debug, Deserialize)]
pub struct HistoryInput {
    pub record_id: String,
    pub db_type: String,
}

#[tauri::command]
pub fn record_get_password_history(
    input: HistoryInput,
    state: State<'_, AppState>,
) -> Result<Vec<crate::storage::records::PasswordHistoryEntry>> {
    with_unlocked_db(&state, &input.db_type, |mk, db| {
        crate::storage::records::get_password_history(db, mk, &input.record_id)
    })
}

#[tauri::command]
pub fn record_clear_password_history(
    input: HistoryInput,
    state: State<'_, AppState>,
) -> Result<()> {
    with_unlocked_db(&state, &input.db_type, |_mk, db| {
        crate::storage::records::clear_password_history(db, &input.record_id)
    })
}

