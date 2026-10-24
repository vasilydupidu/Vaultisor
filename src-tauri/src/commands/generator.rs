// Команды экрана генератора секретов.
//
// Генерация значения живёт во фронтенде (`src/lib/generateSecret.ts`) — один
// генератор на весь продукт, он же используется при заполнении поля записи.
// Backend отвечает за хранение: шифрует значение, проверяет его на соответствие
// заявленному типу и чистит просроченные выдачи.

use serde::Deserialize;
use tauri::State;

use crate::error::{Result, VaultError};
use crate::state::{AppState, SessionState};
use crate::storage::records::generated::{
    self, GeneratedKind, GeneratedSecretMeta, MAX_LEN, PASSWORD_MIN_LEN, RETENTION_HOURS,
};

fn with_unlocked<F, R>(state: &AppState, f: F) -> Result<R>
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
    let session = state.session.lock();
    match &*session {
        SessionState::Locked => Err(VaultError::Locked),
        SessionState::Unlocked {
            master_key,
            records_db,
            ..
        } => f(master_key, records_db),
    }
}

/// Генератор выключен — значит его команд для фронтенда не существует.
///
/// Проверяется на каждом вызове, а не только при отрисовке экрана: настройка
/// защищена MAC метаданных, и обходить её через прямой вызов IPC незачем.
fn require_enabled(state: &AppState) -> Result<()> {
    if state.open_meta()?.get_enable_generator()? {
        Ok(())
    } else {
        Err(VaultError::BadInput(
            "Генератор выключен в настройках".into(),
        ))
    }
}

/// Границы и срок хранения — из backend, чтобы интерфейс не дублировал числа.
#[derive(Debug, serde::Serialize)]
pub struct GeneratorLimits {
    pub password_min_len: u32,
    pub max_len: u32,
    pub retention_hours: u32,
}

#[tauri::command]
pub fn generator_limits() -> GeneratorLimits {
    GeneratorLimits {
        password_min_len: PASSWORD_MIN_LEN as u32,
        max_len: MAX_LEN as u32,
        retention_hours: RETENTION_HOURS as u32,
    }
}

/// Список выдач. Просроченные удаляются здесь же.
///
/// Отдельный планировщик ради суточной очистки заводить незачем: приложение
/// офлайновое и между запусками ничего не делает, а список открывают тогда же,
/// когда генератор нужен.
#[tauri::command]
pub fn generator_list(state: State<'_, AppState>) -> Result<Vec<GeneratedSecretMeta>> {
    require_enabled(&state)?;
    with_unlocked(&state, |_master, db| {
        let removed = generated::purge_expired(db)?;
        if removed > 0 {
            log::info!("generator_list: purged {removed} expired secret(s)");
        }
        generated::list(db)
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratorCreateInput {
    pub kind: GeneratedKind,
    pub value: String,
}

#[tauri::command]
pub fn generator_create(
    input: GeneratorCreateInput,
    state: State<'_, AppState>,
) -> Result<GeneratedSecretMeta> {
    create_generated(&state, input)
}

pub(crate) fn create_generated(
    state: &AppState,
    input: GeneratorCreateInput,
) -> Result<GeneratedSecretMeta> {
    require_enabled(state)?;
    with_unlocked(state, |master, db| {
        generated::insert(db, master, input.kind, &input.value)
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratorDeleteInput {
    pub ids: Vec<String>,
}

#[tauri::command]
pub fn generator_delete(input: GeneratorDeleteInput, state: State<'_, AppState>) -> Result<usize> {
    delete_generated(&state, input)
}

pub(crate) fn delete_generated(state: &AppState, input: GeneratorDeleteInput) -> Result<usize> {
    require_enabled(state)?;
    with_unlocked(state, |_master, db| generated::delete_many(db, &input.ids))
}

/// Скопировать выдачу в буфер обмена.
///
/// Значение не возвращается в webview: копирование выполняет backend тем же
/// защищённым путём, что и для секретов записей — с маркерами исключения из
/// истории Windows и автоочисткой по таймеру. Отдать секрет наружу только для
/// того, чтобы фронтенд положил его в буфер сам, означало бы обойти эту защиту.
/// Тот же и гейт: при включённом подтверждении копирования нужен Hello.
#[tauri::command]
pub async fn generator_copy(
    id: String,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<()> {
    require_enabled(&state)?;
    crate::commands::auth_gate::require_copy_view_auth(&state).await?;
    let clear_after = state.settings.lock().clipboard_clear_seconds;
    // Мьютекс сессии отпускается до работы с буфером: clipboard-операции
    // синхронны и держать под ними состояние незачем.
    let secret = with_unlocked(&state, |master, db| generated::reveal(db, master, &id))?;
    crate::commands::clipboard::copy_secret_text(&app, &secret, clear_after)
}
