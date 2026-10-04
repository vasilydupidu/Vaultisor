//! Native file selection grants authority to one operation in one session.
use crate::{
    error::{Result, VaultError},
    state::{AppState, SessionState},
};
use serde::Deserialize;
use std::{
    collections::HashMap,
    path::PathBuf,
    time::{Duration, Instant},
};
use tauri::State;
use tauri_plugin_dialog::DialogExt;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileOperation {
    Export,
    Restore,
    Import,
    BackupDirectory,
    CsvImport,
    RecoveryRead,
}

struct Grant {
    path: PathBuf,
    operation: FileOperation,
    session: Option<Instant>,
    expires: Instant,
}

#[derive(Default)]
pub struct FileGrants {
    entries: HashMap<String, Grant>,
}

impl FileGrants {
    fn issue(
        &mut self,
        path: PathBuf,
        operation: FileOperation,
        session: Option<Instant>,
        now: Instant,
    ) -> String {
        self.entries.retain(|_, g| g.expires > now);
        let token = uuid::Uuid::new_v4().to_string();
        self.entries.insert(
            token.clone(),
            Grant {
                path,
                operation,
                session,
                expires: now + Duration::from_secs(60),
            },
        );
        token
    }

    pub fn consume(
        &mut self,
        token: &str,
        operation: FileOperation,
        session: Option<Instant>,
    ) -> Result<PathBuf> {
        self.consume_at(token, operation, session, Instant::now())
    }

    fn consume_at(
        &mut self,
        token: &str,
        operation: FileOperation,
        session: Option<Instant>,
        now: Instant,
    ) -> Result<PathBuf> {
        let grant = self.entries.remove(token).ok_or_else(invalid_grant)?;
        if grant.operation != operation || grant.session != session || grant.expires <= now {
            return Err(invalid_grant());
        }
        Ok(grant.path)
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Полномочие без системного диалога — для сценарных тестов.
    #[cfg(test)]
    pub(crate) fn issue_for_test(
        &mut self,
        path: PathBuf,
        operation: FileOperation,
        session: Option<Instant>,
    ) -> String {
        self.issue(path, operation, session, Instant::now())
    }
}

fn invalid_grant() -> VaultError {
    VaultError::BadInput("Полномочие выбора файла недействительно или истекло".into())
}

pub fn session_stamp(session: &SessionState) -> Option<Instant> {
    match session {
        SessionState::Unlocked { unlocked_at, .. } => Some(*unlocked_at),
        SessionState::Locked => None,
    }
}

fn authorize(state: &AppState, operation: FileOperation) -> Result<Option<Instant>> {
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    let session = state.session.lock();
    let stamp = session_stamp(&session);
    if operation == FileOperation::Import {
        if state.meta_path().exists() || state.records_path().exists() || state.web_path().exists()
        {
            return Err(VaultError::BadInput(
                "Импорт доступен только в пустое хранилище".into(),
            ));
        }
    } else if stamp.is_none() && operation != FileOperation::RecoveryRead {
        return Err(VaultError::Locked);
    }
    Ok(stamp)
}

#[tauri::command]
pub async fn file_prepare(
    operation: FileOperation,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<String> {
    let initial = authorize(&state, operation)?;
    let selected = tauri::async_runtime::spawn_blocking(move || {
        let dialog = app.dialog().file();
        match operation {
            FileOperation::Export => dialog
                .set_title("Экспорт Vaultisor")
                .set_file_name("Vaultisor.vault")
                .add_filter("Vaultisor", &["vault"])
                .blocking_save_file(),
            FileOperation::Restore | FileOperation::Import => dialog
                .set_title("Выберите резервную копию Vaultisor")
                .add_filter("Vaultisor", &["vault"])
                .blocking_pick_file(),
            FileOperation::BackupDirectory => dialog
                .set_title("Каталог резервных копий Vaultisor")
                .blocking_pick_folder(),
            FileOperation::CsvImport => dialog
                .set_title("Импорт паролей из CSV")
                .add_filter("CSV", &["csv"])
                .blocking_pick_file(),
            FileOperation::RecoveryRead => dialog
                .set_title("Часть восстановления Vaultisor")
                .add_filter("Vaultisor Share", &["vss", "txt"])
                .blocking_pick_file(),
        }
    })
    .await
    .map_err(|e| VaultError::Internal(e.to_string()))?
    .ok_or_else(|| VaultError::BadInput("Выбор файла отменён".into()))?
    .into_path()
    .map_err(|_| invalid_grant())?;
    let path = if operation == FileOperation::Export {
        let parent = selected
            .parent()
            .ok_or_else(invalid_grant)?
            .canonicalize()?;
        let path = parent.join(selected.file_name().ok_or_else(invalid_grant)?);
        if path.exists() {
            return Err(VaultError::BadInput("Выберите новое имя файла".into()));
        }
        path
    } else {
        selected.canonicalize()?
    };
    if authorize(&state, operation)? != initial {
        return Err(VaultError::Locked);
    }
    // Prevent a lock/new unlock between revalidation and grant insertion.
    let session = state.session.lock();
    if session_stamp(&session) != initial {
        return Err(VaultError::Locked);
    }
    let token = state
        .file_grants
        .lock()
        .issue(path, operation, initial, Instant::now());
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replay_expiry_wrong_operation_and_changed_session_fail() {
        let now = Instant::now();
        let session = Some(now);
        let mut store = FileGrants::default();
        let issue = |store: &mut FileGrants| {
            store.issue(
                PathBuf::from("selected.vault"),
                FileOperation::Export,
                session,
                now,
            )
        };
        let token = issue(&mut store);
        assert!(store
            .consume_at(&token, FileOperation::Export, session, now)
            .is_ok());
        assert!(store
            .consume_at(&token, FileOperation::Export, session, now)
            .is_err());
        let token = issue(&mut store);
        assert!(store
            .consume_at(
                &token,
                FileOperation::Export,
                session,
                now + Duration::from_secs(60)
            )
            .is_err());
        let token = issue(&mut store);
        assert!(store
            .consume_at(&token, FileOperation::Restore, session, now)
            .is_err());
        let token = issue(&mut store);
        assert!(store
            .consume_at(
                &token,
                FileOperation::Export,
                Some(now + Duration::from_secs(1)),
                now
            )
            .is_err());
        let token = issue(&mut store);
        store.clear();
        assert!(store
            .consume_at(&token, FileOperation::Export, session, now)
            .is_err());
    }
}
