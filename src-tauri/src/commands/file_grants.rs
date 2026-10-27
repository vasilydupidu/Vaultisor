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

/// Отклонить сетевой и устройственный путь.
///
/// Проверять нужно КАНОНИЧЕСКИЙ вид: подключённый диск `Z:` после
/// `canonicalize` превращается в `\\?\UNC\server\share`, и по исходной строке
/// сетевого пути не видно. Допустимы только пути на диске с буквой, в обычной
/// форме (`C:\...`) и в verbatim-форме (`\\?\C:\...`). Локальная папка
/// облачного клиента (Я.Диск, OneDrive) — обычный путь на диске и под запрет
/// не попадает.
pub(crate) fn reject_network_path(path: &std::path::Path) -> Result<()> {
    let text = path.to_string_lossy();
    if !(text.starts_with(r"\\") || text.starts_with("//")) {
        return Ok(());
    }
    let local_verbatim = text.strip_prefix(r"\\?\").is_some_and(|rest| {
        let bytes = rest.as_bytes();
        bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
    });
    if local_verbatim {
        Ok(())
    } else {
        Err(VaultError::BadInput(
            "Сетевые и UNC-пути не поддерживаются".into(),
        ))
    }
}

/// Самый большой файл резервной копии, который берётся в память.
pub(crate) const BACKUP_FILE_MAX: u64 = 512 * 1024 * 1024;

/// Привести путь к каноническому виду и только потом проверить его.
pub(crate) fn canonical_local_path(path: &std::path::Path) -> Result<PathBuf> {
    // Строка с сетевым путём отклоняется до обращения к ФС: canonicalize
    // пошёл бы за ним в сеть и мог бы надолго повиснуть.
    reject_network_path(path)?;
    let canonical = path.canonicalize()?;
    reject_network_path(&canonical)?;
    Ok(canonical)
}

/// Прочитать выбранный пользователем файл целиком, не доверяя его виду:
/// ссылки и не-файлы (устройства, каналы, каталоги) отклоняются, размер
/// ограничен. Без ограничения «файл» на сотни гигабайт был бы прочитан в
/// память целиком.
pub(crate) fn read_regular_file_limited(
    path: &std::path::Path,
    max_bytes: u64,
    what: &str,
) -> Result<Vec<u8>> {
    use std::io::Read;
    let too_big = || {
        VaultError::BadInput(format!(
            "{what}: файл больше допустимого размера ({} КиБ)",
            max_bytes / 1024
        ))
    };
    let link = std::fs::symlink_metadata(path)?;
    if link.file_type().is_symlink() || !link.is_file() {
        return Err(VaultError::BadInput(format!(
            "{what}: нужен обычный файл, а не ссылка или устройство"
        )));
    }
    if link.len() > max_bytes {
        return Err(too_big());
    }
    let file = std::fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(VaultError::BadInput(format!(
            "{what}: нужен обычный файл, а не ссылка или устройство"
        )));
    }
    // Размер мог вырасти между проверкой и чтением.
    let mut data = Vec::with_capacity(link.len() as usize);
    file.take(max_bytes + 1).read_to_end(&mut data)?;
    if data.len() as u64 > max_bytes {
        return Err(too_big());
    }
    Ok(data)
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
    // Сетевой путь виден только после canonicalize (подключённый диск
    // превращается в \\?\UNC\...), поэтому проверка идёт по его результату.
    let path = canonical_local_path(&selected)?;
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
    fn network_and_device_paths_are_rejected_in_every_spelling() {
        for bad in [
            r"\\?\UNC\server\share\file.vault",
            r"\\server\share\file.vault",
            r"//server/share/file.vault",
            r"\\.\PhysicalDrive0",
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\file",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\file",
        ] {
            assert!(
                matches!(
                    reject_network_path(std::path::Path::new(bad)),
                    Err(VaultError::BadInput(_))
                ),
                "{bad}"
            );
        }
        for good in [
            r"C:\Users\me\file.vault",
            r"\\?\C:\Users\me\file.vault",
            r"D:\sync\Яндекс.Диск\backups",
        ] {
            assert!(
                reject_network_path(std::path::Path::new(good)).is_ok(),
                "{good}"
            );
        }
    }

    #[test]
    fn canonical_form_is_what_gets_validated() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = canonical_local_path(dir.path()).unwrap();
        assert_eq!(canonical, dir.path().canonicalize().unwrap());
        // Результат canonicalize проходит ту же проверку, что и ввод.
        assert!(reject_network_path(&canonical).is_ok());
        // Сетевая строка отклоняется до обращения к файловой системе.
        assert!(canonical_local_path(std::path::Path::new(r"\\server\share\x")).is_err());
        assert!(canonical_local_path(std::path::Path::new(r"\\?\UNC\server\share\x")).is_err());
    }

    #[test]
    fn oversized_files_and_non_regular_files_are_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let ok = dir.path().join("ok.bin");
        std::fs::write(&ok, vec![7u8; 100]).unwrap();
        assert_eq!(
            read_regular_file_limited(&ok, 100, "Файл").unwrap().len(),
            100
        );

        let big = dir.path().join("big.bin");
        let file = std::fs::File::create(&big).unwrap();
        file.set_len(101).unwrap();
        drop(file);
        let error = read_regular_file_limited(&big, 100, "Файл").unwrap_err();
        assert!(matches!(error, VaultError::BadInput(_)), "{error:?}");

        // Каталог — не файл.
        let error = read_regular_file_limited(dir.path(), 100, "Файл").unwrap_err();
        assert!(matches!(error, VaultError::BadInput(_)), "{error:?}");
        // Нет файла — обычная ошибка ввода-вывода, не паника.
        assert!(read_regular_file_limited(&dir.path().join("none"), 100, "Файл").is_err());
    }

    #[test]
    fn symbolic_links_are_not_followed_when_the_platform_allows_creating_them() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.bin");
        std::fs::write(&target, b"data").unwrap();
        let link = dir.path().join("link.bin");
        #[cfg(windows)]
        let created = std::os::windows::fs::symlink_file(&target, &link).is_ok();
        #[cfg(not(windows))]
        let created = std::os::unix::fs::symlink(&target, &link).is_ok();
        if !created {
            // Без привилегии создавать ссылки (обычная учётка Windows) проверять нечего.
            return;
        }
        assert!(matches!(
            read_regular_file_limited(&link, 100, "Файл"),
            Err(VaultError::BadInput(_))
        ));
    }

    #[test]
    fn size_limits_match_the_documented_values() {
        assert_eq!(BACKUP_FILE_MAX, 512 * 1024 * 1024);
    }

    #[test]
    fn replay_expiry_wrong_operation_and_changed_session_fail() {
        let now = Instant::now();
        let session = Some(now);
        let mut store = FileGrants::default();
        let issue = |store: &mut FileGrants| {
            store.issue(
                PathBuf::from("selected.vault"),
                FileOperation::Import,
                session,
                now,
            )
        };
        let token = issue(&mut store);
        assert!(store
            .consume_at(&token, FileOperation::Import, session, now)
            .is_ok());
        assert!(store
            .consume_at(&token, FileOperation::Import, session, now)
            .is_err());
        let token = issue(&mut store);
        assert!(store
            .consume_at(
                &token,
                FileOperation::Import,
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
                FileOperation::Import,
                Some(now + Duration::from_secs(1)),
                now
            )
            .is_err());
        let token = issue(&mut store);
        store.clear();
        assert!(store
            .consume_at(&token, FileOperation::Import, session, now)
            .is_err());
    }
}
