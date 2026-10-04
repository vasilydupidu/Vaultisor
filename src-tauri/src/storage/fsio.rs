//! Изменения файловой системы в каталоге хранилища.
//!
//! Каждое начинается с точки отказа: тест, моделирующий смерть процесса,
//! должен видеть, что после «краха» ни одно удаление или запись уже не
//! выполняется.

use std::path::Path;

use crate::error::{Result, VaultError};
use crate::failpoint;

/// Префикс временных файлов атомарной записи. Файл с таким префиксом — след
/// оборванной записи: замена не состоялась, и его можно удалить.
pub(crate) const TEMP_PREFIX: &str = ".vaultisor-tmp-";

/// Удалить файл; отсутствие файла — не ошибка.
pub fn remove_file_if_exists(path: &Path) -> Result<()> {
    failpoint::hit("fs.remove")?;
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Записать файл целиком.
pub fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    failpoint::hit("fs.write")?;
    std::fs::write(path, bytes)?;
    Ok(())
}

/// Заменить файл атомарно: временный файл в том же каталоге, fsync, замена с
/// WRITE_THROUGH. После сбоя на диске старое или новое содержимое целиком —
/// никогда усечённое.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .ok_or_else(|| VaultError::Internal("atomic write without parent".into()))?;
    failpoint::hit("fs.write_temp")?;
    let mut temporary = tempfile::Builder::new()
        .prefix(TEMP_PREFIX)
        .tempfile_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    let (file, temporary_path) = temporary.keep().map_err(|error| error.error)?;
    drop(file);
    crate::storage::restore::durable_replace(&temporary_path, path)
}

/// Удалить следы оборванных атомарных записей в каталоге.
pub fn remove_stale_temporaries(dir: &Path) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(TEMP_PREFIX))
        {
            remove_file_if_exists(&entry.path())?;
        }
    }
    Ok(())
}
