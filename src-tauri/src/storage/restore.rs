//! Восстановление пользовательских данных из резервной копии: атомарная
//! замена `vault.records.db` и `vault.web.db` одним снимком.
//!
//! Метаданные безопасности (PIN, Hello, FIDO2, восстановление, задержки PIN,
//! настройки) не заменяются никогда: старая копия не должна возвращать
//! старые факторы входа.
//!
//! ```text
//! prepare: снимки *.new + прообразы *.old/*.absent → PREPARED
//! swap:    SWAPPING → замена обеих баз
//! commit:  COMMITTED → очистка журнала
//! ```
//!
//! Пока нет COMMITTED, старт возвращает прообразы обеих баз: итог целиком
//! старый. После COMMITTED — целиком восстановленный. Состояния «records из
//! копии, web живой» не бывает.
use std::path::{Path, PathBuf};

use crate::error::{Result, VaultError};

const JOURNAL: &str = ".restore-transaction";
const FILES: [&str; 2] = ["vault.records.db", "vault.web.db"];

fn sync_write(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    crate::failpoint::hit("journal.write")?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Persist the directory entry as well as file contents on Windows.
pub fn durable_replace(from: &Path, to: &Path) -> Result<()> {
    crate::failpoint::hit("fs.replace")?;
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::Storage::FileSystem::{
            MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        };
        let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
        let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: both paths are null-terminated buffers alive for this call;
        // names originate from the fixed transaction file list.
        unsafe {
            MoveFileExW(
                windows::core::PCWSTR(from.as_ptr()),
                windows::core::PCWSTR(to.as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
        .map_err(|_| VaultError::Io(std::io::Error::last_os_error()))?;
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(from, to)?;
        if let Some(parent) = to.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
    }
    Ok(())
}

fn mark(journal: &Path, name: &str) -> Result<()> {
    let temp = journal.join(format!("{name}.pending"));
    // An interrupted marker write is safe to retry; no transition happened.
    if temp.exists() {
        crate::storage::fsio::remove_file_if_exists(&temp)?;
    }
    sync_write(&temp, b"1")?;
    durable_replace(&temp, &journal.join(name))
}

fn copy_synced(from: &Path, to: &Path) -> Result<()> {
    crate::failpoint::hit("fs.copy")?;
    std::fs::copy(from, to)?;
    std::fs::OpenOptions::new()
        .write(true)
        .open(to)?
        .sync_all()?;
    Ok(())
}

pub struct RestoreTransaction {
    root: PathBuf,
    journal: PathBuf,
}

impl RestoreTransaction {
    /// Довести прерванное восстановление до конца. Вызывается при старте до
    /// открытия любой базы.
    pub fn recover(root: &Path) -> Result<()> {
        let journal = root.join(JOURNAL);
        if !journal.exists() {
            return Ok(());
        }
        if std::fs::symlink_metadata(&journal)?
            .file_type()
            .is_symlink()
        {
            return Err(VaultError::MetaTampered);
        }
        for marker in ["PREPARED", "SWAPPING", "COMMITTED", "ROLLED_BACK"] {
            let path = journal.join(marker);
            if path.exists() && std::fs::read(path)? != b"1" {
                return Err(VaultError::MetaTampered);
            }
        }
        let swapping = journal.join("SWAPPING").exists();
        let settled = journal.join("COMMITTED").exists() || journal.join("ROLLED_BACK").exists();
        if swapping && !settled {
            if !journal.join("PREPARED").exists() {
                return Err(VaultError::MetaTampered);
            }
            for name in FILES {
                let old = journal.join(format!("{name}.old"));
                let absent = journal.join(format!("{name}.absent"));
                if old.exists() && !absent.exists() {
                    copy_synced(&old, &root.join(name))?;
                } else if absent.exists() && !old.exists() {
                    crate::storage::fsio::remove_file_if_exists(&root.join(name))?;
                } else {
                    return Err(VaultError::MetaTampered);
                }
            }
            // A crash during cleanup must never demand already deleted preimages.
            mark(&journal, "ROLLED_BACK")?;
        }
        crate::failpoint::hit("journal.remove")?;
        std::fs::remove_dir_all(journal)?;
        Ok(())
    }

    /// Записать снимки и прообразы. Живые базы не трогаются.
    pub fn prepare(root: &Path, databases: [&[u8]; 2]) -> Result<Self> {
        let journal = root.join(JOURNAL);
        // Never reuse/overwrite an unfinished transaction.
        crate::failpoint::hit("journal.create")?;
        std::fs::create_dir(&journal)?;
        let transaction = Self {
            root: root.to_owned(),
            journal,
        };
        for (name, bytes) in FILES.iter().zip(databases) {
            sync_write(&transaction.staged(name), bytes)?;
        }
        for name in FILES {
            let source = root.join(name);
            if source.exists() {
                copy_synced(&source, &transaction.journal.join(format!("{name}.old")))?;
            } else {
                sync_write(&transaction.journal.join(format!("{name}.absent")), b"1")?;
            }
        }
        mark(&transaction.journal, "PREPARED")?;
        Ok(transaction)
    }

    fn staged(&self, name: &str) -> PathBuf {
        self.journal.join(format!("{name}.new"))
    }

    pub fn records_path(&self) -> PathBuf {
        self.staged(FILES[0])
    }

    pub fn web_path(&self) -> PathBuf {
        self.staged(FILES[1])
    }

    /// Заменить обе базы. Все соединения с живыми базами должны быть закрыты.
    pub fn swap(&self) -> Result<()> {
        mark(&self.journal, "SWAPPING")?;
        for name in FILES {
            durable_replace(&self.staged(name), &self.root.join(name))?;
        }
        Ok(())
    }

    /// Commit восстановления и очистка журнала.
    pub fn commit(self) -> Result<()> {
        mark(&self.journal, "COMMITTED")?;
        Self::recover(&self.root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live(root: &Path) {
        for (i, name) in FILES.iter().enumerate() {
            std::fs::write(root.join(name), [i as u8]).unwrap();
        }
    }

    #[test]
    fn interrupted_swaps_restore_both_preimages() {
        for count in 0..=2 {
            let dir = tempfile::tempdir().unwrap();
            live(dir.path());
            let tx = RestoreTransaction::prepare(dir.path(), [b"r", b"w"]).unwrap();
            sync_write(&tx.journal.join("SWAPPING"), b"1").unwrap();
            for name in &FILES[..count] {
                std::fs::rename(tx.staged(name), dir.path().join(name)).unwrap();
            }
            RestoreTransaction::recover(dir.path()).unwrap();
            for (i, name) in FILES.iter().enumerate() {
                assert_eq!(std::fs::read(dir.path().join(name)).unwrap(), [i as u8]);
            }
            assert!(!dir.path().join(JOURNAL).exists());
        }
    }

    #[test]
    fn committed_restore_survives_restart_and_cleans_journal() {
        let dir = tempfile::tempdir().unwrap();
        live(dir.path());
        let tx = RestoreTransaction::prepare(dir.path(), [b"r", b"w"]).unwrap();
        tx.swap().unwrap();
        sync_write(&tx.journal.join("COMMITTED"), b"1").unwrap();
        RestoreTransaction::recover(dir.path()).unwrap();
        assert_eq!(std::fs::read(dir.path().join(FILES[0])).unwrap(), b"r");
        assert_eq!(std::fs::read(dir.path().join(FILES[1])).unwrap(), b"w");
        assert!(!dir.path().join(JOURNAL).exists());
    }

    #[test]
    fn prepared_without_swapping_leaves_live_files_untouched() {
        let dir = tempfile::tempdir().unwrap();
        live(dir.path());
        let _tx = RestoreTransaction::prepare(dir.path(), [b"r", b"w"]).unwrap();
        RestoreTransaction::recover(dir.path()).unwrap();
        assert_eq!(std::fs::read(dir.path().join(FILES[0])).unwrap(), [0]);
        assert_eq!(std::fs::read(dir.path().join(FILES[1])).unwrap(), [1]);
    }
}
