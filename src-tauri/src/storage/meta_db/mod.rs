// MetaDb — открытая SQLite-база метаданных vault'а.
//
// Содержит:
//   - vault_meta: обёртка мастер-ключа, integrity_key_dpapi, задержки PIN,
//     Hello, Device Secret, настройки, восстановление (конверт, поколение,
//     состояние), MAC.
//   - fido2_keys: привязанные FIDO2-ключи (их дайджест входит в MAC).
//
// Эта БД НЕ зашифрована SQLCipher. Это **архитектурно осознанно**:
// чтобы выполнить cascade unlock (на любой машине, в т.ч. чужой после
// переноса), backend должен прочитать wrapped_master_key ДО того как
// получит SQLCipher-ключ. SQLCipher-ключ деривируется из master_key,
// который восстанавливается через cascade или Shamir.
//
// Защита целостности:
//   - HMAC-SHA256 (meta_mac) на основе integrity_key_dpapi (DPAPI-обёрнут).
//   - Атакующий без DPAPI-доступа не может ни прочитать integrity_key,
//     ни пересчитать MAC → любая правка vault.meta.db обнаруживается.

pub mod crud;
pub mod schema;

use parking_lot::Mutex;
use rusqlite::Connection;
use std::path::{Path, PathBuf};

use crate::error::Result;

pub use schema::{Fido2KeyRow, RecoveryState, VaultMetaRow};

// Serialize DB commit + external/local checkpoint writes across fresh MetaDb
// connections. Without this, an older writer can overwrite a newer checkpoint.
pub(crate) static SECURITY_WRITE_LOCK: once_cell::sync::Lazy<parking_lot::ReentrantMutex<()>> =
    once_cell::sync::Lazy::new(|| parking_lot::ReentrantMutex::new(()));

pub struct MetaDb {
    pub(crate) conn: Mutex<Connection>,
    pub path: PathBuf,
    /// Каталог живого хранилища: к нему привязан внешний checkpoint. Обычно
    /// это каталог файла; при сборке нового хранилища файл лежит во временном
    /// каталоге, а checkpoint уже относится к будущему живому.
    pub(crate) checkpoint_root: PathBuf,
}

impl MetaDb {
    pub fn open(path: &Path) -> Result<Self> {
        let root = path.parent().map(Path::to_path_buf).unwrap_or_default();
        Self::open_staged(path, &root)
    }

    /// Открыть метаданные, собираемые вне живого каталога `live_root`.
    pub fn open_staged(path: &Path, live_root: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if !path.exists() {
            crate::failpoint::hit("meta.create_file")?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            r#"
            PRAGMA busy_timeout = 5000;
            PRAGMA journal_mode = DELETE;
            PRAGMA synchronous = FULL;
            PRAGMA foreign_keys = ON;
            PRAGMA temp_store = MEMORY;
            PRAGMA secure_delete = ON;
            "#,
        )?;
        schema::apply_meta_migrations(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            path: path.to_path_buf(),
            checkpoint_root: live_root.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn with_conn<R>(&self, f: impl FnOnce(&Connection) -> Result<R>) -> Result<R> {
        let g = self.conn.lock();
        f(&g)
    }

    /// Take a transaction-consistent SQLite online backup while the live
    /// database remains open.  Callers must use the resulting file instead of
    /// copying the live database path directly.
    pub fn backup_to(&self, destination: &Path) -> Result<()> {
        let _security = SECURITY_WRITE_LOCK.lock();
        self.with_conn(|source| {
            source.backup(rusqlite::DatabaseName::Main, destination, None)?;
            Ok(())
        })
    }
}
