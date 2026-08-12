// MetaDb — открытая SQLite-база метаданных vault'а.
//
// Содержит:
//   - vault_meta: wrapped_master_key, integrity_key_dpapi, pin_hash,
//     pin-attempts, hello-wrappers, TPM-wrappers, settings, MAC.
//   - recovery_local: одна локальная Shamir-доля A.
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

pub mod schema;
pub mod crud;

use std::path::{Path, PathBuf};
use parking_lot::Mutex;
use rusqlite::Connection;

use crate::error::Result;

pub use schema::{VaultMetaRow, RecoveryLocalRow, Fido2KeyRow};

pub struct MetaDb {
    pub(crate) conn: Mutex<Connection>,
    pub path: PathBuf,
}

impl MetaDb {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
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
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn with_conn<R>(&self, f: impl FnOnce(&Connection) -> Result<R>) -> Result<R> {
        let g = self.conn.lock();
        f(&*g)
    }
}
