use rusqlite::Connection;
use crate::error::Result;

#[derive(Debug, Clone)]
pub struct VaultMetaRow {
    pub version: i64,
    pub created_at: String,
    pub wrapped_master_dpapi: Vec<u8>,
    pub pin_hash: String,
    pub autolock_seconds: u32,
    pub clipboard_clear_seconds: u32,
    pub require_auth_for_copy: bool,
    pub use_windows_hello: bool,
    pub hello_wrapped_key: Option<Vec<u8>>,
    pub max_pin_attempts: u32,
    pub failed_pin_attempts: u32,
    pub tpm_credential_name: Option<String>,
    pub tpm_wrapped_key: Option<Vec<u8>>,
    // v0.2 fields
    pub crypto_version: u32,
    pub device_secret_tpm_name: Option<String>,
    pub device_secret_tpm_blob: Option<Vec<u8>>,
    pub pq_encapsulation_key: Option<Vec<u8>>,
    pub pq_ciphertext: Option<Vec<u8>>,
    pub pq_dk_encrypted: Option<Vec<u8>>,
    pub argon2_m_cost: u32,
    pub argon2_t_cost: u32,
    pub argon2_p_cost: u32,
}

#[derive(Debug, Clone)]
pub struct RecoveryLocalRow {
    pub share_x: u8,
    pub share_y_dpapi: Vec<u8>,
}

pub(crate) fn apply_meta_migrations(conn: &Connection) -> Result<()> {
    let mut current: i32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if current < 1 {
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let res: Result<()> = (|| {
            conn.execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS vault_meta (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    version INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    wrapped_master_key BLOB NOT NULL,
                    pin_hash TEXT NOT NULL,
                    autolock_seconds INTEGER NOT NULL DEFAULT 60,
                    clipboard_clear_seconds INTEGER NOT NULL DEFAULT 10,
                    require_auth_for_copy INTEGER NOT NULL DEFAULT 0,
                    use_windows_hello INTEGER NOT NULL DEFAULT 0,
                    hello_wrapped_key BLOB,
                    max_pin_attempts INTEGER NOT NULL DEFAULT 10,
                    failed_pin_attempts INTEGER NOT NULL DEFAULT 0,
                    integrity_key_dpapi BLOB,
                    meta_mac BLOB,
                    tpm_credential_name TEXT,
                    tpm_wrapped_key BLOB,
                    -- v0.2: Device Secret (TPM-only)
                    crypto_version INTEGER NOT NULL DEFAULT 1,
                    device_secret_tpm_name TEXT,
                    device_secret_tpm_blob BLOB,
                    -- v0.2: ML-KEM Post-Quantum (Hello-путь)
                    pq_encapsulation_key BLOB,
                    pq_ciphertext BLOB,
                    pq_dk_encrypted BLOB,
                    -- v0.2: Argon2id параметры (хранятся в БД для будущей миграции)
                    argon2_m_cost INTEGER NOT NULL DEFAULT 524288,
                    argon2_t_cost INTEGER NOT NULL DEFAULT 6,
                    argon2_p_cost INTEGER NOT NULL DEFAULT 2,
                    ui_language TEXT NOT NULL DEFAULT 'ru'
                );

                CREATE TABLE IF NOT EXISTS recovery_local (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    share_x INTEGER NOT NULL,
                    share_y_dpapi BLOB NOT NULL
                );
                "#,
            )?;
            Ok(())
        })();
        match res {
            Ok(()) => {
                conn.execute_batch("PRAGMA user_version = 5")?;
                conn.execute_batch("COMMIT")?;
                current = 5;
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        }
    }
    // v0.2 миграция для существующих баз (user_version=1 → 2).
    if current >= 1 && current < 2 {
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let res: Result<()> = (|| {
            conn.execute_batch(
                r#"
                ALTER TABLE vault_meta ADD COLUMN crypto_version INTEGER NOT NULL DEFAULT 1;
                ALTER TABLE vault_meta ADD COLUMN device_secret_tpm_name TEXT;
                ALTER TABLE vault_meta ADD COLUMN device_secret_tpm_blob BLOB;
                ALTER TABLE vault_meta ADD COLUMN pq_encapsulation_key BLOB;
                ALTER TABLE vault_meta ADD COLUMN pq_ciphertext BLOB;
                ALTER TABLE vault_meta ADD COLUMN pq_dk_encrypted BLOB;
                ALTER TABLE vault_meta ADD COLUMN argon2_m_cost INTEGER NOT NULL DEFAULT 524288;
                ALTER TABLE vault_meta ADD COLUMN argon2_t_cost INTEGER NOT NULL DEFAULT 6;
                ALTER TABLE vault_meta ADD COLUMN argon2_p_cost INTEGER NOT NULL DEFAULT 2;
                "#,
            )?;
            Ok(())
        })();
        match res {
            Ok(()) => {
                conn.execute_batch("PRAGMA user_version = 2")?;
                conn.execute_batch("COMMIT")?;
                current = 2;
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        }
    }
    // v0.3 миграция для существующих баз (user_version=2 → 3).
    if current >= 2 && current < 3 {
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let res: Result<()> = (|| {
            // paired_extensions удалена (браузерное расширение вырезано).
            // Миграция сохранена только ради прогресса user_version, чтобы не
            // ломать цепочку версий на уже существующих базах.
            conn.execute_batch("SELECT 1;")?;
            Ok(())
        })();
        match res {
            Ok(()) => {
                conn.execute_batch("PRAGMA user_version = 3")?;
                conn.execute_batch("COMMIT")?;
                current = 3;
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        }
    }
    // v0.4 миграция: ранее добавляла sync_projects_to_mobile (Selective Sync).
    // L-01: фича вырезана, колонка удалена (нигде не читалась/писалась и не
    // входила в HMAC). У уже мигрировавших баз лишняя колонка безвредна —
    // код на неё не ссылается. Оставляем только прогресс user_version.
    if current >= 3 && current < 4 {
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let res: Result<()> = (|| {
            conn.execute_batch("SELECT 1;")?;
            Ok(())
        })();
        match res {
            Ok(()) => {
                conn.execute_batch("PRAGMA user_version = 4")?;
                conn.execute_batch("COMMIT")?;
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        }
    }
    // v0.5 миграция: ui_language
    if current >= 4 && current < 5 {
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let res: Result<()> = (|| {
            conn.execute_batch(
                r#"
                ALTER TABLE vault_meta ADD COLUMN ui_language TEXT NOT NULL DEFAULT 'ru';
                "#,
            )?;
            Ok(())
        })();
        match res {
            Ok(()) => {
                conn.execute_batch("PRAGMA user_version = 5")?;
                conn.execute_batch("COMMIT")?;
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        }
    }
    Ok(())
}
