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
    pub ui_language: String,
    pub fido2_enabled: bool,
    pub fido2_credential_id: Option<Vec<u8>>,
    pub fido2_public_key: Option<Vec<u8>>,
    pub enable_health_check: bool,
    pub enable_password_history: bool,
    /// VULN-06 FIX: per-vault random DPAPI entropy (32 bytes).
    /// None для старых vault'ов — используется дефолт b"vaultisor:dpapi:v1".
    pub dpapi_entropy: Option<Vec<u8>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecoveryLocalRow {
    pub share_x: u8,
    pub share_y_dpapi: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Fido2KeyRow {
    pub id: String,
    pub name: String,
    pub credential_id: Vec<u8>,
    pub public_key: Option<Vec<u8>>,
    pub fido2_wrapped_key: Vec<u8>,
    pub created_at: String,
    /// AAGUID аутентификатора (hex-строка, 32 символа). Определяет модель ключа.
    pub aaguid: Option<String>,
    /// Режим привязки: true = ПИН+Touch (resident key), false = Touch-only (non-resident)
    pub require_pin: bool,
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
                    -- v0.2: Argon2id параметры
                    argon2_m_cost INTEGER NOT NULL DEFAULT 524288,
                    argon2_t_cost INTEGER NOT NULL DEFAULT 6,
                    argon2_p_cost INTEGER NOT NULL DEFAULT 2,
                    ui_language TEXT NOT NULL DEFAULT 'ru',
                    fido2_enabled INTEGER NOT NULL DEFAULT 0,
                    fido2_credential_id BLOB,
                    fido2_public_key BLOB,
                    enable_health_check INTEGER NOT NULL DEFAULT 1,
                    enable_password_history INTEGER NOT NULL DEFAULT 1,
                    fido2_wrapped_key BLOB,
                    dpapi_entropy BLOB
                );

                CREATE TABLE IF NOT EXISTS recovery_local (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    share_x INTEGER NOT NULL,
                    share_y_dpapi BLOB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS fido2_keys (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    credential_id BLOB NOT NULL,
                    public_key BLOB,
                    fido2_wrapped_key BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    aaguid TEXT,
                    require_pin INTEGER NOT NULL DEFAULT 1
                );
                "#,
            )?;
            Ok(())
        })();
        match res {
            Ok(()) => {
                conn.execute_batch("PRAGMA user_version = 11")?;
                conn.execute_batch("COMMIT")?;
                current = 11;
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        }
    }
    // v0.2 миграция
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
    // v0.3 миграция
    if current >= 2 && current < 3 {
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let res: Result<()> = (|| {
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
    // v0.4 миграция
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
                current = 4;
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
                current = 5;
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        }
    }
    // v0.6 миграция: fido2 и enable_health_check
    if current >= 5 && current < 6 {
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let res: Result<()> = (|| {
            conn.execute_batch(
                r#"
                ALTER TABLE vault_meta ADD COLUMN fido2_enabled INTEGER NOT NULL DEFAULT 0;
                ALTER TABLE vault_meta ADD COLUMN fido2_credential_id BLOB;
                ALTER TABLE vault_meta ADD COLUMN fido2_public_key BLOB;
                ALTER TABLE vault_meta ADD COLUMN enable_health_check INTEGER NOT NULL DEFAULT 1;
                "#,
            )?;
            Ok(())
        })();
        match res {
            Ok(()) => {
                conn.execute_batch("PRAGMA user_version = 6")?;
                conn.execute_batch("COMMIT")?;
                current = 6;
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        }
    }
    // v0.7 миграция: enable_password_history
    if current >= 6 && current < 7 {
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let res: Result<()> = (|| {
            conn.execute_batch(
                r#"
                ALTER TABLE vault_meta ADD COLUMN enable_password_history INTEGER NOT NULL DEFAULT 1;
                "#,
            )?;
            Ok(())
        })();
        match res {
            Ok(()) => {
                conn.execute_batch("PRAGMA user_version = 7")?;
                conn.execute_batch("COMMIT")?;
                current = 7;
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        }
    }
    // v0.8 миграция: fido2_wrapped_key
    if current >= 7 && current < 8 {
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let res: Result<()> = (|| {
            conn.execute_batch(
                r#"
                ALTER TABLE vault_meta ADD COLUMN fido2_wrapped_key BLOB;
                "#,
            )?;
            Ok(())
        })();
        match res {
            Ok(()) => {
                current = 8;
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        }
    }
    // v0.9 миграция: fido2_keys мульти-ключи
    if current >= 8 && current < 9 {
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let res: Result<()> = (|| {
            conn.execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS fido2_keys (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    credential_id BLOB NOT NULL,
                    public_key BLOB,
                    fido2_wrapped_key BLOB NOT NULL,
                    created_at TEXT NOT NULL
                );

                INSERT OR IGNORE INTO fido2_keys (id, name, credential_id, public_key, fido2_wrapped_key, created_at)
                SELECT 'legacy-fido2-key-1', 'Рутокен MFA / FIDO2 Ключ', fido2_credential_id, fido2_public_key, fido2_wrapped_key, datetime('now')
                FROM vault_meta
                WHERE id = 1 AND fido2_enabled = 1 AND fido2_credential_id IS NOT NULL AND fido2_wrapped_key IS NOT NULL;
                "#,
            )?;
            Ok(())
        })();
        match res {
            Ok(()) => {
                conn.execute_batch("PRAGMA user_version = 9")?;
                conn.execute_batch("COMMIT")?;
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        }
    }
    // v0.10 миграция: добавить aaguid и require_pin в fido2_keys
    if current >= 9 && current < 10 {
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let res: Result<()> = (|| {
            // Добавляем колонки только если их ещё нет
            let cols: Vec<String> = conn
                .prepare("PRAGMA table_info(fido2_keys)")?
                .query_map([], |r| r.get::<_, String>(1))?
                .filter_map(|r| r.ok())
                .collect();
            if !cols.iter().any(|c| c == "aaguid") {
                conn.execute_batch("ALTER TABLE fido2_keys ADD COLUMN aaguid TEXT")?;
            }
            if !cols.iter().any(|c| c == "require_pin") {
                conn.execute_batch("ALTER TABLE fido2_keys ADD COLUMN require_pin INTEGER NOT NULL DEFAULT 1")?;
            }
            Ok(())
        })();
        match res {
            Ok(()) => {
                conn.execute_batch("PRAGMA user_version = 10")?;
                conn.execute_batch("COMMIT")?;
                current = 10;
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        }
    }
    // v11 миграция: VULN-06 FIX — per-vault DPAPI entropy
    if current >= 10 && current < 11 {
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let res: Result<()> = (|| {
            let cols: Vec<String> = conn
                .prepare("PRAGMA table_info(vault_meta)")?
                .query_map([], |r| r.get::<_, String>(1))?
                .filter_map(|r| r.ok())
                .collect();
            if !cols.iter().any(|c| c == "dpapi_entropy") {
                conn.execute_batch("ALTER TABLE vault_meta ADD COLUMN dpapi_entropy BLOB")?;
            }
            // Генерируем 32-byte random entropy для существующего vault'а.
            let has_vault: bool = conn.query_row(
                "SELECT COUNT(*) > 0 FROM vault_meta WHERE id = 1", [], |r| r.get(0)
            ).unwrap_or(false);
            if has_vault {
                let existing: Option<Vec<u8>> = conn.query_row(
                    "SELECT dpapi_entropy FROM vault_meta WHERE id = 1", [],
                    |r| r.get(0),
                ).unwrap_or(None);
                if existing.is_none() {
                    let mut entropy = [0u8; 32];
                    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut entropy);
                    conn.execute(
                        "UPDATE vault_meta SET dpapi_entropy = ?1 WHERE id = 1",
                        rusqlite::params![&entropy[..]],
                    )?;
                }
            }
            Ok(())
        })();
        match res {
            Ok(()) => {
                conn.execute_batch("PRAGMA user_version = 11")?;
                conn.execute_batch("COMMIT")?;
                let _ = current;
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        }
    }
    Ok(())
}
