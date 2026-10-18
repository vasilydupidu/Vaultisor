use crate::error::Result;
use rusqlite::Connection;

/// Версия схемы метаданных. Продукт ещё не выпущен, поэтому миграций нет:
/// база создаётся сразу в актуальном виде. Первая же миграция появится
/// вместе с первым публичным релизом.
const META_SCHEMA_VERSION: i32 = 1;

#[derive(Debug, Clone)]
pub struct VaultMetaRow {
    pub created_at: String,
    pub wrapped_master_dpapi: Vec<u8>,
    pub autolock_seconds: u32,
    pub clipboard_clear_seconds: u32,
    pub require_auth_for_copy: bool,
    pub use_windows_hello: bool,
    /// Неверные попытки PIN и задержка до следующей (см. `auth::backoff`).
    pub backoff: crate::auth::backoff::BackoffState,
    /// 1 — мастер-пароль без TPM, 2 — PIN + Device Secret из TPM.
    pub crypto_version: u32,
    pub device_secret_tpm_name: Option<String>,
    pub device_secret_tpm_blob: Option<Vec<u8>>,
    pub argon2_m_cost: u32,
    pub argon2_t_cost: u32,
    pub argon2_p_cost: u32,
    pub ui_language: String,
    pub enable_health_check: bool,
    pub enable_password_history: bool,
    /// Экран генератора секретов и хранение его выдач.
    pub enable_generator: bool,
    /// Последняя закоммиченная операция с ресурсами ОС.
    pub last_op_id: Option<String>,
    /// Случайная per-vault энтропия DPAPI (32 байта). Создаётся вместе с
    /// хранилищем, поэтому необязательной быть не может.
    pub dpapi_entropy: Vec<u8>,
    pub recovery_generation: u64,
    pub recovery_wrapped_master: Option<Vec<u8>>,
    pub recovery_state: RecoveryState,
    /// После импорта ревизии баз нужно поднять выше подтверждённых; это
    /// делает первый вход, когда появляется мастер-ключ.
    pub data_rebase_pending: bool,
    /// Идентификатор последней выполненной смены PIN: повтор того же запроса
    /// после потерянного ответа распознаётся и не выполняется второй раз.
    pub pin_change_request_id: Option<String>,
    /// SHA-256 импортированных `records.db` и `web.db`: rebase при первом
    /// входе выполняется только над этим снимком.
    pub imported_snapshot: Option<([u8; 32], [u8; 32])>,
    pub security_epoch: u64,
    /// Windows Hello: платформенный WebAuthn-credential, который требуется
    /// дополнительно к PIN Vaultisor.
    pub hello_key_credential_name: Option<String>,
    pub hello_key_credential_public_key: Option<Vec<u8>>,
}

/// Состояние восстановления по долям Шамира.
///
/// ```text
/// disabled ──replace──▶ pending ──acknowledge──▶ active
///     ▲                    │  ▲                     │
///     └──────clear─────────┘  └──────replace────────┘
/// ```
///
/// `pending` — поколение создано, но пользователь не подтвердил, что сохранил
/// части B и C (или они израсходованы восстановлением, или хранилище
/// импортировано из копии). Такое хранилище при следующем входе ведёт к
/// выдаче нового комплекта: потерянный ответ процесса не превращается в
/// скрытую потерю восстановления. Доли B и C локально не хранятся никогда.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryState {
    Disabled,
    Pending,
    Active,
}

impl RecoveryState {
    pub fn as_str(self) -> &'static str {
        match self {
            RecoveryState::Disabled => "disabled",
            RecoveryState::Pending => "pending",
            RecoveryState::Active => "active",
        }
    }

    pub fn parse(value: &str) -> crate::error::Result<Self> {
        match value {
            "disabled" => Ok(RecoveryState::Disabled),
            "pending" => Ok(RecoveryState::Pending),
            "active" => Ok(RecoveryState::Active),
            _ => Err(crate::error::VaultError::MetaTampered),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Fido2KeyRow {
    pub id: String,
    pub name: String,
    pub credential_id: Vec<u8>,
    /// Публичный ключ credential'а (несжатый SEC1 P-256) из регистрации:
    /// им проверяется подпись каждого assertion.
    pub public_key: Vec<u8>,
    pub fido2_wrapped_key: Vec<u8>,
    pub created_at: String,
    /// AAGUID аутентификатора (hex-строка, 32 символа). Определяет модель ключа.
    pub aaguid: Option<String>,
    /// Режим привязки: true = ПИН+Touch (resident key), false = Touch-only.
    pub require_pin: bool,
    /// Запрос, которым ключ привязан (см. `commands::request`).
    pub request_id: Option<String>,
}

pub(crate) fn apply_meta_migrations(conn: &Connection) -> Result<()> {
    let current: i32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if current >= META_SCHEMA_VERSION {
        return Ok(());
    }

    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result: Result<()> = (|| {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS vault_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                created_at TEXT NOT NULL,
                wrapped_master_key BLOB NOT NULL,
                integrity_key_dpapi BLOB,
                dpapi_entropy BLOB NOT NULL,
                meta_mac BLOB,

                autolock_seconds INTEGER NOT NULL DEFAULT 300,
                clipboard_clear_seconds INTEGER NOT NULL DEFAULT 10,
                require_auth_for_copy INTEGER NOT NULL DEFAULT 0,
                use_windows_hello INTEGER NOT NULL DEFAULT 0,
                failed_pin_attempts INTEGER NOT NULL DEFAULT 0,
                pin_next_allowed INTEGER NOT NULL DEFAULT 0,
                pin_last_failure INTEGER NOT NULL DEFAULT 0,

                crypto_version INTEGER NOT NULL DEFAULT 1,
                device_secret_tpm_name TEXT,
                device_secret_tpm_blob BLOB,
                argon2_m_cost INTEGER NOT NULL DEFAULT 524288,
                argon2_t_cost INTEGER NOT NULL DEFAULT 6,
                argon2_p_cost INTEGER NOT NULL DEFAULT 2,

                ui_language TEXT NOT NULL DEFAULT 'ru',
                enable_health_check INTEGER NOT NULL DEFAULT 1,
                enable_password_history INTEGER NOT NULL DEFAULT 1,
                enable_generator INTEGER NOT NULL DEFAULT 0,

                recovery_generation INTEGER NOT NULL DEFAULT 0,
                recovery_wrapped_master BLOB,
                recovery_state TEXT NOT NULL DEFAULT 'disabled'
                    CHECK (recovery_state IN ('disabled', 'pending', 'active')),
                data_rebase_pending INTEGER NOT NULL DEFAULT 0,
                pin_change_request_id TEXT,
                import_records_sha256 BLOB,
                import_web_sha256 BLOB,
                security_epoch INTEGER NOT NULL DEFAULT 0,

                hello_key_credential_name TEXT,
                hello_key_credential_public_key BLOB,

                -- Последняя закоммиченная операция журнала ресурсов ОС.
                last_op_id TEXT
            );

            CREATE TABLE IF NOT EXISTS fido2_keys (
                id TEXT PRIMARY KEY,
                -- Запрос привязки: повтор после потерянного ответа не
                -- регистрирует второй credential.
                request_id TEXT UNIQUE,
                name TEXT NOT NULL,
                credential_id BLOB NOT NULL,
                public_key BLOB NOT NULL,
                fido2_wrapped_key BLOB NOT NULL,
                created_at TEXT NOT NULL,
                aaguid TEXT,
                require_pin INTEGER NOT NULL DEFAULT 1
            );
            "#,
        )?;
        conn.execute_batch(&format!("PRAGMA user_version = {META_SCHEMA_VERSION}"))?;
        Ok(())
    })();

    match result {
        Ok(()) => {
            if let Err(error) = crate::failpoint::hit("meta.migrate") {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(error);
            }
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}
