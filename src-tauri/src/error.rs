// Единый тип ошибки бэкенда.
// Конвертируется в строку для фронта (внутренние детали скрыты),
// но в логах сохраняет техническую информацию.

use serde::{Serialize, Serializer};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Хранилище не инициализировано")]
    NotInitialized,

    #[error("Неверный PIN")]
    InvalidPin,

    #[error("Неверная master-passphrase")]
    InvalidPassphrase,

    // Префикс DEVICE_MISMATCH: фронтенд детектирует это конкретное состояние
    // и автоматически открывает Recovery-диалог с заголовком про перенос.
    #[error("DEVICE_MISMATCH: Хранилище создано на другом устройстве или для другой учётной записи Windows. Восстановите доступ через Shamir B+C.")]
    DeviceMismatch,

    // TPM_REQUIRED: v0.2 требует TPM для создания Device Secret.
    // Без аппаратного якоря невозможно обеспечить защиту от офлайн-перебора.
    #[error("TPM_REQUIRED: Для создания хранилища требуется модуль TPM (Trusted Platform Module). Убедитесь, что TPM 2.0 включён в BIOS.")]
    TpmRequired,

    // TOO_MANY_ATTEMPTS: persistent счётчик в БД исчерпан. Перезапуск НЕ
    // помогает (счётчик с MAC в БД). Единственный путь — Shamir-recovery.
    #[error("TOO_MANY_ATTEMPTS: Лимит попыток PIN исчерпан. Доступ возможен только через аварийное восстановление по Shamir 2-of-3.")]
    TooManyAttempts,

    // META_TAMPERED: HMAC от vault_meta не совпадает с сохранённым.
    // Кто-то отредактировал БД мимо приложения. Доступ блокируется до
    // явного сброса через recovery_restore.
    #[error("META_TAMPERED: Целостность хранилища нарушена. Требуется аварийное восстановление.")]
    MetaTampered,

    #[error("Хранилище заблокировано")]
    Locked,

    #[error("Запись не найдена")]
    RecordNotFound,

    #[error("Ошибка криптографии: {0}")]
    Crypto(String),

    #[error("Ошибка хранилища: {0}")]
    Storage(String),

    #[error("Ошибка ввода/вывода: {0}")]
    Io(#[from] std::io::Error),

    #[error("Ошибка БД: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Ошибка JSON: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Системная ошибка: {0}")]
    System(String),

    #[error("Recovery: {0}")]
    Recovery(String),

    #[error("Некорректный аргумент: {0}")]
    BadInput(String),

    #[error("Внутренняя ошибка: {0}")]
    Internal(String),
}

impl From<argon2::Error> for VaultError {
    fn from(e: argon2::Error) -> Self {
        VaultError::Crypto(format!("argon2: {e}"))
    }
}

impl From<argon2::password_hash::Error> for VaultError {
    fn from(e: argon2::password_hash::Error) -> Self {
        VaultError::Crypto(format!("argon2-hash: {e}"))
    }
}

impl From<aes_gcm::Error> for VaultError {
    fn from(_: aes_gcm::Error) -> Self {
        // Не раскрываем детали AES-GCM, чтобы не помогать таймингу.
        VaultError::Crypto("aead-failure".into())
    }
}

impl From<anyhow::Error> for VaultError {
    fn from(e: anyhow::Error) -> Self {
        VaultError::Internal(e.to_string())
    }
}

impl From<core_shared::error::CoreError> for VaultError {
    fn from(e: core_shared::error::CoreError) -> Self {
        match e {
            core_shared::error::CoreError::Crypto(s) => VaultError::Crypto(s),
            core_shared::error::CoreError::BadInput(s) => VaultError::BadInput(s),
            core_shared::error::CoreError::Internal(s) => VaultError::Internal(s),
        }
    }
}

// Чтобы возвращать VaultError из Tauri-команд: serde::Serialize.
// Полный путь std::result::Result, чтобы локальный алиас Result<T> не подменил.
impl Serialize for VaultError {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // MED-11: Sanitize internal details before sending to the frontend.
        // Structured error variants keep their user-facing messages;
        // catch-all wrappers (Database, Io, Internal) are
        // redacted so stack traces / file paths don't leak to the webview.
        let msg = match self {
            VaultError::Database(_) => "Ошибка БД".to_owned(),
            VaultError::Io(_) => "Ошибка ввода/вывода".to_owned(),
            VaultError::Internal(_) => "Внутренняя ошибка".to_owned(),
            other => other.to_string(),
        };
        serializer.serialize_str(&msg)
    }
}

pub type Result<T> = std::result::Result<T, VaultError>;
