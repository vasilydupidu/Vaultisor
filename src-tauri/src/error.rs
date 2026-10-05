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

    #[error("HELLO_CANCELLED: Подтверждение Windows Hello отменено")]
    HelloCancelled,
    #[error("HELLO_FAILED: Подтверждение Windows Hello не выполнено")]
    HelloFailed,
    /// Windows отклонила саму церемонию WebAuthn. Код и его имя из
    /// `WebAuthNGetErrorName` не являются секретом и нужны пользователю:
    /// без них диалог «Произошла ошибка» неотличим от любого другого сбоя.
    #[error("HELLO_FAILED: Windows Hello отклонил операцию ({0})")]
    HelloOsError(String),
    #[error("HELLO_UNAVAILABLE: Windows Hello недоступен")]
    HelloUnavailable,
    #[error("FIDO_FAILED: Операция FIDO2 не выполнена: {0}")]
    FidoFailed(String),
    #[error("TPM_UNAVAILABLE: TPM или аппаратный ключ недоступен")]
    TpmUnavailable,
    #[error("DPAPI_FAILURE: Windows DPAPI не выполнил операцию")]
    DpapiFailure,
    #[error("CORRUPTED_WRAPPER: Повреждена обёртка ключа")]
    CorruptedWrapper,

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

    // PIN_BACKOFF: после серии неверных PIN следующая попытка принимается
    // только через указанное число секунд. Постоянной блокировки нет.
    #[error("PIN_BACKOFF: Слишком много неверных попыток. Повторите через {0} с.")]
    PinBackoff(i64),

    // AUTH_REQUIRED: изменение политики безопасности требует свежего
    // подтверждения PIN (и Hello) именно для этого действия.
    #[error("AUTH_REQUIRED:{0}: Подтвердите PIN для этого действия")]
    AuthorizationRequired(&'static str),

    // META_TAMPERED: HMAC от vault_meta не совпадает с сохранённым.
    // Кто-то отредактировал БД мимо приложения. Доступ блокируется до
    // явного сброса через recovery_restore.
    #[error("META_TAMPERED: Целостность хранилища нарушена. Требуется аварийное восстановление.")]
    MetaTampered,

    // DATA_ROLLBACK: база записей или паролей сайтов старее подтверждённой во
    // внешнем checkpoint'е — файл подменён старой копией. Тихо работать на
    // откаченных данных нельзя: вход с ними возможен только явным решением
    // владельца с полной проверкой PIN (как восстановление из копии).
    // Параметр — идентификатор обнаруженного снимка: явное «продолжить»
    // принимается только для него, а не для файлов, подложенных позже.
    #[error("DATA_ROLLBACK:{0}: Базы хранилища не совпадают с подтверждённым состоянием — файлы заменены старыми копиями.")]
    DataRollback(String),

    // Машинный префикс, чтобы фронтенд определял состояние по коду,
    // а не по подстроке русского текста (ломалось бы при любой правке формулировки
    // и не работало бы при смене языка сообщений).
    #[error("LOCKED: Хранилище заблокировано")]
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
    DbFailure(#[from] rusqlite::Error),

    #[error("Ошибка JSON: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Системная ошибка: {0}")]
    System(String),

    // Сообщения, которые действительно предназначены пользователю,
    // получили собственный вариант. Раньше они ехали в System вместе с текстами
    // Windows API, из-за чего System нельзя было безопасно редактировать.
    #[error("HELLO_SETUP_REQUIRED: {0}")]
    HelloSetupRequired(String),

    #[error("Recovery: {0}")]
    Recovery(String),

    #[error("Некорректный аргумент: {0}")]
    BadInput(String),

    #[error("Внутренняя ошибка: {0}")]
    Internal(String),

    /// Отказ, внесённый точкой отказа в тесте атомарности.
    #[cfg(test)]
    #[error("INJECTED: {0}")]
    Injected(&'static str),
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
        // Sanitize internal details before sending to the frontend.
        // Structured error variants keep their user-facing messages;
        // catch-all wrappers (Database, Io, Internal) are
        // redacted so stack traces / file paths don't leak to the webview.
        let msg = match self {
            VaultError::DbFailure(_) => "DB_FAILURE: Ошибка БД".to_owned(),
            VaultError::FidoFailed(_) => "FIDO_FAILED: Операция FIDO2 не выполнена".to_owned(),
            VaultError::Io(_) => "Ошибка ввода/вывода".to_owned(),
            VaultError::Internal(_) => "Внутренняя ошибка".to_owned(),
            // System и Storage несут тексты Windows API и SQLite
            // (включая имена CNG-ключей и пути), поэтому наружу уходит только
            // код; подробности остаются в логе.
            VaultError::System(detail) => {
                log::warn!("system error: {detail}");
                "SYSTEM_ERROR: Системная ошибка".to_owned()
            }
            VaultError::Storage(detail) => {
                log::warn!("storage error: {detail}");
                "STORAGE_ERROR: Ошибка хранилища".to_owned()
            }
            other => other.to_string(),
        };
        serializer.serialize_str(&msg)
    }
}

pub type Result<T> = std::result::Result<T, VaultError>;

#[cfg(test)]
mod tests {
    use super::*;

    fn serialized(error: VaultError) -> String {
        serde_json::to_string(&error).expect("VaultError must serialize")
    }

    /// Наружу уходит код, а не текст Windows API / SQLite.
    #[test]
    fn internal_details_never_reach_the_frontend() {
        let leaky = [
            VaultError::System("NCryptOpenKey: Vaultisor-CNG-8f3a not found".into()),
            VaultError::Storage("C:/Users/victim/vault/vault.meta.db locked".into()),
            VaultError::Internal("thread panicked at src/lib.rs:42".into()),
            VaultError::FidoFailed("0x8009002E device path hid#vid_1050".into()),
        ];
        for error in leaky {
            let json = serialized(error);
            for secret in [
                "NCryptOpenKey",
                "Vaultisor-CNG",
                "victim",
                "src/lib.rs",
                "hid#vid",
            ] {
                assert!(
                    !json.contains(secret),
                    "внутренняя деталь {secret} утекла во фронтенд: {json}"
                );
            }
        }
    }

    /// Коды состояний, на которые опирается интерфейс, должны быть стабильны.
    #[test]
    fn machine_readable_codes_are_stable() {
        assert!(serialized(VaultError::Locked).contains("LOCKED:"));
        assert!(serialized(VaultError::DeviceMismatch).contains("DEVICE_MISMATCH:"));
        assert!(serialized(VaultError::PinBackoff(30)).contains("PIN_BACKOFF:"));
        assert!(serialized(VaultError::AuthorizationRequired("change_pin"))
            .contains("AUTH_REQUIRED:change_pin"));
        assert!(serialized(VaultError::MetaTampered).contains("META_TAMPERED:"));
        assert!(serialized(VaultError::DataRollback("abc".into())).contains("DATA_ROLLBACK:abc:"));
        assert!(serialized(VaultError::System("x".into())).contains("SYSTEM_ERROR:"));
        assert!(serialized(VaultError::Storage("x".into())).contains("STORAGE_ERROR:"));
    }

    /// Пользовательские сообщения, наоборот, обязаны доходить целиком.
    #[test]
    fn user_facing_messages_are_preserved() {
        let json = serialized(VaultError::BadInput("PIN короче 11 символов".into()));
        assert!(json.contains("PIN"));
        let json = serialized(VaultError::Recovery("Введите хотя бы одну часть".into()));
        assert!(json.contains("Recovery") || json.contains("часть"));
    }
}
