use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub enum CoreError {
    Crypto(String),
    BadInput(String),
    Internal(String),
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoreError::Crypto(s) => write!(f, "Ошибка криптографии: {s}"),
            CoreError::BadInput(s) => write!(f, "Некорректный аргумент: {s}"),
            CoreError::Internal(s) => write!(f, "Внутренняя ошибка: {s}"),
        }
    }
}

impl std::error::Error for CoreError {}

impl From<argon2::Error> for CoreError {
    fn from(e: argon2::Error) -> Self {
        CoreError::Crypto(format!("argon2: {e}"))
    }
}

impl From<argon2::password_hash::Error> for CoreError {
    fn from(e: argon2::password_hash::Error) -> Self {
        CoreError::Crypto(format!("argon2-hash: {e}"))
    }
}

impl From<aes_gcm::Error> for CoreError {
    fn from(_: aes_gcm::Error) -> Self {
        CoreError::Crypto("aead-failure".into())
    }
}

pub type Result<T> = std::result::Result<T, CoreError>;
