//! Вынос блокирующей работы (Argon2, TPM, WebAuthn, файловые операции) из
//! потока асинхронного рантайма.
//!
//! В рабочей сборке — `spawn_blocking`: Argon2 на 512 МиБ держит поток
//! секундами, и на потоке рантайма это замораживало бы весь IPC.
//!
//! В тестах работа выполняется на месте. Точки отказа
//! ([`crate::failpoint`]) считают шаги в потоке теста, и перенос работы в
//! другой поток сделал бы шаги невидимыми: тест «уронил» бы процесс, а запись
//! на диск всё равно прошла бы.

use crate::error::Result;
#[cfg(not(test))]
use crate::error::VaultError;

#[cfg(not(test))]
pub async fn run<R, F>(f: F) -> Result<R>
where
    F: FnOnce() -> Result<R> + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| VaultError::Internal(format!("blocking task failed: {e}")))?
}

#[cfg(test)]
pub async fn run<R, F>(f: F) -> Result<R>
where
    F: FnOnce() -> Result<R> + Send + 'static,
    R: Send + 'static,
{
    f()
}
