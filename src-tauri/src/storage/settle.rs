//! Доведение прерванных операций до согласованного состояния.
//!
//! Выполняется при старте приложения и в начале каждой операции, меняющей
//! ресурсы ОС. Порядок важен: сначала откатывается незавершённое создание
//! хранилища (оно определяет, есть ли живые метаданные), затем по живым
//! метаданным доводится журнал ресурсов ОС.

use std::path::Path;

use crate::error::Result;
use crate::platform::Os;

pub(crate) fn settle(root: &Path, os: &Os) -> Result<()> {
    crate::storage::fsio::remove_stale_temporaries(root)?;
    crate::storage::create_staging::recover(root)?;
    let meta = root.join("vault.meta.db");
    let last = if meta.exists() {
        last_op_id(&meta)?
    } else {
        None
    };
    crate::storage::osjournal::recover(root, os, last.as_deref())
}

/// Закоммичена ли операция: живые метаданные опубликованы и несут её
/// `last_op_id`. Оставшийся после создания каталог сборки commit не отменяет —
/// важно лишь, перенесены ли из него метаданные.
pub(crate) fn is_committed(root: &Path, op_id: &str) -> Result<bool> {
    if crate::storage::create_staging::meta_unpublished(root) {
        return Ok(false);
    }
    let meta = root.join("vault.meta.db");
    if !meta.exists() {
        return Ok(false);
    }
    Ok(last_op_id(&meta)?.as_deref() == Some(op_id))
}

/// `last_op_id` живых метаданных без их изменения. Целостность здесь не
/// проверяется: значение нужно лишь чтобы решить, какие ресурсы ОС лишние, а
/// подмена поля мимо приложения обнаруживается MAC при разблокировке.
pub(crate) fn last_op_id(meta: &Path) -> Result<Option<String>> {
    let connection = rusqlite::Connection::open_with_flags(
        meta,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let value = connection
        .query_row(
            "SELECT last_op_id FROM vault_meta WHERE id = 1",
            [],
            |row| row.get::<_, Option<String>>(0),
        )
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })?;
    Ok(value)
}
