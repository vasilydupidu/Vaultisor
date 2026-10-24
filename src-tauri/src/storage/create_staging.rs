//! Создание хранилища в отдельном каталоге с атомарной публикацией.
//!
//! Все файлы нового хранилища собираются в `vault/.create-staging/`. Живой
//! каталог не трогается, пока сборка не завершена целиком. Так же
//! публикуется импорт из резервной копии. Публикация:
//!
//! ```text
//! COMMITTING(op_id) → перенос web, records, meta (последней) = COMMIT
//!                   → удаление каталога сборки (cleanup)
//! ```
//!
//! Commit определяется по фактически опубликованному состоянию: хранилище
//! создано, как только в живом каталоге лежат метаданные этой операции
//! (`last_op_id`), а в сборке их больше нет. Метаданные переносятся последними,
//! поэтому к этому моменту опубликованы и все остальные файлы. Оставшийся
//! каталог сборки — лишь незавершённая уборка: при старте он удаляется, а
//! хранилище остаётся (NEW_VALID + cleanup pending).
//!
//! Если метаданные не опубликованы, создание откатывается: удаляются файлы
//! сборки и — только при наличии маркера COMMITTING и только пока живых
//! метаданных нет — те живые файлы, которые уже были перенесены из сборки.
//! Файл, чья копия ещё лежит в сборке, не перенесён, а значит живой файл с тем
//! же именем чужой и не трогается. Живые метаданные означают существующее
//! хранилище: создание и импорт начинаются только без них, поэтому рядом с
//! ними маркер может быть лишь подложенным, и ни один живой файл не удаляется.
//!
//! Создание начинается, только если живых файлов хранилища нет. Существующее
//! хранилище этот модуль не удаляет ни при каких условиях.

use std::path::{Path, PathBuf};

use crate::error::{Result, VaultError};

const DIR: &str = ".create-staging";
const MARKER: &str = "COMMITTING";

const META: &str = "vault.meta.db";

/// Файлы в порядке публикации: метаданные последними — их появление в живом
/// каталоге означает, что всё остальное уже на месте.
const FILES: [&str; 3] = ["vault.web.db", "vault.records.db", "vault.meta.db"];

pub struct CreateStaging {
    root: PathBuf,
    dir: PathBuf,
}

impl CreateStaging {
    pub fn begin(root: &Path) -> Result<Self> {
        let dir = root.join(DIR);
        if dir.exists() {
            return Err(VaultError::Internal(
                "unfinished vault creation was not settled".into(),
            ));
        }
        crate::failpoint::hit("staging.create")?;
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            root: root.to_owned(),
            dir,
        })
    }

    pub fn meta_path(&self) -> PathBuf {
        self.dir.join("vault.meta.db")
    }

    pub fn records_path(&self) -> PathBuf {
        self.dir.join("vault.records.db")
    }

    pub fn web_path(&self) -> PathBuf {
        self.dir.join("vault.web.db")
    }

    /// Опубликовать сборку. Все соединения с её базами должны быть закрыты.
    ///
    /// После переноса метаданных хранилище создано; неудачная уборка каталога
    /// сборки создание не отменяет и доделывается при следующем старте.
    pub fn commit(self, op_id: &str) -> Result<()> {
        write_marker(&self.dir, op_id)?;
        for name in FILES {
            crate::storage::restore::durable_replace(&self.dir.join(name), &self.root.join(name))?;
        }
        if let Err(error) = remove_dir(&self.dir) {
            log::warn!("create staging: cleanup deferred: {error}");
        }
        Ok(())
    }
}

/// Довести незавершённое создание: опубликованное — дочистить, не
/// опубликованное — откатить. Вызывается при старте и при ошибке создания;
/// без каталога сборки ничего не делает.
pub(crate) fn recover(root: &Path) -> Result<()> {
    let dir = root.join(DIR);
    if !dir.exists() {
        return Ok(());
    }
    let marker = read_marker(&dir)?;
    if let Some(op_id) = &marker {
        if published(root, op_id) {
            log::info!("create staging: creation was committed, finishing cleanup");
            return remove_dir(&dir);
        }
    }
    if marker.is_some() {
        if root.join(META).exists() {
            log::warn!("create staging: a live vault exists, its files are left intact");
        } else {
            for name in FILES {
                if dir.join(name).exists() {
                    continue; // не перенесён — живой файл с этим именем не наш
                }
                crate::storage::fsio::remove_file_if_exists(&root.join(name))?;
            }
        }
    }
    remove_dir(&dir)
}

/// Метаданные сборки ещё не опубликованы: создание не дошло до commit.
pub(crate) fn meta_unpublished(root: &Path) -> bool {
    root.join(DIR).join(META).exists()
}

/// Commit создания состоялся: метаданные этой операции перенесены в живой
/// каталог.
fn published(root: &Path, op_id: &str) -> bool {
    !meta_unpublished(root) && meta_belongs_to(&root.join(META), op_id)
}

fn meta_belongs_to(path: &Path, op_id: &str) -> bool {
    crate::storage::settle::last_op_id(path)
        .ok()
        .flatten()
        .as_deref()
        == Some(op_id)
}

fn write_marker(dir: &Path, op_id: &str) -> Result<()> {
    crate::failpoint::hit("staging.mark")?;
    crate::storage::fsio::write_atomic(&dir.join(MARKER), op_id.as_bytes())
}

fn read_marker(dir: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(dir.join(MARKER)) {
        Ok(op_id) => Ok(Some(op_id)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn remove_dir(dir: &Path) -> Result<()> {
    crate::failpoint::hit("staging.remove")?;
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
