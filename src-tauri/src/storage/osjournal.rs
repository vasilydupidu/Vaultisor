//! Журнал внешних ресурсов операции: TPM-ключи, ключи Windows Hello и
//! внешние checkpoint'ы хранилища.
//!
//! Операция, которая создаёт или заменяет ресурс ОС, идёт по схеме
//!
//! ```text
//! begin → will_create(новый) → создать и проверить → retire(старый)
//!       → commit метаданных (last_op_id = op) → mark_committed → cleanup
//! ```
//!
//! После сбоя старт приложения (и начало любой следующей операции) доводит
//! журнал до конца детерминированно:
//! - commit не состоялся → удаляются созданные ресурсы, старые остаются;
//! - commit состоялся → удаляются заменённые ресурсы, новые остаются.
//!
//! Удаления идемпотентны, поэтому повторная очистка после сбоя безопасна.
//!
//! Commit состоялся, если запись помечена `committed` **или** живые
//! метаданные несут `last_op_id` этой операции. Вторая проверка покрывает
//! сбой между commit БД и пометкой журнала; она надёжна, потому что
//! `last_op_id` пишут только журналируемые операции, а каждая из них перед
//! стартом доводит до конца все незавершённые записи.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Result, VaultError};
use crate::platform::Os;

const DIR: &str = ".os-journal";

/// Внешний ресурс ОС.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Resource {
    /// TPM-ключ Device Secret по имени (имя выдаётся до создания).
    Tpm { name: String },
    /// Ключ Hello, созданный с этим user.id. Имя credential'а выдаёт
    /// аутентификатор, поэтому до создания известен только user.id.
    HelloUser { user_handle: String },
    /// Существующий ключ Hello по имени — для замены.
    HelloName { name: String },
    /// Внешний checkpoint integrity-ключа (см. `meta_db::crud::checkpoint_id`).
    Checkpoint { id: String },
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Entry {
    op_id: String,
    created: Vec<Resource>,
    retire: Vec<Resource>,
    committed: bool,
}

pub struct OsJournal {
    path: PathBuf,
    entry: Entry,
}

fn dir(root: &Path) -> PathBuf {
    root.join(DIR)
}

impl OsJournal {
    /// Начать операцию. Незавершённые операции прошлых запусков сначала
    /// доводятся до конца — пока `last_op_id` ещё указывает на них.
    pub fn begin(root: &Path, os: &Os) -> Result<Self> {
        crate::storage::settle::settle(root, os)?;
        let op_id = uuid::Uuid::new_v4().to_string();
        let journal = Self {
            path: dir(root).join(format!("{op_id}.json")),
            entry: Entry {
                op_id,
                ..Entry::default()
            },
        };
        journal.persist()?;
        Ok(journal)
    }

    pub fn op_id(&self) -> &str {
        &self.entry.op_id
    }

    /// Записать намерение создать ресурс. Вызывается ДО создания.
    pub fn will_create(&mut self, resource: Resource) -> Result<()> {
        self.entry.created.push(resource);
        self.persist()
    }

    /// Записать ресурс, который станет лишним после commit. Вызывается ДО
    /// commit: удаляется он только если commit состоялся.
    pub fn retire(&mut self, resource: Resource) -> Result<()> {
        self.entry.retire.push(resource);
        self.persist()
    }

    /// Завершить операцию.
    ///
    /// Состоялся ли commit, решает не код возврата операции, а живые
    /// метаданные: защищённая мутация может вернуть ошибку уже после commit
    /// SQLite (не записался якорь), и поверить такой ошибке значило бы удалить
    /// только что созданный живой ключ.
    ///
    /// Ошибки очистки не возвращаются: состояние хранилища уже определено
    /// commit'ом (или его отсутствием), а незавершённая очистка останется в
    /// журнале и будет доведена при следующем старте или операции.
    pub fn finish(mut self, os: &Os, root: &Path) {
        let committed = match crate::storage::settle::is_committed(root, &self.entry.op_id) {
            Ok(committed) => committed,
            Err(error) => {
                log::warn!("os journal: commit state unknown, cleanup deferred: {error}");
                return;
            }
        };
        if committed && !self.entry.committed {
            self.entry.committed = true;
            if let Err(error) = self.persist() {
                log::warn!("os journal: commit mark not persisted: {error}");
                return;
            }
        }
        if let Err(error) = cleanup(&self.path, &self.entry, os, committed) {
            log::warn!("os journal: cleanup deferred to next start: {error}");
        }
    }

    fn persist(&self) -> Result<()> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| VaultError::Internal("os journal path".into()))?;
        std::fs::create_dir_all(parent)?;
        let json = serde_json::to_vec(&self.entry)?;
        crate::failpoint::hit("osjournal.write")?;
        crate::storage::fsio::write_atomic(&self.path, &json)
    }
}

/// Удалить лишние ресурсы и саму запись журнала.
fn cleanup(path: &Path, entry: &Entry, os: &Os, committed: bool) -> Result<()> {
    let root = path
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| VaultError::Internal("os journal path".into()))?;
    let doomed = if committed {
        &entry.retire
    } else {
        &entry.created
    };
    for resource in doomed {
        match resource {
            Resource::Tpm { name } => {
                os.tpm_delete(name)?;
                log::info!("os journal: TPM key removed");
            }
            Resource::HelloName { name } => {
                os.hello_delete(name)?;
                log::info!("os journal: Hello credential removed from Windows passkey store");
            }
            Resource::HelloUser { user_handle } => {
                let handle = decode_handle(user_handle)?;
                for name in os.hello_find(&handle)? {
                    os.hello_delete(&name)?;
                    log::info!("os journal: unused Hello credential removed");
                }
            }
            Resource::Checkpoint { id } => crate::storage::machine_checkpoint::remove(root, id)?,
        }
    }
    crate::storage::fsio::remove_file_if_exists(path)
}

/// Довести до конца все операции из журнала.
///
/// `last_op_id` — идентификатор последней закоммиченной операции в живых
/// метаданных (`None`, если хранилища нет).
pub(crate) fn recover(root: &Path, os: &Os, last_op_id: Option<&str>) -> Result<()> {
    let directory = dir(root);
    if !directory.exists() {
        return Ok(());
    }
    for item in std::fs::read_dir(&directory)? {
        let path = item?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            // Временный файл оборванной записи: замена не произошла.
            crate::storage::fsio::remove_file_if_exists(&path)?;
            continue;
        }
        let entry: Entry =
            serde_json::from_slice(&std::fs::read(&path)?).map_err(|_| VaultError::MetaTampered)?;
        let committed = entry.committed || last_op_id == Some(entry.op_id.as_str());
        cleanup(&path, &entry, os, committed)?;
    }
    Ok(())
}

/// Незавершённых операций нет.
#[cfg(test)]
pub(crate) fn is_empty(root: &Path) -> bool {
    std::fs::read_dir(dir(root))
        .map(|mut entries| entries.next().is_none())
        .unwrap_or(true)
}

pub fn new_user_handle() -> ([u8; 16], Resource) {
    let handle: [u8; 16] = crate::crypto::rng::random_array();
    (
        handle,
        Resource::HelloUser {
            user_handle: hex::encode(handle),
        },
    )
}

fn decode_handle(hex_handle: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(hex_handle).map_err(|_| VaultError::MetaTampered)?;
    bytes.try_into().map_err(|_| VaultError::MetaTampered)
}
