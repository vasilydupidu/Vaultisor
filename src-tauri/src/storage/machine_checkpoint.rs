//! External CurrentUser/device-bound checkpoint. This detects DB/local-sidecar
//! rollback while the external state survives. It is NOT a TPM monotonic counter
//! and does not defend against same-user code forging all DPAPI-protected state.
use crate::error::{Result, VaultError};
use std::path::{Path, PathBuf};

pub(crate) fn path(_vault_root: &Path, id: &str) -> Result<PathBuf> {
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(VaultError::MetaTampered);
    }
    #[cfg(test)]
    let root = _vault_root.join(".test-machine-checkpoints");
    #[cfg(not(test))]
    let root = {
        #[cfg(debug_assertions)]
        if std::env::var_os("VAULTISOR_TEST_CHECKPOINTS").as_deref()
            == Some(std::ffi::OsStr::new("1"))
        {
            _vault_root.join(".test-machine-checkpoints")
        } else {
            production_root()?
        }
        #[cfg(not(debug_assertions))]
        production_root()?
    };
    Ok(root.join(format!("{id}.checkpoint")))
}

#[cfg(not(test))]
fn production_root() -> Result<PathBuf> {
    Ok(PathBuf::from(
        std::env::var_os("LOCALAPPDATA")
            .ok_or_else(|| VaultError::System("LOCALAPPDATA unavailable".into()))?,
    )
    .join("Vaultisor")
    .join("SecurityCheckpoints"))
}

pub(crate) fn read(vault_root: &Path, id: &str) -> Result<Option<Vec<u8>>> {
    let bytes = match std::fs::read(path(vault_root, id)?) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let plain = crate::windows_api::dpapi::unprotect_with_entropy(
        &bytes,
        b"vaultisor:machine-checkpoint:v1",
    )
    .map_err(|_| VaultError::MetaTampered)?;
    if plain.len() <= 64 || &plain[..64] != id.as_bytes() {
        return Err(VaultError::MetaTampered);
    }
    Ok(Some(plain[64..].to_vec()))
}

pub(crate) fn exists(vault_root: &Path, id: &str) -> Result<bool> {
    Ok(path(vault_root, id)?.exists())
}

/// Удалить checkpoint. Идемпотентно: отсутствующий файл — не ошибка.
pub(crate) fn remove(vault_root: &Path, id: &str) -> Result<()> {
    crate::failpoint::hit("checkpoint.remove")?;
    crate::storage::fsio::remove_file_if_exists(&path(vault_root, id)?)
}

pub(crate) fn write(vault_root: &Path, id: &str, checkpoint: &[u8]) -> Result<()> {
    let path = path(vault_root, id)?;
    crate::failpoint::hit("checkpoint.write")?;
    let parent = path.parent().ok_or(VaultError::MetaTampered)?;
    std::fs::create_dir_all(parent)?;
    let mut plain = Vec::with_capacity(64 + checkpoint.len());
    plain.extend_from_slice(id.as_bytes());
    plain.extend_from_slice(checkpoint);
    let sealed = crate::windows_api::dpapi::protect_with_entropy(
        &plain,
        b"vaultisor:machine-checkpoint:v1",
    )?;
    crate::storage::fsio::write_atomic(&path, &sealed)
}
