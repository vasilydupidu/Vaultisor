// Жизненный цикл хранилища: создание, разблокировка, блокировка, смена PIN.
use crate::error::{Result, VaultError};

mod create;
mod unlock;
mod io;
mod lifecycle;
mod helpers;

// Glob-ре-экспорт: тянет публичные команды + их input/output-структуры +
// скрытые элементы, которые генерирует #[tauri::command] (__cmd__*,
// __tauri_command_name_*), нужные generate_handler! в lib.rs. Также покрывает
// pub(crate)-хелперы (TPM_KEK_CHALLENGE, wrap_hello_v2), используемые в
// settings.rs под путём crate::commands::vault::*.
pub use create::*;
pub use unlock::*;
pub use io::*;
pub use lifecycle::*;

/// Валидация пути от пользователя для read/write операций.
/// Защита от path traversal: отвергаем относительные пути и пути с "..".
/// На Windows дополнительно отсекаем UNC-пути (\\?\, \\.\) которые
/// могут указывать на physical devices.
pub(super) fn validate_user_path(p: &str) -> Result<&std::path::Path> {
    let path = std::path::Path::new(p);
    if !path.is_absolute() {
        return Err(VaultError::BadInput(
            "Путь должен быть абсолютным".into(),
        ));
    }
    // Проверяем наличие ".." сегментов (path-traversal атаки).
    use std::path::Component;
    for comp in path.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(VaultError::BadInput(
                "Путь содержит запрещённые сегменты ..".into(),
            ));
        }
    }
    // AUDIT M8: отклоняем ЛЮБЫЕ UNC/сетевые/device-пути (\\?\, \\.\,
    // \\server\share). Раньше пропускались обычные сетевые шары — через них
    // разблокированная сессия могла писать бандл на SMB атакующего.
    if p.starts_with(r"\\") {
        return Err(VaultError::BadInput(
            "Сетевые и UNC-пути не поддерживаются".into(),
        ));
    }
    Ok(path)
}

/// DPAPI-снятие integrity_key. Возвращает DEVICE_MISMATCH при ошибке —
/// это однозначный признак чужой машины (DPAPI работает только в той же
/// учётке Windows, на том же устройстве).
pub(super) fn unwrap_integrity_key(blob: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    let plain =
        crate::windows_api::dpapi::unprotect(blob).map_err(|_| VaultError::DeviceMismatch)?;
    if plain.len() != 32 {
        return Err(VaultError::Crypto("integrity key length".into()));
    }
    let mut k = zeroize::Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&plain);
    Ok(k)
}
