// Сохранение/чтение Shamir-доли на USB.
//
// Формат файла:
//   "vaultisor-share-v1\n"
//   "x: <i>\n"
//   "y: <hex>\n"
// Первая строка — magic (для валидации формата).
//
// Файл — текстовый, чтобы в случае повреждения USB пользователь мог
// прочитать содержимое глазами и ввести вручную.

use std::path::Path;

use crate::crypto::shamir::Share;
use crate::error::{Result, VaultError};

const MAGIC: &str = "vaultisor-share-v1";

/// Записать долю в файл, выбранный в системном диалоге сохранения.
///
/// Существующий файл заменяется: согласие на замену пользователь уже дал в
/// диалоге, а при перевыпуске долей старый файл и должен смениться — прежнее
/// поколение недействительно. Замена атомарная (временный файл рядом, fsync,
/// замена записи каталога), поэтому подмена пути между выбором и записью не
/// усечёт чужой файл, а сбой оставит старую или новую долю целиком.
pub fn write_share_file(path: &Path, share: &Share) -> Result<()> {
    let body = format!("{MAGIC}\n{}|{}\n", share.x, hex::encode(&share.y));
    crate::storage::fsio::write_atomic(path, body.as_bytes())
}

/// Файл с долей — несколько десятков байт; всё, что больше, — не он.
const SHARE_FILE_MAX: u64 = 64 * 1024;

pub fn read_share_file(path: &Path) -> Result<Share> {
    let raw = crate::commands::file_grants::read_regular_file_limited(
        path,
        SHARE_FILE_MAX,
        "Файл части восстановления",
    )?;
    let s = String::from_utf8(raw).map_err(|_| {
        VaultError::BadInput("Файл части восстановления не является текстом".into())
    })?;
    parse_share_text(&s)
}

pub fn parse_share_text(s: &str) -> Result<Share> {
    let mut x: Option<u8> = None;
    let mut y: Option<Vec<u8>> = None;

    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() || line == MAGIC {
            continue;
        }
        if line.contains('|') {
            if let Ok(share) = parse_line_pipe(line) {
                x = Some(share.x);
                y = Some(share.y.clone());
            }
        } else if let Some(rest) = line.strip_prefix("x:") {
            x = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("y:") {
            y = hex::decode(rest.trim()).ok();
        }
    }

    let x = x.ok_or_else(|| VaultError::Recovery("USB: нет поля x".into()))?;
    let y = y.ok_or_else(|| VaultError::Recovery("USB: нет поля y".into()))?;
    if x == 0 {
        return Err(VaultError::Recovery("USB: x=0 запрещён".into()));
    }
    if y.is_empty() {
        return Err(VaultError::Recovery("USB: пустой y".into()));
    }
    Ok(Share { x, y })
}

fn parse_line_pipe(line: &str) -> Result<Share> {
    let mut parts = line.splitn(2, '|');
    let x_str = parts
        .next()
        .ok_or_else(|| VaultError::Recovery("bad format".into()))?;
    let y_hex = parts
        .next()
        .ok_or_else(|| VaultError::Recovery("bad format".into()))?;
    let x: u8 = x_str
        .trim()
        .parse()
        .map_err(|_| VaultError::Recovery("bad x".into()))?;
    let y = hex::decode(y_hex.trim()).map_err(|_| VaultError::Recovery("bad y".into()))?;
    Ok(Share { x, y })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn write_and_read_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("share.vss");
        let s = Share {
            x: 2,
            y: vec![0xAA, 0xBB, 0xCC, 0xDD],
        };
        write_share_file(&path, &s).unwrap();
        let restored = read_share_file(&path).unwrap();
        assert_eq!(restored.x, s.x);
        assert_eq!(restored.y, s.y);
    }

    #[test]
    fn share_file_over_the_limit_or_not_a_file_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("share.vss");
        let share = Share {
            x: 3,
            y: vec![9; 32],
        };
        write_share_file(&path, &share).unwrap();
        assert_eq!(read_share_file(&path).unwrap().y, share.y);

        let huge = dir.path().join("huge.vss");
        let file = std::fs::File::create(&huge).unwrap();
        file.set_len(SHARE_FILE_MAX + 1).unwrap();
        drop(file);
        assert!(matches!(
            read_share_file(&huge),
            Err(VaultError::BadInput(_))
        ));

        assert!(matches!(
            read_share_file(dir.path()),
            Err(VaultError::BadInput(_))
        ));

        let binary = dir.path().join("binary.vss");
        std::fs::write(&binary, [0xff, 0xfe, 0x00, 0x80]).unwrap();
        assert!(matches!(
            read_share_file(&binary),
            Err(VaultError::BadInput(_))
        ));
        assert_eq!(SHARE_FILE_MAX, 64 * 1024);
    }

    #[test]
    fn new_generation_replaces_the_old_share_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("share.vss");
        let old = Share {
            x: 2,
            y: vec![1, 2, 3],
        };
        let new = Share {
            x: 2,
            y: vec![4, 5, 6],
        };
        write_share_file(&path, &old).unwrap();
        write_share_file(&path, &new).unwrap();
        assert_eq!(read_share_file(&path).unwrap().y, new.y);
        let leftovers = std::fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(leftovers, 1, "временный файл не должен оставаться");
    }
}
