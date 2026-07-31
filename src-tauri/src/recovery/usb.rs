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

use std::fs;
use std::path::Path;

use crate::crypto::shamir::Share;
use crate::error::{Result, VaultError};

const MAGIC: &str = "vaultisor-share-v1";

pub fn write_share_file(path: &Path, share: &Share) -> Result<()> {
    let body = format!("{MAGIC}\n{}|{}\n", share.x, hex::encode(&share.y));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, body)?;
    Ok(())
}

pub fn read_share_file(path: &Path) -> Result<Share> {
    let s = fs::read_to_string(path)?;
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
    let x_str = parts.next().ok_or_else(|| VaultError::Recovery("bad format".into()))?;
    let y_hex = parts.next().ok_or_else(|| VaultError::Recovery("bad format".into()))?;
    let x: u8 = x_str.trim().parse().map_err(|_| VaultError::Recovery("bad x".into()))?;
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
}
