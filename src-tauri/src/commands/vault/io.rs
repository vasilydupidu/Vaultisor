#![allow(unused_imports)]
use std::time::Instant;

use serde::Deserialize;
use tauri::State;
use zeroize::Zeroize;

use crate::auth::pin::validate_pin_format;
use crate::crypto::kdf;
use crate::crypto::master::{
    generate_master_key, unwrap_master_with_pin, unwrap_master_with_pin_v2, wrap_master_with_pin,
    wrap_master_with_pin_v2,
};
use crate::crypto::shamir::split_secret;
use crate::error::{Result, VaultError};
use crate::state::{AppState, SessionState, VaultSettings};
use crate::storage::db::{unwrap_dpapi_layer, wrap_dpapi_layer};
use crate::storage::meta_db::MetaDb;
use crate::storage::records_db::{derive_sqlcipher_key, RecordsDb};

use super::*;

/// Экспорт хранилища: копирует ОБА файла (meta + records) в .vault-bundle.
/// Формат бандла: tar-архив с двумя файлами внутри (или просто два рядом
/// расположенных файла с расширением .meta и .records). Для простоты —
/// один tar-файл, без сжатия.
#[derive(Debug, Deserialize)]
pub struct ExportInput {
    pub target_path: String,
}

#[tauri::command]
pub fn vault_export(input: ExportInput, state: State<'_, AppState>) -> Result<()> {
    // HIGH-RES-01: требуем разблокированную сессию.
    // Без проверки злонамеренный JS мог экспортировать БД без ввода PIN —
    // и хотя файл бесполезен без master_key (DPAPI-защита), при компрометации
    // Shamir-долей атакующий получит доступ к содержимому.
    // AUDIT M5: сначала авто-блокировка по простою.
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    let session = state.session.lock();
    if !session.is_unlocked() {
        return Err(VaultError::Locked);
    }
    drop(session);
    let meta_src = state.meta_path();
    let records_src = state.records_path();
    let web_src = state.web_path();
    if !meta_src.exists() || !records_src.exists() || !web_src.exists() {
        return Err(VaultError::NotInitialized);
    }
    let target = validate_user_path(&input.target_path)?;
    // См. импорт: поддержка VLT2 формата
    let meta_bytes = std::fs::read(&meta_src)?;
    let records_bytes = std::fs::read(&records_src)?;
    let web_bytes = std::fs::read(&web_src)?;
    let mut out = Vec::with_capacity(12 + meta_bytes.len() + records_bytes.len() + web_bytes.len() + 12);
    out.extend_from_slice(b"VLT2");
    out.extend_from_slice(&(meta_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&meta_bytes);
    out.extend_from_slice(&(records_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&records_bytes);
    out.extend_from_slice(&(web_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&web_bytes);
    std::fs::write(target, &out)?;
    log::info!(
        "vault_export: succeeded ({} + {} + {} bytes)",
        meta_bytes.len(),
        records_bytes.len(),
        web_bytes.len()
    );
    Ok(())
}

/// Импорт ранее экспортированной БД. Доступен только если локальной БД
/// ещё нет (т.е. на чистой инсталляции после онбординга или до него).
#[derive(Debug, Deserialize)]
pub struct ImportInput {
    pub source_path: String,
}

#[tauri::command]
pub fn vault_import(input: ImportInput, state: State<'_, AppState>) -> Result<()> {
    let meta_dst = state.meta_path();
    let records_dst = state.records_path();
    let web_dst = state.web_path();
    if meta_dst.exists() || records_dst.exists() || web_dst.exists() {
        return Err(VaultError::BadInput(
            "Хранилище уже существует. Удалите ./vault/ перед импортом.".into(),
        ));
    }
    let source = validate_user_path(&input.source_path)?;
    if !source.exists() {
        return Err(VaultError::BadInput(
            "Файл импорта не найден".into(),
        ));
    }

    let bundle = std::fs::read(source)?;
    std::fs::create_dir_all(&state.data_dir)?;

    // L-03: единый разбор бандла (VLT2: meta+records+web, VLT1: meta+records)
    // через parse_bundle — тот же код, что и в vault_restore, вместо дубля.
    let (meta_bytes, records_bytes, web_bytes) = parse_bundle(&bundle)?;
    std::fs::write(&meta_dst, &meta_bytes)?;
    std::fs::write(&records_dst, &records_bytes)?;
    if let Some(w) = &web_bytes {
        std::fs::write(&web_dst, w)?;
    }

    let res = MetaDb::open(&meta_dst).and_then(|db| db.vault_initialized());
    match res {
        Ok(true) => {
            log::info!("vault_import: succeeded");
            Ok(())
        }
        Ok(false) => {
            let _ = std::fs::remove_file(&meta_dst);
            let _ = std::fs::remove_file(&records_dst);
            let _ = std::fs::remove_file(&web_dst);
            Err(VaultError::BadInput(
                "Бандл не содержит инициализированного vault'а"
                    .into(),
            ))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&meta_dst);
            let _ = std::fs::remove_file(&records_dst);
            let _ = std::fs::remove_file(&web_dst);
            Err(e)
        }
    }
}

/// Разобрать .vault-бандл (VLT2: meta+records+web, VLT1: meta+records).
/// Возвращает (meta, records, Option<web>).
fn parse_bundle(bundle: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Option<Vec<u8>>)> {
    fn corrupt() -> VaultError {
        VaultError::BadInput("Повреждённый бандл".into())
    }
    if bundle.len() < 8 {
        return Err(corrupt());
    }
    // AUDIT L6: читаем length-prefixed чанк с checked-арифметикой — заявленная
    // длина проверяется против остатка буфера через u64/checked_add, без риска
    // переполнения usize на 32-битной цели и OOB-паники на срезе.
    fn read_chunk(b: &[u8], off: usize) -> Result<(Vec<u8>, usize)> {
        let len_end = off.checked_add(4).ok_or_else(corrupt)?;
        if b.len() < len_end {
            return Err(corrupt());
        }
        let len = u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]) as usize;
        let data_end = len_end.checked_add(len).ok_or_else(corrupt)?;
        if b.len() < data_end {
            return Err(corrupt());
        }
        Ok((b[len_end..data_end].to_vec(), data_end))
    }

    match &bundle[0..4] {
        b"VLT2" => {
            let (meta, off) = read_chunk(bundle, 4)?;
            let (records, off) = read_chunk(bundle, off)?;
            let (web, _off) = read_chunk(bundle, off)?;
            Ok((meta, records, Some(web)))
        }
        b"VLT1" => {
            let (meta, off) = read_chunk(bundle, 4)?;
            let (records, _off) = read_chunk(bundle, off)?;
            Ok((meta, records, None))
        }
        _ => Err(VaultError::BadInput(
            "Файл не является бандлом Vaultisor".into(),
        )),
    }
}

/// Восстановление из .vault ПОВЕРХ существующего хранилища (вызывается из
/// Настроек → Резервная копия). В отличие от vault_import (только чистая
/// установка) здесь vault уже есть, поэтому:
///   1) блокируем сессию (закрываем SQLCipher-хэндлы, затираем master-key);
///   2) делаем pre-restore копии текущих файлов (*.prerestore) для отката;
///   3) разворачиваем бандл и валидируем; при ошибке — откат.
/// После успеха фронт перезагружается; вход — PIN этого устройства (если копия
/// с него) или Shamir (если копия с другого ПК — device-bound слои не подойдут).
#[tauri::command]
pub fn vault_restore(input: ImportInput, state: State<'_, AppState>) -> Result<()> {
    let source = validate_user_path(&input.source_path)?;
    if !source.exists() {
        return Err(VaultError::BadInput("Файл восстановления не найден".into()));
    }
    let bundle = std::fs::read(source)?;
    let (meta_bytes, records_bytes, web_bytes) = parse_bundle(&bundle)?;

    let meta_dst = state.meta_path();
    let records_dst = state.records_path();
    let web_dst = state.web_path();

    // AUDIT H4: перезапись СУЩЕСТВУЮЩЕГО хранилища — деструктивная операция.
    // Требуем разблокированную сессию (доказательство PIN), как export/backup.
    // Свежая машина (хранилища ещё нет) использует vault_import — там сессии нет
    // и терять нечего. Здесь же, если vault уже инициализирован, без PIN
    // перезаписать его нельзя — защита от вредоносного IPC-вызова.
    let existing = meta_dst.exists()
        && MetaDb::open(&meta_dst)
            .and_then(|db| db.vault_initialized())
            .unwrap_or(false);
    if existing {
        let session = state.session.lock();
        if !session.is_unlocked() {
            return Err(VaultError::Locked);
        }
        drop(session);
    }

    // Блокируем сессию — освобождаем файловые хэндлы и затираем ключ.
    state.lock();

    // AUDIT H4: таймстамп-копии текущих файлов (НЕ перезаписывают друг друга),
    // чтобы повторный restore не затёр единственный откат.
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let bak_ext = format!("prerestore-{ts}");
    let targets = [&meta_dst, &records_dst, &web_dst];
    for p in targets {
        if p.exists() {
            let _ = std::fs::copy(p, p.with_extension(&bak_ext));
        }
    }

    // AUDIT M7: пишем во временные файлы и атомарно переименовываем. Новый meta
    // валидируется на temp-файле ДО подмены — бракованный бандл не тронет
    // оригинал. rename на одном томе атомарен, поэтому нет окна «новый meta +
    // старый records».
    let apply = (|| -> Result<()> {
        let meta_tmp = meta_dst.with_extension("restore-tmp");
        let records_tmp = records_dst.with_extension("restore-tmp");
        let web_tmp = web_dst.with_extension("restore-tmp");

        std::fs::write(&meta_tmp, &meta_bytes)?;
        std::fs::write(&records_tmp, &records_bytes)?;
        if let Some(w) = &web_bytes {
            std::fs::write(&web_tmp, w)?;
        }

        // Валидация нового meta на temp-файле до подмены.
        if !MetaDb::open(&meta_tmp)?.vault_initialized()? {
            let _ = std::fs::remove_file(&meta_tmp);
            let _ = std::fs::remove_file(&records_tmp);
            let _ = std::fs::remove_file(&web_tmp);
            return Err(VaultError::BadInput(
                "Бандл не содержит инициализированного vault".into(),
            ));
        }

        std::fs::rename(&meta_tmp, &meta_dst)?;
        std::fs::rename(&records_tmp, &records_dst)?;
        if web_bytes.is_some() {
            std::fs::rename(&web_tmp, &web_dst)?;
        }
        Ok(())
    })();

    if apply.is_err() {
        // Откат из таймстамп-копий.
        for p in targets {
            let bak = p.with_extension(&bak_ext);
            if bak.exists() {
                let _ = std::fs::copy(&bak, p);
            }
        }
    }
    apply?;
    log::warn!("vault_restore: vault replaced from backup file (security event)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_vlt2(meta: &[u8], records: &[u8], web: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"VLT2");
        b.extend_from_slice(&(meta.len() as u32).to_le_bytes());
        b.extend_from_slice(meta);
        b.extend_from_slice(&(records.len() as u32).to_le_bytes());
        b.extend_from_slice(records);
        b.extend_from_slice(&(web.len() as u32).to_le_bytes());
        b.extend_from_slice(web);
        b
    }

    #[test]
    fn parse_bundle_vlt2_roundtrip() {
        let bundle = build_vlt2(b"META-BYTES", b"RECORDS-BYTES", b"WEB-BYTES");
        let (m, r, w) = parse_bundle(&bundle).unwrap();
        assert_eq!(m, b"META-BYTES");
        assert_eq!(r, b"RECORDS-BYTES");
        assert_eq!(w.unwrap(), b"WEB-BYTES");
    }

    #[test]
    fn parse_bundle_rejects_bad_magic() {
        let mut b = build_vlt2(b"M", b"R", b"W");
        b[0] = b'X';
        assert!(parse_bundle(&b).is_err());
    }

    #[test]
    fn parse_bundle_rejects_truncated() {
        let bundle = build_vlt2(b"META", b"RECORDS", b"WEB");
        let truncated = &bundle[..bundle.len() - 5];
        assert!(parse_bundle(truncated).is_err());
    }

    #[test]
    fn parse_bundle_rejects_oversized_length() {
        // Заявленная meta_len = u32::MAX выходит за буфер → должно отвергнуться,
        // а не паниковать на срезе (AUDIT: bounds перед slicing).
        let mut b = build_vlt2(b"META", b"RECORDS", b"WEB");
        b[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_bundle(&b).is_err());
    }

    #[test]
    fn parse_bundle_rejects_too_short() {
        assert!(parse_bundle(b"VLT").is_err());
        assert!(parse_bundle(&[]).is_err());
    }
}

