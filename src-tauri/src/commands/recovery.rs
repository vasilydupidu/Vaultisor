// Восстановление: запись доли на USB, восстановление по двум долям.

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::crypto::master::{wrap_master_with_pin, wrap_master_with_pin_v2};
use crate::crypto::shamir::{combine_shares, Share};
use crate::error::{Result, VaultError};
use crate::recovery::usb;
use crate::state::AppState;
use crate::storage::meta_db::MetaDb;

/// share_b_hex — формат "X|YYYY..." (см. vault_create).
#[derive(Debug, Deserialize)]
pub struct SaveToUsbInput {
    pub share_b_hex: String,
    /// Полный путь к файлу на USB-носителе.
    pub usb_path: String,
}

#[tauri::command]
pub fn recovery_save_to_usb(input: SaveToUsbInput) -> Result<()> {
    let share = parse_share_hex(&input.share_b_hex)?;
    let path = validate_user_path(&input.usb_path)?;
    usb::write_share_file(path, &share)?;
    log::info!("recovery_save_to_usb: ok");
    Ok(())
}

/// Валидация пути от пользователя — защита от path traversal.
fn validate_user_path(p: &str) -> Result<&std::path::Path> {
    let path = std::path::Path::new(p);
    if !path.is_absolute() {
        return Err(VaultError::BadInput("Путь должен быть абсолютным".into()));
    }
    use std::path::Component;
    for comp in path.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(VaultError::BadInput(
                "Путь содержит запрещённые сегменты ..".into(),
            ));
        }
    }
    // AUDIT M8: отклоняем ЛЮБЫЕ UNC/сетевые/device-пути.
    if p.starts_with(r"\\") {
        return Err(VaultError::BadInput(
            "Сетевые и UNC-пути не поддерживаются".into(),
        ));
    }
    Ok(path)
}

#[derive(Debug, Deserialize)]
pub struct RestoreInput {
    /// Любые две из трёх долей в hex-формате "X|hex".
    pub shares_hex: Vec<String>,
    pub new_pin: String,
}

#[derive(Debug, Serialize)]
pub struct RestoreOutput {
    pub recovered: bool,
}

#[tauri::command]
pub async fn recovery_restore(
    input: RestoreInput,
    state: State<'_, AppState>,
    _app: tauri::AppHandle,
) -> Result<RestoreOutput> {
    use crate::auth::pin::validate_pin_format;
    use crate::crypto::kdf;
    use crate::storage::db::wrap_dpapi_layer;

    // Ветка «TPM 2.0 или мастер-пароль» — та же, что при создании хранилища:
    // с TPM 2.0 восстанавливаем как v2 (PIN + Device Secret), без него — как v1
    // (мастер-пароль ≥15). Это позволяет развернуть бэкап с TPM-машины на машине
    // без TPM 2.0 (и наоборот).
    let tpm_supported = crate::windows_api::cng_hello::is_supported();

    if tpm_supported {
        validate_pin_format(&input.new_pin)?;
    } else if input.new_pin.chars().count() < 15 {
        return Err(VaultError::BadInput(
            "Мастер-пароль должен быть не менее 15 символов".into(),
        ));
    }
    // Требуем минимум ОДНУ введённую пользователем долю: из одной локальной A
    // восстановить нельзя (иначе доступ к устройству = доступ к хранилищу).
    if input.shares_hex.is_empty() {
        return Err(VaultError::Recovery(
            "Введите хотя бы одну часть восстановления (B или C).".into(),
        ));
    }

    // Парсим доли, введённые пользователем.
    let mut shares: Vec<Share> = input
        .shares_hex
        .iter()
        .map(|s| parse_share_hex(s))
        .collect::<Result<Vec<Share>>>()?;

    // Авто-подгрузка локальной доли A (сценарий «забыл PIN» на ТОМ ЖЕ ПК): доля A
    // хранится DPAPI-обёрнутой, поэтому на чужом ПК/учётке не развернётся — тогда
    // молча пропускаем и полагаемся на введённые B+C. Доля A НЕ покидает backend.
    {
        let path = state.meta_path();
        if path.exists() {
            if let Ok(db0) = MetaDb::open(&path) {
                if let Ok(Some((ax, ay_dpapi))) = db0.load_recovery_local() {
                    let ay = crate::windows_api::dpapi::unprotect(&ay_dpapi).ok();
                    if let Some(ay) = ay {
                        if !shares.iter().any(|s| s.x == ax) {
                            shares.push(Share { x: ax, y: ay.to_vec() });
                        }
                    }
                }
            }
        }
    }

    if shares.len() < 2 {
        return Err(VaultError::Recovery(
            "Недостаточно частей восстановления. Доля A с этого ПК недоступна — \
             введите две части (B и C)."
                .into(),
        ));
    }

    // Восстанавливаем master-key.
    let secret = combine_shares(&shares, 2)?;
    if secret.len() != 32 {
        return Err(VaultError::Recovery(
            "Восстановленный ключ имеет некорректную длину".into(),
        ));
    }
    let mut key_buf = [0u8; 32];
    key_buf.copy_from_slice(&secret);
    let mk = crate::crypto::master::MasterKey::new(key_buf);
    {
        use zeroize::Zeroize;
        key_buf.zeroize(); // AUDIT M4: затираем стековую копию master-ключа
    }

    // AUDIT H5: ПРЕЖДЕ чем что-либо пере-запечатывать и удалять долю A,
    // убеждаемся, что собранный master реально открывает существующую
    // records-БД. Иначе неверные доли (например от прежнего экземпляра
    // хранилища) молча «окирпичили» бы базу: старый master записался бы в meta,
    // доля A удалилась бы, а records.db остался бы недоступен. Проверяем ДО
    // дорогой TPM-операции — fail fast, ничего не меняя.
    {
        let records_path = state.records_path();
        if records_path.exists() {
            let opens = mk.with_decrypted(|d| {
                let key = crate::storage::records_db::derive_sqlcipher_key(d)?;
                Ok::<bool, VaultError>(crate::storage::records_db::records_key_opens(
                    &records_path,
                    &key,
                ))
            })?;
            if !opens {
                return Err(VaultError::Recovery(
                    "Части восстановления не подходят к этому хранилищу. Ничего не изменено — \
                     проверьте, что вводите доли именно от этого хранилища."
                        .into(),
                ));
            }
            log::info!("recovery_restore: reconstructed master verified against records.db");
        }
    }

    // Оборачиваем master под режим устройства (см. ветку выше).
    let ds_data: Option<crate::crypto::device_secret::DeviceSecretData>;
    let wrapped;
    if tpm_supported {
        log::info!("recovery_restore: TPM 2.0 → новый Device Secret (v2)");
        let ds_cred = crate::windows_api::cng_hello::create_and_sign_silent(
            crate::crypto::device_secret::DS_KEK_CHALLENGE,
        )
        .await?;
        let (ds, data) = crate::crypto::device_secret::generate_and_encrypt(
            &ds_cred.stored_id,
            &ds_cred.signature,
        )?;
        wrapped = wrap_master_with_pin_v2(&mk, input.new_pin.as_bytes(), &*ds)?;
        ds_data = Some(data);
    } else {
        log::info!("recovery_restore: нет TPM 2.0 → режим мастер-пароля (v1)");
        wrapped = wrap_master_with_pin(&mk, input.new_pin.as_bytes())?;
        ds_data = None;
    }

    let stored = wrap_dpapi_layer(&wrapped)?;
    // AUDIT (pentest P0): не храним Argon2id-хэш PIN (оффлайн-оракул перебора).
    let pin_hash = String::new();

    // Recovery всегда генерирует НОВЫЙ integrity_key, потому что:
    //  - старый integrity_key DPAPI-обёрнут старой машиной (на новой не разворачивается),
    //  - даже если бы он развернулся, сама модель защиты требует ротации
    //    при компрометации устройства.
    let mut integrity_key = zeroize::Zeroizing::new([0u8; 32]);
    crate::crypto::rng::fill(integrity_key.as_mut_slice());
    let integrity_key_dpapi = crate::windows_api::dpapi::protect(&integrity_key[..])?;

    let path = state.meta_path();
    let db = MetaDb::open(&path)?;

    if db.vault_initialized()? {
        // Сначала ставим новый integrity_key — он используется во всех
        // последующих update_meta_secure-вызовах для пересчёта MAC.
        db.set_integrity_key_and_seal(&integrity_key_dpapi, &*integrity_key)?;
        db.update_wrapped_master(&*integrity_key, &stored, &pin_hash)?;
        // Hello-обёртка из старой машины более невалидна — стираем.
        db.clear_hello_wrapped(&*integrity_key)?;
        // TPM-credential из старой машины тоже бесполезен (привязан к чужому TPM).
        // Удаляем его metadata; CNG/WebAuthn/KCM объект чистится по префиксу ниже.
        if let Some(meta) = db.vault_load()? {
            if let Some(old_cred) = meta.tpm_credential_name {
                // Учётные данные Hello всегда создаются как CNG-ключ Platform
                // Crypto Provider (см. cng_hello); прочих типов не бывает.
                let _ = crate::windows_api::cng_hello::delete(&old_cred);
            }
        }
        db.clear_tpm_wrap(&*integrity_key)?;
        // Локальная Shamir-доля A была DPAPI-обёрнута старой машиной — невалидна.
        db.with_conn(|c| {
            c.execute("DELETE FROM recovery_local WHERE id = 1", [])?;
            Ok(())
        })?;
        // Сбросываем счётчик неудачных попыток PIN.
        db.set_failed_attempts(&*integrity_key, 0)?;
    } else {
        // LOW-NEW-01: используем тот же дефолт что и обычный vault_create
        // (5 минут autolock), а не hardcoded 60 сек.
        let defaults = crate::state::VaultSettings::default();
        db.vault_create(
            &stored,
            &pin_hash,
            defaults.autolock_seconds,
            defaults.clipboard_clear_seconds,
            defaults.require_auth_for_copy,
            defaults.use_windows_hello,
            defaults.max_pin_attempts,
            &integrity_key_dpapi,
            &*integrity_key,
        )?;
    }

    // Финализация под режим: v2 → сохраняем Device Secret (ставит crypto_version=2);
    // v1 → переводим в режим мастер-пароля (crypto_version=1, чистим DS/PQ-поля).
    match &ds_data {
        Some(ds) => {
            db.save_device_secret(&*integrity_key, &ds.tpm_key_name, &ds.encrypted_blob)?;
        }
        None => {
            db.set_passphrase_v1(&*integrity_key)?;
        }
    }
    db.save_argon2_params(
        &*integrity_key,
        kdf::ARGON2_M_COST,
        kdf::ARGON2_T_COST,
        kdf::ARGON2_P_COST,
    )?;

    log::warn!("recovery_restore: vault was recovered via Shamir shares (security event)");
    log::info!("recovery_restore: vault re-sealed with new integrity key");

    // НЕ разблокируем сессию автоматически: пусть пользователь
    // войдёт через обычный экран unlock — это очистит флоу.
    Ok(RestoreOutput { recovered: true })
}

#[derive(Debug, Deserialize)]
pub struct LoadFromUsbInput {
    pub usb_path: String,
}

#[derive(Debug, Serialize)]
pub struct ShareReadOutput {
    pub share_hex: String,
}

/// Статус recovery: настроено ли (есть ли локальная часть A в БД).
#[derive(Debug, Serialize)]
pub struct RecoveryStatus {
    pub configured: bool,
}

#[tauri::command]
pub fn recovery_status(state: State<'_, AppState>) -> Result<RecoveryStatus> {
    let path = state.meta_path();
    if !path.exists() {
        return Ok(RecoveryStatus { configured: false });
    }
    let db = MetaDb::open(&path)?;
    let configured = db.load_recovery_local()?.is_some();
    Ok(RecoveryStatus { configured })
}

/// Перегенерировать Shamir 2-of-3 из текущего master-key.
/// Требуется unlocked-сессия. Старая локальная часть перезаписывается.
#[derive(Debug, Serialize)]
pub struct RecoveryRegenerateOutput {
    pub recovery_share_b_hex: String,
    pub recovery_share_c_hex: String,
}

#[tauri::command]
pub fn recovery_regenerate(state: State<'_, AppState>) -> Result<RecoveryRegenerateOutput> {
    use crate::crypto::shamir::split_secret;
    // AUDIT M5: авто-блокировка по простою.
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    let session = state.session.lock();
    let master = match &*session {
        crate::state::SessionState::Unlocked { master_key, .. } => master_key.clone(),
        crate::state::SessionState::Locked => return Err(VaultError::Locked),
    };
    drop(session);

    let path = state.meta_path();
    let db = MetaDb::open(&path)?;

    let shares = master.with_decrypted(|decrypted| {
        split_secret(decrypted, 2, 3)
    })?;
    let share_a = &shares[0];
    let share_b = &shares[1];
    let share_c = &shares[2];

    // Сохраняем долю A локально (DPAPI-обёрнутую на Windows).
    let y_dpapi = crate::windows_api::dpapi::protect(&share_a.y)?;
    db.save_recovery_local(share_a.x, &y_dpapi)?;

    Ok(RecoveryRegenerateOutput {
        recovery_share_b_hex: format!("{}|{}", share_b.x, hex::encode(&share_b.y)),
        recovery_share_c_hex: format!("{}|{}", share_c.x, hex::encode(&share_c.y)),
    })
}

/// Отключить recovery: удалить локальную долю A с этого ПК.
/// ВНИМАНИЕ: это НЕ делает B и C бесполезными — Shamir 2-of-3 восстанавливает
/// любыми 2 долями, т.е. B+C вдвоём всё ещё восстановят vault. Чтобы полностью
/// исключить восстановление, пользователь должен также уничтожить B и C.
/// Требует unlocked-сессию (LOW-05 из security audit).
/// Исключение: на онбординге, когда vault только что создан, у нас уже
/// активная сессия, поэтому ограничение не мешает.
#[tauri::command]
pub fn recovery_disable(state: State<'_, AppState>) -> Result<()> {
    state.touch();
    let session = state.session.lock();
    if !session.is_unlocked() {
        return Err(VaultError::Locked);
    }
    drop(session);
    let path = state.meta_path();
    if !path.exists() {
        return Ok(());
    }
    let db = MetaDb::open(&path)?;
    db.with_conn(|c| {
        c.execute("DELETE FROM recovery_local WHERE id = 1", [])?;
        Ok(())
    })?;
    log::info!("recovery_disable: local share A removed");
    Ok(())
}

#[tauri::command]
pub fn recovery_load_from_usb(input: LoadFromUsbInput) -> Result<ShareReadOutput> {
    let path = validate_user_path(&input.usb_path)?;
    let share = usb::read_share_file(path)?;
    Ok(ShareReadOutput {
        share_hex: format!("{}|{}", share.x, hex::encode(&share.y)),
    })
}

fn parse_share_hex(s: &str) -> Result<Share> {
    let mut parts = s.splitn(2, '|');
    let x_str = parts
        .next()
        .ok_or_else(|| VaultError::Recovery("share format: missing x".into()))?;
    let y_hex = parts
        .next()
        .ok_or_else(|| VaultError::Recovery("share format: missing y".into()))?;
    let x: u8 = x_str
        .trim()
        .parse()
        .map_err(|_| VaultError::Recovery("share format: invalid x".into()))?;
    let y = hex::decode(y_hex.trim())
        .map_err(|_| VaultError::Recovery("share format: bad hex".into()))?;
    Ok(Share { x, y })
}
