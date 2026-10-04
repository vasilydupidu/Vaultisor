// Восстановление: запись доли на USB, восстановление по двум долям.

use serde::{Deserialize, Serialize};
use tauri::State;
use tauri_plugin_dialog::DialogExt;

use crate::crypto::master::{wrap_master_with_pin_params, wrap_master_with_pin_v2_params};
use crate::crypto::shamir::{combine_shares, Share};
use crate::error::{Result, VaultError};
use crate::recovery::usb;
use crate::state::AppState;
use crate::storage::meta_db::crud::Reseed;
use crate::storage::meta_db::{MetaDb, RecoveryState};
use crate::storage::osjournal::{OsJournal, Resource};

fn recovery_aad(generation: u64) -> Vec<u8> {
    format!("vaultisor:recovery-master-wrap:v2:{generation}").into_bytes()
}

/// Recovery v2 shares reconstruct a random KEK, not the long-lived master key.
/// Replacing the envelope makes the previous share generation unusable against
/// current metadata.
pub fn create_recovery_generation(
    master: &crate::crypto::master::MasterKey,
    generation: u64,
) -> Result<(Vec<Share>, Vec<u8>)> {
    let recovery_key = zeroize::Zeroizing::new(crate::crypto::rng::random_array::<32>());
    let wrapped = master.with_decrypted(|plain| {
        crate::crypto::aead::encrypt(&recovery_key, plain, &recovery_aad(generation))
    })?;
    let shares = crate::crypto::shamir::split_secret(&*recovery_key, 2, 3)?;
    Ok((shares, wrapped.to_bytes()))
}

/// share_hex — формат "X|YYYY..." (см. vault_create).  The destination is
/// selected by the backend-owned native dialog and is represented to the
/// frontend only by a short-lived opaque capability.
#[derive(Debug, Deserialize)]
pub struct PrepareSaveInput {
    pub share_hex: String,
    pub part: String,
}

#[tauri::command]
pub async fn recovery_prepare_save(
    input: PrepareSaveInput,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<String> {
    if state.check_autolock() || !state.session.lock().is_unlocked() {
        return Err(VaultError::Locked);
    }
    let initial = crate::commands::file_grants::session_stamp(&state.session.lock())
        .ok_or(VaultError::Locked)?;
    let share = parse_share_hex(&input.share_hex)?;
    let (file_name, extension) = match input.part.as_str() {
        "B" | "b" => ("vaultisor-recovery-part-b.vss", "vss"),
        "C" | "c" => ("vaultisor-recovery-part-c.txt", "txt"),
        _ => {
            return Err(VaultError::BadInput(
                "Неизвестная часть восстановления".into(),
            ))
        }
    };

    // This dialog runs in the backend process.  No arbitrary path from the
    // webview is accepted by any recovery write command.
    //
    // AUDIT 3.1.1: blocking_save_file ждёт действия пользователя. Вызов прямо
    // в async-команде занимал поток исполнителя tokio на всё время показа
    // диалога; выносим в blocking-пул, как это уже сделано в file_prepare.
    let dialog_app = app.clone();
    let file_name = file_name.to_string();
    let extension = extension.to_string();
    let selected = tauri::async_runtime::spawn_blocking(move || {
        dialog_app
            .dialog()
            .file()
            .set_title("Сохранить часть восстановления")
            .set_file_name(file_name)
            .add_filter("Vaultisor Share", &[extension.as_str()])
            .blocking_save_file()
    })
    .await
    .map_err(|e| VaultError::Internal(format!("save dialog task failed: {e}")))?
    .ok_or_else(|| VaultError::BadInput("Сохранение отменено".into()))?;
    let selected = selected
        .into_path()
        .map_err(|_| VaultError::BadInput("Некорректный путь сохранения".into()))?;
    let canonical = canonical_save_path(&selected)?;
    if canonical.exists() {
        return Err(VaultError::BadInput(
            "Файл уже существует; выберите новое имя в диалоге сохранения".into(),
        ));
    }

    let capability = uuid::Uuid::new_v4().to_string();
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    let session = state.session.lock();
    if crate::commands::file_grants::session_stamp(&session) != Some(initial) {
        return Err(VaultError::Locked);
    }
    let mut pending = state.pending_recovery_saves.lock();
    let now = std::time::Instant::now();
    pending.retain(|_, item| item.expires_at > now);
    pending.insert(
        capability.clone(),
        crate::state::PendingRecoverySave {
            session_started: initial,
            canonical_path: canonical,
            share,
            expires_at: now + std::time::Duration::from_secs(60),
        },
    );
    Ok(capability)
}

#[tauri::command]
pub fn recovery_save_to_usb(capability: String, state: State<'_, AppState>) -> Result<()> {
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    let session = state.session.lock();
    let initial =
        crate::commands::file_grants::session_stamp(&session).ok_or(VaultError::Locked)?;
    let pending = {
        let mut capabilities = state.pending_recovery_saves.lock();
        let now = std::time::Instant::now();
        capabilities.retain(|_, item| item.expires_at > now);
        capabilities.remove(&capability).ok_or_else(|| {
            VaultError::BadInput(
                "Полномочие сохранения недействительно или уже использовано".into(),
            )
        })?
    };
    if pending.session_started != initial {
        return Err(VaultError::Locked);
    }
    usb::write_share_file_exclusive(&pending.canonical_path, &pending.share)?;
    log::info!("recovery_save_to_usb: capability consumed");
    Ok(())
}

fn canonical_save_path(path: &std::path::Path) -> Result<std::path::PathBuf> {
    validate_user_path(path.to_string_lossy().as_ref())?;
    let parent = path
        .parent()
        .ok_or_else(|| VaultError::BadInput("У пути нет каталога назначения".into()))?;
    let parent = std::fs::canonicalize(parent)?;
    let name = path
        .file_name()
        .ok_or_else(|| VaultError::BadInput("Укажите имя файла".into()))?;
    Ok(parent.join(name))
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
) -> Result<RestoreOutput> {
    restore_from_shares(&state, input).await
}

/// Восстановить доступ по долям Шамира: собрать мастер-ключ и заново
/// создать всё, что привязывает хранилище к устройству и PIN.
///
/// ```text
/// блокировка сессии → доли → мастер-ключ → проверка обеих баз
/// → журнал: новый TPM-ключ (создан и проверен), checkpoint нового ключа
///           retire: старый TPM-ключ, ключ Hello, старый checkpoint
/// → одна транзакция reseed (commit) → очистка по журналу
/// ```
///
/// До commit хранилище целиком старое: старый PIN, старые доли и старый
/// TPM-ключ работают. После commit — целиком новое: новый PIN, новый
/// Device Secret, новый integrity-ключ с собственным checkpoint'ом.
/// Промежуточных сочетаний (новая обёртка со старым Device Secret, новый
/// ключ со старой энтропией, ссылка на удалённый TPM-ключ) нет: всё меняется
/// одним commit'ом, старые ресурсы удаляются только после него.
pub(crate) async fn restore_from_shares(
    state: &AppState,
    input: RestoreInput,
) -> Result<RestoreOutput> {
    let _auth_flow = state.auth_flow.lock().await;
    use crate::auth::pin::validate_secret_format;

    // Старый integrity-ключ не должен пережить смену ключей в памяти.
    state.lock();

    // Режим определяется железом ТЕКУЩЕЙ машины, а не исходной: восстановление
    // на машине без TPM 2.0 переводит хранилище в режим мастер-пароля и наоборот.
    let tpm_supported = state.os.tpm_supported();
    let params = crate::crypto::new_wrap_params();
    validate_secret_format(&input.new_pin, tpm_supported)?;
    // Требуем минимум ОДНУ введённую пользователем долю: из одной локальной A
    // восстановить нельзя (иначе доступ к устройству = доступ к хранилищу).
    if input.shares_hex.is_empty() {
        return Err(VaultError::Recovery(
            "Введите хотя бы одну часть восстановления (B или C).".into(),
        ));
    }
    let mut shares: Vec<Share> = input
        .shares_hex
        .iter()
        .map(|s| parse_share_hex(s))
        .collect::<Result<Vec<Share>>>()?;

    let db = MetaDb::open(&state.meta_path())?;
    let old = db.vault_load()?.ok_or(VaultError::NotInitialized)?;
    // Доля A (сценарий «забыл PIN» на том же ПК) хранится под DPAPI: на чужом
    // ПК или в чужой учётной записи не развернётся, тогда нужны B и C.
    if let Some((ax, ay_dpapi)) = &old.recovery_local {
        if let Ok(ay) =
            crate::windows_api::dpapi::unprotect_with_entropy(ay_dpapi, &old.dpapi_entropy)
        {
            if !shares.iter().any(|s| s.x == *ax) {
                shares.push(Share {
                    x: *ax,
                    y: ay.to_vec(),
                });
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
    let envelope = old.recovery_wrapped_master.clone().ok_or_else(|| {
        VaultError::Recovery(
            "Для этого хранилища восстановление не настроено: конверт мастер-ключа отсутствует."
                .into(),
        )
    })?;
    let master = open_envelope(&shares, &envelope, old.recovery_generation)?;

    // Собранный ключ обязан открывать ОБЕ базы, иначе ничего не меняется.
    let records_key = master.with_decrypted(crate::storage::records_db::derive_sqlcipher_key)?;
    let web_key = master.with_decrypted(crate::storage::records_db::derive_web_sqlcipher_key)?;
    for (path, key) in [
        (state.records_path(), &records_key),
        (state.web_path(), &web_key),
    ] {
        if !crate::storage::records_db::records_key_opens(&path, key) {
            return Err(VaultError::Recovery(
                "Части восстановления не подходят к этому хранилищу. Ничего не изменено — \
                 проверьте, что вводите доли именно от этого хранилища."
                    .into(),
            ));
        }
    }
    // Старый integrity-ключ разворачивается только на исходном устройстве:
    // тогда его checkpoint здесь и подлежит удалению после commit.
    let old_key = db.get_integrity_key_dpapi()?.and_then(|blob| {
        crate::commands::vault::unwrap_integrity_key(&blob, &old.dpapi_entropy).ok()
    });
    let old_checkpoint = old_key
        .as_ref()
        .map(|key| crate::storage::meta_db::crud::checkpoint_id(key));
    // Подтверждённые ревизии не уменьшаются и при смене ключа: базы
    // переносятся выше и старого checkpoint'а, и своих фактических ревизий.
    let (confirmed_records, confirmed_web) = old_key
        .as_ref()
        .and_then(|key| db.data_state(key).ok())
        .map(|(records, web)| (records.revision, web.revision))
        .unwrap_or((0, 0));
    drop(db);
    let records_db =
        crate::storage::records_db::RecordsDb::open(&state.records_path(), &records_key)?;
    let web_db = crate::storage::records_db::RecordsDb::open(&state.web_path(), &web_key)?;
    let records_revision = records_db.revision()?.max(confirmed_records) + 1;
    let web_revision = web_db.revision()?.max(confirmed_web) + 1;
    // Ревизия выше старого checkpoint'а безопасна и без commit: для старых
    // метаданных это продолжение вперёд, а не откат.
    records_db.set_revision(records_revision)?;
    web_db.set_revision(web_revision)?;
    let records_state = crate::commands::vault::helpers::data_state(records_db.state()?);
    let web_state = crate::commands::vault::helpers::data_state(web_db.state()?);
    drop((records_db, web_db));

    let mut journal = OsJournal::begin(&state.data_dir, &state.os)?;
    let result = reseed_vault(
        state,
        &mut journal,
        Reseeding {
            master: &master,
            new_pin: &input.new_pin,
            tpm_supported,
            params,
            old: &old,
            old_checkpoint,
            records: records_state,
            web: web_state,
        },
    )
    .await;
    journal.finish(&state.os, &state.data_dir);
    result?;

    log::warn!("recovery_restore: vault was recovered via Shamir shares (security event)");
    // Сессия не открывается: вход новым PIN через обычный экран.
    Ok(RestoreOutput { recovered: true })
}

/// Собрать recovery-KEK из пары долей и открыть им конверт мастер-ключа.
///
/// Схема 2-из-3 не обнаруживает испорченную долю, поэтому перебираются пары,
/// и принимается первая, которая реально открывает конверт.
pub(crate) fn open_envelope(
    shares: &[Share],
    envelope: &[u8],
    generation: u64,
) -> Result<crate::crypto::master::MasterKey> {
    let blob = crate::crypto::aead::EncryptedBlob::from_bytes(envelope)
        .map_err(|_| VaultError::Recovery("Конверт восстановления повреждён".into()))?;
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            let Ok(secret) = combine_shares(&[shares[i].clone(), shares[j].clone()], 2) else {
                continue;
            };
            let Ok(recovery_key) = <[u8; 32]>::try_from(secret.as_slice()) else {
                continue;
            };
            let recovery_key = zeroize::Zeroizing::new(recovery_key);
            let Ok(mut plain) =
                crate::crypto::aead::decrypt(&recovery_key, &blob, &recovery_aad(generation))
            else {
                continue;
            };
            let key = <[u8; 32]>::try_from(plain.as_slice());
            zeroize::Zeroize::zeroize(&mut plain);
            let Ok(mut key) = key else {
                return Err(VaultError::Recovery(
                    "Восстановленный мастер-ключ имеет некорректную длину".into(),
                ));
            };
            let master = crate::crypto::master::MasterKey::new(key);
            zeroize::Zeroize::zeroize(&mut key);
            return Ok(master);
        }
    }
    Err(VaultError::Recovery(
        "Ни одна пара частей не подошла к этому хранилищу. Проверьте, что части от нужного \
         хранилища и текущего поколения восстановления."
            .into(),
    ))
}

struct Reseeding<'a> {
    master: &'a crate::crypto::master::MasterKey,
    new_pin: &'a str,
    tpm_supported: bool,
    params: crate::crypto::kdf::Argon2Params,
    old: &'a crate::storage::meta_db::VaultMetaRow,
    old_checkpoint: Option<String>,
    records: crate::storage::meta_db::crud::DataState,
    web: crate::storage::meta_db::crud::DataState,
}

async fn reseed_vault(
    state: &AppState,
    journal: &mut OsJournal,
    spec: Reseeding<'_>,
) -> Result<()> {
    // Новые ресурсы: создаются и проверяются до commit.
    let (wrapped, device_secret) = if spec.tpm_supported {
        let name = state.os.tpm_new_key_name();
        journal.will_create(Resource::Tpm { name: name.clone() })?;
        let os = state.os.clone();
        let credential = crate::blocking::run(move || os.tpm_create_device_key(&name))
            .await
            .map_err(|_| VaultError::TpmUnavailable)?;
        let (secret, data) = crate::crypto::device_secret::generate_and_encrypt(
            &credential.name,
            &credential.signature,
        )?;
        // Ключ обязан снова подписать challenge и открыть свой Device Secret.
        let os = state.os.clone();
        let name = credential.name.clone();
        let signature = crate::blocking::run(move || os.tpm_sign_device_challenge(&name))
            .await
            .map_err(|_| VaultError::TpmUnavailable)?;
        let reopened = crate::crypto::device_secret::decrypt_device_secret(&data, &signature)?;
        if *reopened != *secret {
            return Err(VaultError::TpmUnavailable);
        }
        let wrapped = wrap_master_with_pin_v2_params(
            spec.master,
            spec.new_pin.as_bytes(),
            &secret,
            spec.params,
        )?;
        (wrapped, Some(data))
    } else {
        (
            wrap_master_with_pin_params(spec.master, spec.new_pin.as_bytes(), spec.params)?,
            None,
        )
    };

    let dpapi_entropy: [u8; 32] = crate::crypto::rng::random_array();
    let stored = crate::storage::db::wrap_dpapi_layer(&wrapped, &dpapi_entropy)?;
    let integrity_key = zeroize::Zeroizing::new(crate::crypto::rng::random_array::<32>());
    let integrity_key_dpapi =
        crate::windows_api::dpapi::protect_with_entropy(&integrity_key[..], &dpapi_entropy)?;
    journal.will_create(Resource::Checkpoint {
        id: crate::storage::meta_db::crud::checkpoint_id(&integrity_key),
    })?;

    // Старые ресурсы станут лишними только после commit.
    if let Some(name) = &spec.old.device_secret_tpm_name {
        journal.retire(Resource::Tpm { name: name.clone() })?;
    }
    if let Some(name) = &spec.old.hello_key_credential_name {
        journal.retire(Resource::HelloName { name: name.clone() })?;
    }
    if let Some(id) = spec.old_checkpoint {
        journal.retire(Resource::Checkpoint { id })?;
    }

    MetaDb::open(&state.meta_path())?.reseed(&Reseed {
        integrity_key: &integrity_key,
        integrity_key_dpapi: &integrity_key_dpapi,
        dpapi_entropy: &dpapi_entropy,
        wrapped_master_dpapi: &stored,
        params: spec.params,
        device_secret: device_secret
            .as_ref()
            .map(|data| (data.tpm_key_name.as_str(), data.encrypted_blob.as_slice())),
        op_id: journal.op_id(),
        records: spec.records,
        web: spec.web,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadFromUsbInput {
    pub capability: String,
}

#[derive(Debug, Serialize)]
pub struct ShareReadOutput {
    pub share_hex: String,
}

/// Состояние восстановления для интерфейса.
#[derive(Debug, Serialize)]
pub struct RecoveryStatus {
    pub state: RecoveryState,
    pub generation: u64,
}

#[tauri::command]
pub fn recovery_status(state: State<'_, AppState>) -> Result<RecoveryStatus> {
    if state.check_autolock() || !state.session.lock().is_unlocked() {
        return Err(VaultError::Locked);
    }
    let meta = state
        .open_meta()?
        .vault_load()?
        .ok_or(VaultError::NotInitialized)?;
    Ok(RecoveryStatus {
        state: meta.recovery_state,
        generation: meta.recovery_generation,
    })
}

/// Новый комплект долей. B и C возвращаются только здесь и нигде не
/// сохраняются: если ответ потерян, поколение остаётся `pending`, и при
/// следующем входе будет выдан новый комплект.
#[derive(Debug, Serialize)]
pub struct RecoveryRegenerateOutput {
    pub generation: u64,
    pub recovery_share_b_hex: String,
    pub recovery_share_c_hex: String,
}

#[tauri::command]
pub fn recovery_regenerate(state: State<'_, AppState>) -> Result<RecoveryRegenerateOutput> {
    regenerate_recovery(&state)
}

/// Создать новое поколение: прежнее отзывается тем же commit'ом.
pub(crate) fn regenerate_recovery(state: &AppState) -> Result<RecoveryRegenerateOutput> {
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    // Новые доли — постоянный доступ к хранилищу: выдаются только после
    // свежего подтверждения PIN.
    crate::commands::security::consume(
        state,
        crate::commands::security::SecurityAction::RegenerateRecovery,
    )?;
    let (master, integrity_key) = session_keys(state)?;
    let db = state.open_meta()?;
    let meta = db.vault_load()?.ok_or(VaultError::NotInitialized)?;

    let generation = meta.recovery_generation.saturating_add(1).max(1);
    let (shares, wrapped_master) = create_recovery_generation(&master, generation)?;
    let (share_a, share_b, share_c) = (&shares[0], &shares[1], &shares[2]);
    let y_dpapi = crate::windows_api::dpapi::protect_with_entropy(&share_a.y, &meta.dpapi_entropy)?;
    db.replace_recovery(
        &integrity_key,
        generation,
        &wrapped_master,
        share_a.x,
        &y_dpapi,
    )?;
    log::info!("recovery_regenerate: generation {generation} created, awaiting acknowledgement");
    Ok(RecoveryRegenerateOutput {
        generation,
        recovery_share_b_hex: format!("{}|{}", share_b.x, hex::encode(&share_b.y)),
        recovery_share_c_hex: format!("{}|{}", share_c.x, hex::encode(&share_c.y)),
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcknowledgeInput {
    pub generation: u64,
}

/// Пользователь подтвердил, что сохранил доли B и C этого поколения.
#[tauri::command]
pub fn recovery_acknowledge(input: AcknowledgeInput, state: State<'_, AppState>) -> Result<()> {
    acknowledge_recovery(&state, input.generation)
}

pub(crate) fn acknowledge_recovery(state: &AppState, generation: u64) -> Result<()> {
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    let (_, integrity_key) = session_keys(state)?;
    state
        .open_meta()?
        .acknowledge_recovery(&integrity_key, generation)?;
    log::info!("recovery_acknowledge: generation {generation} is active");
    Ok(())
}

/// Отключить восстановление: отозвать поколение, удалить конверт и долю A.
#[tauri::command]
pub fn recovery_disable(state: State<'_, AppState>) -> Result<()> {
    disable_recovery(&state)
}

pub(crate) fn disable_recovery(state: &AppState) -> Result<()> {
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    // Повтор после потерянного ответа: уже выключено — успех без мутации.
    let current = state
        .open_meta()?
        .vault_load()?
        .ok_or(VaultError::NotInitialized)?;
    if current.recovery_state == RecoveryState::Disabled {
        return Ok(());
    }
    crate::commands::security::consume(
        state,
        crate::commands::security::SecurityAction::DisableRecovery,
    )?;
    let (_, integrity_key) = session_keys(state)?;
    state.open_meta()?.clear_recovery(&integrity_key)?;
    log::info!("recovery_disable: current recovery generation revoked");
    Ok(())
}

fn session_keys(
    state: &AppState,
) -> Result<(
    crate::crypto::master::MasterKey,
    zeroize::Zeroizing<[u8; 32]>,
)> {
    match &*state.session.lock() {
        crate::state::SessionState::Unlocked {
            master_key,
            integrity_key,
            ..
        } => Ok((master_key.clone(), integrity_key.clone())),
        crate::state::SessionState::Locked => Err(VaultError::Locked),
    }
}

#[tauri::command]
pub fn recovery_load_from_usb(
    input: LoadFromUsbInput,
    state: State<'_, AppState>,
) -> Result<ShareReadOutput> {
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    let session = state.session.lock();
    let path = state.file_grants.lock().consume(
        &input.capability,
        crate::commands::file_grants::FileOperation::RecoveryRead,
        crate::commands::file_grants::session_stamp(&session),
    )?;
    let share = usb::read_share_file(&path)?;
    Ok(ShareReadOutput {
        share_hex: format!("{}|{}", share.x, hex::encode(&share.y)),
    })
}

pub(crate) fn parse_share_hex(s: &str) -> Result<Share> {
    let s = s.trim();
    if s.contains("vaultisor-share-v1") || s.contains("x:") {
        return usb::parse_share_text(s);
    }
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
    if x == 0 || y.is_empty() {
        return Err(VaultError::Recovery(
            "share format: invalid share value".into(),
        ));
    }
    Ok(Share { x, y })
}
