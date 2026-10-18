//! Создание хранилища.
//!
//! Хранилище собирается целиком во временном каталоге и публикуется одним
//! переносом (см. `storage::create_staging`). TPM-ключ Device Secret
//! записывается в журнал ресурсов ОС до создания. Поэтому сбой на любом шаге
//! оставляет либо полностью созданное хранилище, либо никакого — вместе с
//! TPM-ключом, который удалится при следующем старте.
//!
//! Существующее хранилище создание не трогает: при наличии любого из его
//! файлов операция отказывает до первого побочного эффекта.

use serde::Deserialize;
use tauri::State;

use crate::auth::pin::validate_secret_format;
use crate::crypto::master::{
    generate_master_key, wrap_master_with_pin_params, wrap_master_with_pin_v2_params, MasterKey,
};
use crate::error::{Result, VaultError};
use crate::state::{AppState, VaultSettings};
use crate::storage::create_staging::CreateStaging;
use crate::storage::db::wrap_dpapi_layer;
use crate::storage::meta_db::MetaDb;
use crate::storage::osjournal::{OsJournal, Resource};
use crate::storage::records_db::RecordsDb;

use crate::commands::vault::helpers::open_session;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultCreateInput {
    /// PIN (с TPM 2.0) либо мастер-пароль (без TPM).
    pub pin: String,
    /// Сразу включить Windows Hello как второй фактор.
    pub use_windows_hello: bool,
    pub autolock_seconds: Option<u32>,
    pub clipboard_clear_seconds: Option<u32>,
}

/// Доли Шамира, которые пользователь обязан сохранить сам.
/// Доля A остаётся на устройстве под DPAPI и наружу не выдаётся.
#[derive(Debug, serde::Serialize)]
pub struct VaultCreateOutput {
    /// Поколение восстановления: его подтверждает `recovery_acknowledge`,
    /// когда пользователь сохранил обе доли.
    pub recovery_generation: u64,
    /// Для USB-носителя.
    pub recovery_share_b_hex: String,
    /// Для бумажной копии.
    pub recovery_share_c_hex: String,
}

#[tauri::command]
pub async fn vault_create(
    input: VaultCreateInput,
    state: State<'_, AppState>,
) -> Result<VaultCreateOutput> {
    create_vault(&state, input).await
}

/// Собранное, но ещё не опубликованное хранилище.
struct Staged {
    output: VaultCreateOutput,
    master: MasterKey,
    integrity_key: zeroize::Zeroizing<[u8; 32]>,
    settings: VaultSettings,
}

pub(crate) async fn create_vault(
    state: &AppState,
    input: VaultCreateInput,
) -> Result<VaultCreateOutput> {
    let _auth_flow = state.auth_flow.lock().await;
    log::info!(
        "vault_create: start (use_hello={})",
        input.use_windows_hello
    );

    let tpm_supported = state.os.tpm_supported();
    validate_secret_format(&input.pin, tpm_supported)?;
    let present = [state.meta_path(), state.records_path(), state.web_path()]
        .iter()
        .any(|path| path.exists());
    if present {
        return Err(VaultError::BadInput(
            "Хранилище уже создано. Используйте разблокировку.".into(),
        ));
    }

    let mut journal = OsJournal::begin(&state.data_dir, &state.os)?;
    let staged = match stage_and_publish(state, &input, tpm_supported, &mut journal).await {
        Ok(staged) => {
            journal.finish(&state.os, &state.data_dir);
            staged
        }
        Err(error) => {
            log::error!("vault_create FAILED: {error}");
            // Каталог сборки откатывается, созданный TPM-ключ удаляется.
            // Если отказ был смертью процесса, то же сделает следующий старт.
            if let Err(cleanup) = crate::storage::create_staging::recover(&state.data_dir) {
                log::warn!("vault_create: staging cleanup deferred: {cleanup}");
            }
            journal.finish(&state.os, &state.data_dir);
            return Err(error);
        }
    };
    log::info!("vault_create: published");

    let Staged {
        output,
        master,
        integrity_key,
        mut settings,
    } = staged;

    // Hello — дополнительный фактор своей собственной операцией: хранилище уже
    // создано, и неудача включения не должна его отменять.
    if input.use_windows_hello && state.os.hello_supported() {
        match crate::commands::settings::enable_hello(state, &integrity_key).await {
            Ok(()) => settings.use_windows_hello = true,
            Err(error) => log::warn!("vault_create: Hello enrollment failed: {error}"),
        }
    }

    *state.settings.lock() = settings;
    // Доли уже созданы и должны дойти до пользователя, поэтому сбой открытия
    // сессии не превращается в ошибку создания: войти можно по PIN.
    match open_session(state, master, integrity_key) {
        // PIN задан только что: мастер создания может сразу отказаться от
        // восстановления без повторного ввода PIN.
        Ok(()) => crate::commands::security::grant_after_proof(
            state,
            crate::commands::security::SecurityAction::DisableRecovery,
        ),
        Err(error) => log::warn!("vault_create: session not opened after creation: {error}"),
    }
    Ok(output)
}

async fn stage_and_publish(
    state: &AppState,
    input: &VaultCreateInput,
    tpm_supported: bool,
    journal: &mut OsJournal,
) -> Result<Staged> {
    let staging = CreateStaging::begin(&state.data_dir)?;
    let params = crate::crypto::new_wrap_params();
    let master = generate_master_key();

    // С TPM 2.0 мастер-ключ дополнительно привязан к устройству через Device
    // Secret; без TPM защита держится только на длине мастер-пароля.
    let (wrapped, device_secret_data) = if tpm_supported {
        let name = state.os.tpm_new_key_name();
        journal.will_create(Resource::Tpm { name: name.clone() })?;
        let os = state.os.clone();
        let credential = crate::blocking::run(move || os.tpm_create_device_key(&name))
            .await
            .map_err(|_| VaultError::TpmUnavailable)?;
        let (device_secret, data) = crate::crypto::device_secret::generate_and_encrypt(
            &credential.name,
            &credential.signature,
        )?;
        let wrapped =
            wrap_master_with_pin_v2_params(&master, input.pin.as_bytes(), &device_secret, params)?;
        (wrapped, Some(data))
    } else {
        (
            wrap_master_with_pin_params(&master, input.pin.as_bytes(), params)?,
            None,
        )
    };

    let mut dpapi_entropy = zeroize::Zeroizing::new([0u8; 32]);
    crate::crypto::rng::fill(dpapi_entropy.as_mut_slice());
    let stored = wrap_dpapi_layer(&wrapped, &*dpapi_entropy)?;

    let mut integrity_key = zeroize::Zeroizing::new([0u8; 32]);
    crate::crypto::rng::fill(integrity_key.as_mut_slice());
    let integrity_key_dpapi =
        crate::windows_api::dpapi::protect_with_entropy(&integrity_key[..], &*dpapi_entropy)?;
    // Внешний checkpoint пишется ещё при сборке: без commit его удалит журнал.
    journal.will_create(Resource::Checkpoint {
        id: crate::storage::meta_db::crud::checkpoint_id(&integrity_key),
    })?;

    let settings = VaultSettings {
        autolock_seconds: input.autolock_seconds.unwrap_or(300),
        clipboard_clear_seconds: input.clipboard_clear_seconds.unwrap_or(10),
        require_auth_for_copy: false,
        use_windows_hello: false,
    };

    let generation = 1u64;
    let (shares, recovery_wrapped_master) =
        crate::commands::recovery::create_recovery_generation(&master, generation)?;
    let (share_b, share_c) = (&shares[0], &shares[1]);

    {
        let db = MetaDb::open_staged(&staging.meta_path(), &state.data_dir)?;
        db.vault_create(
            &stored,
            settings.autolock_seconds,
            settings.clipboard_clear_seconds,
            &integrity_key_dpapi,
            &integrity_key,
            &*dpapi_entropy,
            Some(journal.op_id()),
        )?;
        if let Some(data) = device_secret_data {
            db.save_device_secret(&integrity_key, &data.tpm_key_name, &data.encrypted_blob)?;
        }
        db.save_argon2_params(&integrity_key, params.m_cost, params.t_cost, params.p_cost)?;
        db.replace_recovery(&integrity_key, generation, &recovery_wrapped_master)?;
    }

    // Базы записей создаются пустыми тем же ключом, что будет у сессии.
    let records_key = master.with_decrypted(crate::storage::records_db::derive_sqlcipher_key)?;
    drop(RecordsDb::open(&staging.records_path(), &records_key)?);
    let web_key = master.with_decrypted(crate::storage::records_db::derive_web_sqlcipher_key)?;
    drop(RecordsDb::open(&staging.web_path(), &web_key)?);

    staging.commit(journal.op_id())?;

    Ok(Staged {
        output: VaultCreateOutput {
            recovery_generation: generation,
            recovery_share_b_hex: format!("{}|{}", share_b.x, hex::encode(&share_b.y)),
            recovery_share_c_hex: format!("{}|{}", share_c.x, hex::encode(&share_c.y)),
        },
        master,
        integrity_key,
        settings,
    })
}
