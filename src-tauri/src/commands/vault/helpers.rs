use crate::error::{Result, VaultError};
use crate::state::AppState;
use crate::storage::meta_db::crud::DataState;
use crate::storage::meta_db::MetaDb;

/// Загрузить Device Secret: TPM подписывает фиксированный challenge, из подписи
/// выводится KEK, им расшифровывается сохранённый секрет устройства.
///
/// Имя CNG-ключа хранится открытым: это не секрет, защиту даёт неэкспортируемый
/// TPM-ключ.
pub(crate) async fn load_device_secret(
    os: &crate::platform::Os,
    db: &MetaDb,
) -> Result<(
    crate::crypto::device_secret::DeviceSecretData,
    zeroize::Zeroizing<[u8; 32]>,
)> {
    let (tpm_key_name, encrypted_blob) = db
        .get_device_secret()?
        .ok_or_else(|| VaultError::Crypto("Device Secret data missing".into()))?;

    let os = os.clone();
    let name = tpm_key_name.clone();
    let signature = crate::blocking::run(move || os.tpm_sign_device_challenge(&name))
        .await
        .map_err(|_| VaultError::TpmUnavailable)?;

    let data = crate::crypto::device_secret::DeviceSecretData {
        tpm_key_name,
        encrypted_blob,
    };
    let secret = crate::crypto::device_secret::decrypt_device_secret(&data, &signature)?;
    Ok((data, secret))
}

pub(crate) async fn load_device_secret_and_unwrap(
    os: &crate::platform::Os,
    db: &MetaDb,
    wrapped: &crate::crypto::master::WrappedKey,
    pin: &[u8],
    params: crate::crypto::kdf::Argon2Params,
) -> Result<crate::crypto::master::MasterKey> {
    let (_data, ds) = load_device_secret(os, db).await?;
    unwrap_master_off_thread(wrapped.clone(), pin, Some(ds), params).await
}

/// Развернуть мастер-ключ, не занимая поток async-рантайма: Argon2id на
/// 512 МиБ держит поток секундами.
pub(crate) async fn unwrap_master_off_thread(
    wrapped: crate::crypto::master::WrappedKey,
    pin: &[u8],
    device_secret: Option<zeroize::Zeroizing<[u8; 32]>>,
    params: crate::crypto::kdf::Argon2Params,
) -> Result<crate::crypto::master::MasterKey> {
    let pin = zeroize::Zeroizing::new(pin.to_vec());
    crate::blocking::run(move || match device_secret {
        Some(ds) => {
            crate::crypto::master::unwrap_master_with_pin_v2_params(&wrapped, &pin, &ds, params)
        }
        None => crate::crypto::master::unwrap_master_with_pin_params(&wrapped, &pin, params),
    })
    .await
}

/// Запечатать мастер-ключ новым секретом вне потока рантайма. Возвращает и
/// параметры Argon2id, под которыми сделана обёртка: сохранять нужно именно их.
pub(crate) async fn wrap_master_off_thread(
    master: crate::crypto::master::MasterKey,
    pin: &[u8],
    device_secret: Option<zeroize::Zeroizing<[u8; 32]>>,
) -> Result<(
    crate::crypto::master::MasterKey,
    crate::crypto::master::WrappedKey,
    crate::crypto::kdf::Argon2Params,
)> {
    let pin = zeroize::Zeroizing::new(pin.to_vec());
    let params = crate::crypto::new_wrap_params();
    crate::blocking::run(move || {
        let wrapped = match device_secret {
            Some(ds) => {
                crate::crypto::master::wrap_master_with_pin_v2_params(&master, &pin, &ds, params)?
            }
            None => crate::crypto::master::wrap_master_with_pin_params(&master, &pin, params)?,
        };
        Ok((master, wrapped, params))
    })
    .await
}

/// Снять DPAPI-слой с обёртки мастер-ключа.
///
/// Fallback «а вдруг слоя нет» удалён: слой ставится всегда при создании
/// хранилища, и его отсутствие означает подмену файла, а не старый формат.
pub(crate) fn unwrap_master_blob(
    wrapped_master_dpapi: &[u8],
    dpapi_entropy: &[u8],
) -> Result<crate::crypto::master::WrappedKey> {
    crate::storage::db::unwrap_dpapi_layer(wrapped_master_dpapi, dpapi_entropy)
        .map_err(|_| VaultError::DeviceMismatch)
}

/// Что делать с базами, которые не совпадают с подтверждённым состоянием.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DataRollback {
    /// Отказать (`DATA_ROLLBACK`). Обычный вход.
    Refuse,
    /// Принять текущие базы как новое состояние: владелец явно решил
    /// продолжить с ними после полной проверки PIN. Решение действует только
    /// для снимка, который ему показали (идентификатор из `DATA_ROLLBACK`).
    Accept { snapshot: String },
}

/// Открыть базы записей и перевести сессию в разблокированное состояние.
pub(crate) fn open_session(
    state: &AppState,
    master: crate::crypto::master::MasterKey,
    integrity_key: zeroize::Zeroizing<[u8; 32]>,
) -> Result<()> {
    open_session_with(state, master, integrity_key, DataRollback::Refuse)
}

/// Идентификатор снимка баз, о котором сообщается владельцу.
fn snapshot_id(records: (u64, [u8; 32]), web: (u64, [u8; 32])) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"vaultisor:rollback-snapshot:v1");
    for (revision, file) in [records, web] {
        digest.update(revision.to_le_bytes());
        digest.update(file);
    }
    hex::encode(&digest.finalize()[..16])
}

/// Совпадает ли база с подтверждённым состоянием.
#[derive(Debug, PartialEq, Eq)]
enum Match {
    /// Та же ревизия и тот же файл (или дайджест ещё не зафиксирован).
    Confirmed,
    /// Ревизия выше: сбой между commit и подтверждением — продолжение.
    Ahead,
    /// Ревизия ниже или та же ревизия с другим файлом (подмена страниц).
    RolledBack,
}

fn compare(current: (u64, [u8; 32]), confirmed: DataState) -> Match {
    let (revision, digest) = current;
    if revision > confirmed.revision {
        Match::Ahead
    } else if revision < confirmed.revision
        || (confirmed.recorded()
            && !bool::from(subtle::ConstantTimeEq::ct_eq(
                &digest[..],
                &confirmed.digest[..],
            )))
    {
        Match::RolledBack
    } else {
        Match::Confirmed
    }
}

/// Открыть сессию, сверив базы с внешним checkpoint'ом.
///
/// База старее подтверждённой или та же ревизия с другим файлом — подложенная
/// копия или подмена страниц: вход отказывает (или, по явному решению
/// владельца для показанного ему снимка, принимает её новым состоянием).
/// База новее — сбой между commit и подтверждением: checkpoint догоняется.
/// После импорта (`data_rebase_pending`) ревизии переносятся вперёд, но
/// только над тем снимком, который был импортирован.
pub(crate) fn open_session_with(
    state: &AppState,
    master: crate::crypto::master::MasterKey,
    integrity_key: zeroize::Zeroizing<[u8; 32]>,
    rollback: DataRollback,
) -> Result<()> {
    let sqlcipher_key = master.with_decrypted(crate::storage::records_db::derive_sqlcipher_key)?;
    let records_db =
        crate::storage::records_db::RecordsDb::open(&state.records_path(), &sqlcipher_key)?;
    let web_sqlcipher_key =
        master.with_decrypted(crate::storage::records_db::derive_web_sqlcipher_key)?;
    let web_db =
        crate::storage::records_db::RecordsDb::open(&state.web_path(), &web_sqlcipher_key)?;

    let meta = state.open_meta()?;
    let row = meta.vault_load()?.ok_or(VaultError::NotInitialized)?;
    let (records_confirmed, web_confirmed) = meta.data_state(&integrity_key)?;
    let (records_now, web_now) = (records_db.state()?, web_db.state()?);

    // Rebase после импорта допустим только над импортированными файлами.
    let imported_intact = match (row.data_rebase_pending, row.imported_snapshot) {
        (true, Some((records, web))) => records_now.1 == records && web_now.1 == web,
        _ => false,
    };
    let rolled_back = compare(records_now, records_confirmed) == Match::RolledBack
        || compare(web_now, web_confirmed) == Match::RolledBack
        || (row.data_rebase_pending && !imported_intact);
    if rolled_back && !imported_intact {
        let snapshot = snapshot_id(records_now, web_now);
        log::error!(
            "open_session: databases do not match the confirmed state (records r{} vs r{}, web r{} vs r{}, snapshot {snapshot})",
            records_now.0,
            records_confirmed.revision,
            web_now.0,
            web_confirmed.revision
        );
        match &rollback {
            DataRollback::Accept { snapshot: accepted } if *accepted == snapshot => {
                log::warn!("open_session: owner accepted snapshot {snapshot} (security event)");
            }
            _ => return Err(VaultError::DataRollback(snapshot)),
        }
    }

    let (mut records_revision, mut web_revision) = (records_now.0, web_now.0);
    if imported_intact || rolled_back {
        // Старые данные становятся НОВЫМ состоянием: ревизии переносятся выше
        // подтверждённых, подтверждённая ревизия не уменьшается.
        records_revision = records_revision.max(records_confirmed.revision) + 1;
        web_revision = web_revision.max(web_confirmed.revision) + 1;
        records_db.set_revision(records_revision)?;
        web_db.set_revision(web_revision)?;
        let (records, web) = (records_db.state()?, web_db.state()?);
        meta.advance_data_state(
            &integrity_key,
            Some(data_state(records)),
            Some(data_state(web)),
        )?;
        if row.data_rebase_pending {
            meta.finish_data_rebase(&integrity_key)?;
        }
    } else {
        // Отставший checkpoint догоняется; первый вход фиксирует дайджест.
        meta.advance_data_state(
            &integrity_key,
            Some(data_state(records_now)),
            Some(data_state(web_now)),
        )?;
    }
    records_db.attach_revision_sink(
        records_revision,
        revision_sink(state, &integrity_key, Database::Records),
    );
    web_db.attach_revision_sink(
        web_revision,
        revision_sink(state, &integrity_key, Database::Web),
    );

    let mut session = state.session.lock();
    *session = crate::state::SessionState::Unlocked {
        master_key: master,
        integrity_key,
        records_db,
        web_db,
        unlocked_at: std::time::Instant::now(),
        last_activity: std::time::Instant::now(),
        auth_verified_at: None,
        authorization: None,
    };
    Ok(())
}

pub(crate) fn data_state((revision, digest): (u64, [u8; 32])) -> DataState {
    DataState { revision, digest }
}

#[derive(Clone, Copy)]
enum Database {
    Records,
    Web,
}

/// Подтверждение нового состояния базы во внешнем checkpoint'е этого ключа.
fn revision_sink(
    state: &AppState,
    integrity_key: &[u8; 32],
    database: Database,
) -> crate::storage::records_db::RevisionSink {
    let meta_path = state.meta_path();
    let integrity_key = zeroize::Zeroizing::new(*integrity_key);
    Box::new(move |revision, digest| {
        let update = Some(data_state((revision, digest)));
        let (records, web) = match database {
            Database::Records => (update, None),
            Database::Web => (None, update),
        };
        MetaDb::open(&meta_path)?.advance_data_state(&integrity_key, records, web)
    })
}

pub(crate) fn apply_settings(state: &AppState, meta: &crate::storage::meta_db::VaultMetaRow) {
    let mut s = state.settings.lock();
    *s = crate::state::VaultSettings {
        autolock_seconds: meta.autolock_seconds,
        clipboard_clear_seconds: meta.clipboard_clear_seconds,
        require_auth_for_copy: meta.require_auth_for_copy,
        use_windows_hello: meta.use_windows_hello,
    };
}
