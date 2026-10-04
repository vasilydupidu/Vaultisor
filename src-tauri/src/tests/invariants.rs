//! Общие инварианты хранилища, которые проверяются после любого сбоя.
//!
//! После перезапуска хранилище обязано быть в одном из состояний:
//! - `NotCreated` — файлов хранилища нет, ресурсов ОС от него не осталось;
//! - `Created` — метаданные целы и согласованы с ресурсами ОС.
//!
//! Недопустимы: `PARTIAL` (часть файлов), незавершённые журналы после старта,
//! несовпадение MAC/якорей, «Hello включён — ключа нет», Device Secret без
//! TPM-ключа, конверт восстановления без локальной доли (и наоборот),
//! осиротевшие TPM- и Hello-ключи, параметры KDF вне диапазона.
//!
//! Какое из состояний — старое или новое для конкретной операции — решают
//! постусловия сценариев; здесь только то, что верно для любого состояния.

use crate::storage::meta_db::{MetaDb, VaultMetaRow};

use super::harness::Env;

pub enum Observed {
    NotCreated,
    Created(Box<VaultMetaRow>),
}

/// Проверить общие инварианты. Вызывать после `env.restart()`.
pub async fn inspect(env: &Env) -> (Option<Observed>, Vec<String>) {
    let mut violations = Vec::new();
    let root = &env.root;

    if root.join(".create-staging").exists() {
        violations.push("после старта остался каталог сборки хранилища".into());
    }
    if !crate::storage::osjournal::is_empty(root) {
        violations.push("после старта остался журнал ресурсов ОС".into());
    }
    if root.join(".restore-transaction").exists() {
        violations.push("после старта остался журнал restore".into());
    }
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(crate::storage::fsio::TEMP_PREFIX) {
                violations.push(format!("после старта остался временный файл {name}"));
            }
        }
    }

    let present = [
        env.state.meta_path().exists(),
        env.state.records_path().exists(),
        env.state.web_path().exists(),
    ];
    let tpm_keys = env.fake.tpm_keys();
    let hello_keys = env.fake.hello_keys();
    let checkpoints = env.checkpoints();

    if present.iter().all(|p| !p) {
        let tpm_left: Vec<_> = tpm_keys.difference(&env.foreign_tpm).collect();
        if !tpm_left.is_empty() {
            violations.push(format!(
                "хранилища нет, но остались TPM-ключи: {tpm_left:?}"
            ));
        }
        if !hello_keys.is_empty() {
            violations.push(format!(
                "хранилища нет, но остались ключи Hello: {hello_keys:?}"
            ));
        }
        let checkpoints_left: Vec<_> = checkpoints.difference(&env.foreign_checkpoints).collect();
        if !checkpoints_left.is_empty() {
            violations.push(format!(
                "хранилища нет, но остались checkpoint'ы: {checkpoints_left:?}"
            ));
        }
        return (Some(Observed::NotCreated), violations);
    }
    if !present.iter().all(|p| *p) {
        violations.push(format!(
            "PARTIAL: есть только часть файлов (meta, records, web) = {present:?}"
        ));
        return (None, violations);
    }

    let db = match MetaDb::open(&env.state.meta_path()) {
        Ok(db) => db,
        Err(error) => {
            violations.push(format!("метаданные не открываются: {error}"));
            return (None, violations);
        }
    };
    let meta = match db.vault_load() {
        Ok(Some(meta)) => meta,
        other => {
            violations.push(format!("метаданные пусты: {:?}", other.map(|_| ())));
            return (None, violations);
        }
    };

    // Целостность: MAC и checkpoint текущего ключа — единственный checkpoint
    // на устройстве (старые удаляются после смены ключа).
    match db.get_integrity_key_dpapi() {
        Ok(Some(blob)) => {
            match crate::commands::vault::unwrap_integrity_key(&blob, &meta.dpapi_entropy) {
                Ok(key) => {
                    if let Err(error) = db.verify_meta_integrity(&key) {
                        violations.push(format!("META mismatch: {error}"));
                    }
                    let current = format!(
                        "{}.checkpoint",
                        crate::storage::meta_db::crud::checkpoint_id(&key)
                    );
                    let stale: Vec<_> = checkpoints
                        .iter()
                        .filter(|name| {
                            **name != current && !env.foreign_checkpoints.contains(*name)
                        })
                        .collect();
                    if !stale.is_empty() {
                        violations.push(format!("осиротевшие checkpoint'ы: {stale:?}"));
                    }
                }
                Err(error) => {
                    violations.push(format!("integrity-ключ не разворачивается: {error}"))
                }
            }
        }
        _ => violations.push("нет integrity-ключа".into()),
    }

    // Hello: флаг, имя и публичный ключ — вместе, и ключ существует в ОС.
    match (
        meta.use_windows_hello,
        meta.hello_key_credential_name.as_deref(),
        meta.hello_key_credential_public_key.is_some(),
    ) {
        (true, Some(name), true) => {
            if !hello_keys.contains(name) {
                violations.push("Hello включён, но его ключа нет в ОС".into());
            }
        }
        (false, None, false) => {}
        state => violations.push(format!("Hello рассогласован (флаг, имя, ключ) = {state:?}")),
    }

    // Device Secret: режим, имя и TPM-ключ согласованы.
    match (meta.crypto_version, meta.device_secret_tpm_name.as_deref()) {
        (2, Some(name)) => {
            if !tpm_keys.contains(name) {
                violations.push("Device Secret ссылается на отсутствующий TPM-ключ".into());
            } else if let Err(error) =
                crate::commands::vault::helpers::load_device_secret(&env.state.os, &db).await
            {
                violations.push(format!("Device Secret не расшифровывается: {error}"));
            }
        }
        (1, None) => {}
        state => violations.push(format!("режим защиты рассогласован = {state:?}")),
    }

    // Восстановление согласовано со своим состоянием:
    // active — конверт и доля A; disabled — ни того, ни другого;
    // pending — доля A только вместе с конвертом.
    {
        use crate::storage::meta_db::RecoveryState;
        let envelope = meta.recovery_wrapped_master.is_some();
        let local_share = meta.recovery_local.is_some();
        let consistent = match meta.recovery_state {
            RecoveryState::Active => envelope && local_share,
            RecoveryState::Disabled => !envelope && !local_share,
            RecoveryState::Pending => envelope || !local_share,
        };
        if !consistent {
            violations.push(format!(
                "восстановление рассогласовано: {:?}, конверт={envelope}, доля A={local_share}",
                meta.recovery_state
            ));
        }
    }

    // FIDO2: каждый сохранённый ключ существует на «токене».
    let tokens = env.fake.fido_credentials();
    for key in db.get_fido2_keys().unwrap_or_default() {
        if !tokens.contains(&key.credential_id) {
            violations.push(format!("FIDO2-ключ {} неизвестен токенам", key.name));
        }
    }

    // Сироты: в ОС нет ключей, на которые не ссылаются метаданные.
    for name in &tpm_keys {
        if meta.device_secret_tpm_name.as_deref() != Some(name.as_str())
            && !env.foreign_tpm.contains(name)
        {
            violations.push(format!("осиротевший TPM-ключ {name}"));
        }
    }
    for name in &hello_keys {
        if meta.hello_key_credential_name.as_deref() != Some(name.as_str()) {
            violations.push(format!("осиротевший ключ Hello {name}"));
        }
    }

    if crate::crypto::kdf::Argon2Params::from_stored(
        meta.argon2_m_cost,
        meta.argon2_t_cost,
        meta.argon2_p_cost,
    )
    .is_err()
    {
        violations.push("параметры Argon2 вне допустимого диапазона".into());
    }

    (Some(Observed::Created(Box::new(meta))), violations)
}
