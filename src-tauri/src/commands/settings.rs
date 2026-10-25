//! Настройки хранилища и операции с факторами входа.
//!
//! Настройки удобства (автоблокировка, очистка буфера) меняются в открытой
//! сессии. Всё, что меняет политику безопасности — Windows Hello,
//! подтверждение копирования, FIDO2-ключи, — требует свежего подтверждения
//! (`commands::security`) и выполняется атомарной операцией.

use crate::auth::webauthn_rp::{self, Ceremony, ClientData};
use crate::commands::security::{self, SecurityAction};
use crate::error::{Result, VaultError};
use crate::state::{AppState, SessionState, VaultSettings};
use crate::storage::meta_db::Fido2KeyRow;
use crate::storage::osjournal::{OsJournal, Resource};
use serde::{Deserialize, Serialize};
use tauri::State;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsDto {
    pub autolock_seconds: u32,
    pub clipboard_clear_seconds: u32,
    pub require_auth_for_copy: bool,
    pub use_windows_hello: bool,
}

impl From<&VaultSettings> for SettingsDto {
    fn from(s: &VaultSettings) -> Self {
        Self {
            autolock_seconds: s.autolock_seconds,
            clipboard_clear_seconds: s.clipboard_clear_seconds,
            require_auth_for_copy: s.require_auth_for_copy,
            use_windows_hello: s.use_windows_hello,
        }
    }
}

#[tauri::command]
pub fn settings_get(state: State<'_, AppState>) -> Result<SettingsDto> {
    if state.check_autolock() || !state.session.lock().is_unlocked() {
        return Err(VaultError::Locked);
    }
    let s = state.settings.lock();
    Ok(SettingsDto::from(&*s))
}

/// Настройки удобства. Факторы и подтверждения здесь не меняются.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConvenienceSettings {
    pub autolock_seconds: u32,
    pub clipboard_clear_seconds: u32,
}

#[tauri::command]
pub async fn settings_update(input: ConvenienceSettings, state: State<'_, AppState>) -> Result<()> {
    update_settings(&state, input).await
}

pub(crate) async fn update_settings(state: &AppState, input: ConvenienceSettings) -> Result<()> {
    let _auth_flow = state.auth_flow.lock().await;
    let integrity_key = session_integrity_key(state)?;
    state.touch();
    let autolock = input.autolock_seconds.min(60 * 60);
    let clipboard = input.clipboard_clear_seconds.min(120);
    state
        .open_meta()?
        .update_settings(&integrity_key, autolock, clipboard)?;
    let mut settings = state.settings.lock();
    settings.autolock_seconds = autolock;
    settings.clipboard_clear_seconds = clipboard;
    log::info!("settings_update: applied");
    Ok(())
}

fn session_integrity_key(state: &AppState) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    match &*state.session.lock() {
        SessionState::Unlocked { integrity_key, .. } => Ok(integrity_key.clone()),
        SessionState::Locked => Err(VaultError::Locked),
    }
}

/// Перечитать флаги безопасности из метаданных в кэш настроек.
fn refresh_security_flags(state: &AppState) -> Result<()> {
    let meta = state
        .open_meta()?
        .vault_load()?
        .ok_or(VaultError::NotInitialized)?;
    let mut settings = state.settings.lock();
    settings.use_windows_hello = meta.use_windows_hello;
    settings.require_auth_for_copy = meta.require_auth_for_copy;
    Ok(())
}

#[tauri::command]
pub async fn security_set_hello(enabled: bool, state: State<'_, AppState>) -> Result<()> {
    set_hello(&state, enabled).await
}

/// Включить или выключить Windows Hello как второй фактор.
pub(crate) async fn set_hello(state: &AppState, enabled: bool) -> Result<()> {
    let _auth_flow = state.auth_flow.lock().await;
    let integrity_key = session_integrity_key(state)?;
    let current = state
        .open_meta()?
        .vault_load()?
        .ok_or(VaultError::NotInitialized)?;
    if current.use_windows_hello == enabled {
        return Ok(());
    }
    if enabled {
        security::consume(state, SecurityAction::EnableHello)?;
        if !state.os.hello_supported() {
            return Err(VaultError::HelloUnavailable);
        }
        let stamp = crate::commands::file_grants::session_stamp(&state.session.lock());
        enable_hello_in_session(state, &integrity_key, stamp).await?;
        log::info!("settings: Windows Hello enabled");
    } else {
        security::consume(state, SecurityAction::DisableHello)?;
        disable_hello(state, &integrity_key, current.hello_key_credential_name).await?;
        log::info!("settings: Windows Hello disabled");
    }
    refresh_security_flags(state)
}

#[tauri::command]
pub async fn security_set_step_up(enabled: bool, state: State<'_, AppState>) -> Result<()> {
    set_step_up(&state, enabled).await
}

/// Подтверждение Hello для копирования и просмотра секретов.
pub(crate) async fn set_step_up(state: &AppState, enabled: bool) -> Result<()> {
    let _auth_flow = state.auth_flow.lock().await;
    let integrity_key = session_integrity_key(state)?;
    let current = state
        .open_meta()?
        .vault_load()?
        .ok_or(VaultError::NotInitialized)?;
    if current.require_auth_for_copy == enabled {
        return Ok(());
    }
    security::consume(
        state,
        if enabled {
            SecurityAction::EnableStepUp
        } else {
            SecurityAction::DisableStepUp
        },
    )?;
    state.open_meta()?.set_step_up(&integrity_key, enabled)?;
    refresh_security_flags(state)
}

/// Включить Windows Hello одной операцией журнала ресурсов ОС.
///
/// ```text
/// user.id → журнал → создать ключ и доказать его assertion
///         → commit {флаг, имя, публичный ключ, last_op_id} → якоря
/// ```
///
/// Сбой до commit оставляет Hello выключенным, а созданный ключ удаляется
/// (сразу или при следующем старте — по user.id из журнала). После commit
/// Hello включён и его ключ существует.
pub(crate) async fn enable_hello(state: &AppState, integrity_key: &[u8; 32]) -> Result<()> {
    enable_hello_in_session(state, integrity_key, None).await
}

async fn enable_hello_in_session(
    state: &AppState,
    integrity_key: &[u8; 32],
    session_started: Option<std::time::Instant>,
) -> Result<()> {
    let mut journal = OsJournal::begin(&state.data_dir, &state.os)?;
    let result = async {
        let (handle, resource) = crate::storage::osjournal::new_user_handle();
        journal.will_create(resource)?;
        let os = state.os.clone();
        let created = crate::blocking::run(move || os.hello_create(&handle)).await?;
        // Системный диалог может длиться долго: за это время сессию могли
        // закрыть, и включать фактор от её имени уже нельзя.
        if let Some(started) = session_started {
            if state.check_autolock()
                || crate::commands::file_grants::session_stamp(&state.session.lock())
                    != Some(started)
            {
                return Err(VaultError::Locked);
            }
        }
        state.open_meta()?.set_hello(
            integrity_key,
            journal.op_id(),
            Some((&created.name, &created.public_key)),
        )
    }
    .await;
    journal.finish(&state.os, &state.data_dir);
    result
}

/// Выключить Windows Hello — асимметрично включению:
///
/// ```text
/// журнал(retire старого ключа) → commit {флаг = 0, ссылки на ключ нет}
///                              → якоря → удаление старого ключа
/// ```
///
/// Внешний ключ удаляется только после надёжного commit. Сбой до commit:
/// Hello включён и ключ цел. Сбой после: Hello выключен, а ключ — безвредная
/// сирота, которую журнал удалит при следующем старте. Состояния «Hello
/// включён, ключа нет» не бывает.
async fn disable_hello(
    state: &AppState,
    integrity_key: &[u8; 32],
    credential: Option<String>,
) -> Result<()> {
    let mut journal = OsJournal::begin(&state.data_dir, &state.os)?;
    let result = (|| {
        if let Some(name) = credential {
            journal.retire(Resource::HelloName { name })?;
        }
        state
            .open_meta()?
            .set_hello(integrity_key, journal.op_id(), None)
    })();
    journal.finish(&state.os, &state.data_dir);
    result
}

#[tauri::command]
pub async fn get_ui_language(state: State<'_, AppState>) -> Result<String> {
    let session = state.session.lock();
    match &*session {
        SessionState::Unlocked { .. } => {
            let db = state.open_meta()?;
            db.get_ui_language()
        }
        _ => Ok("ru".to_string()), // fallback before unlock
    }
}

#[tauri::command]
pub async fn set_ui_language(lang: String, state: State<'_, AppState>) -> Result<()> {
    update_ui_language(&state, &lang)
}

pub(crate) fn update_ui_language(state: &AppState, lang: &str) -> Result<()> {
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    let session = state.session.lock();
    match &*session {
        SessionState::Unlocked { integrity_key, .. } => {
            let db = state.open_meta()?;
            db.set_ui_language(integrity_key, lang)
        }
        _ => Err(VaultError::Locked),
    }
}

#[tauri::command]
pub async fn get_enable_health_check(state: State<'_, AppState>) -> Result<bool> {
    if state.check_autolock() || !state.session.lock().is_unlocked() {
        return Err(VaultError::Locked);
    }
    let db = state.open_meta()?;
    db.get_enable_health_check()
}

#[tauri::command]
pub async fn set_enable_health_check(enabled: bool, state: State<'_, AppState>) -> Result<()> {
    update_health_check(&state, enabled)
}

pub(crate) fn update_health_check(state: &AppState, enabled: bool) -> Result<()> {
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    let session = state.session.lock();
    match &*session {
        SessionState::Unlocked { integrity_key, .. } => {
            let db = state.open_meta()?;
            db.set_enable_health_check(integrity_key, enabled)
        }
        _ => Err(VaultError::Locked),
    }
}

#[tauri::command]
pub async fn get_enable_generator(state: State<'_, AppState>) -> Result<bool> {
    if state.check_autolock() || !state.session.lock().is_unlocked() {
        return Err(VaultError::Locked);
    }
    let db = state.open_meta()?;
    db.get_enable_generator()
}

#[tauri::command]
pub async fn set_enable_generator(enabled: bool, state: State<'_, AppState>) -> Result<()> {
    update_generator(&state, enabled)
}

pub(crate) fn update_generator(state: &AppState, enabled: bool) -> Result<()> {
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    let session = state.session.lock();
    match &*session {
        SessionState::Unlocked { integrity_key, .. } => {
            let db = state.open_meta()?;
            db.set_enable_generator(integrity_key, enabled)
        }
        _ => Err(VaultError::Locked),
    }
}

#[tauri::command]
pub async fn get_enable_password_history(state: State<'_, AppState>) -> Result<bool> {
    if state.check_autolock() || !state.session.lock().is_unlocked() {
        return Err(VaultError::Locked);
    }
    let db = state.open_meta()?;
    db.get_enable_password_history()
}

#[tauri::command]
pub async fn set_enable_password_history(enabled: bool, state: State<'_, AppState>) -> Result<()> {
    update_password_history(&state, enabled)
}

pub(crate) fn update_password_history(state: &AppState, enabled: bool) -> Result<()> {
    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    let session = state.session.lock();
    match &*session {
        SessionState::Unlocked {
            records_db,
            web_db,
            integrity_key,
            ..
        } => {
            // Флаг и две базы — три отдельных commit'а. Порядок выбран так,
            // чтобы сбой между ними не возвращал стёртые значения: включение
            // начинается с пустой истории, а недочищенное после выключения
            // дочищает следующий вход (`open_session_with`).
            let db = state.open_meta()?;
            // Повтор того же значения ничего не меняет: иначе повторное
            // включение стёрло бы накопленную историю.
            let current = db.vault_load()?.ok_or(VaultError::NotInitialized)?;
            if current.enable_password_history == enabled {
                return Ok(());
            }
            if enabled {
                crate::storage::records::clear_all_password_history(records_db)?;
                crate::storage::records::clear_all_password_history(web_db)?;
                db.set_enable_password_history(integrity_key, true)?;
            } else {
                db.set_enable_password_history(integrity_key, false)?;
                crate::storage::records::clear_all_password_history(records_db)?;
                crate::storage::records::clear_all_password_history(web_db)?;
            }
            Ok(())
        }
        _ => Err(VaultError::Locked),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2KeyItem {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub credential_id_preview: String,
    /// Название модели ключа, определённое по AAGUID ("Рутокен MFA", "YubiKey 5 NFC" и т.д.)
    pub model_name: String,
    /// Режим привязки: true = ПИН+Touch, false = Touch-only
    pub require_pin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2StatusDto {
    pub enabled: bool,
    pub available: bool,
    pub keys: Vec<Fido2KeyItem>,
}

/// Представление ключа для интерфейса.
fn key_item(key: Fido2KeyRow) -> Fido2KeyItem {
    let hex_id = hex::encode(&key.credential_id);
    let preview = if hex_id.len() > 12 {
        format!("{}...{}", &hex_id[..6], &hex_id[hex_id.len() - 6..])
    } else {
        hex_id
    };
    let model_name = key
        .aaguid
        .as_deref()
        .and_then(|aaguid| {
            let mut buf = [0u8; 16];
            hex::decode_to_slice(aaguid, &mut buf).ok()?;
            Some(crate::auth::fido2::aaguid_model_name(&buf).to_string())
        })
        .unwrap_or_else(|| "FIDO2 Security Key".to_string());
    Fido2KeyItem {
        id: key.id,
        name: key.name,
        created_at: key.created_at,
        credential_id_preview: preview,
        model_name,
        require_pin: key.require_pin,
    }
}

#[tauri::command]
pub async fn get_fido2_status(state: State<'_, AppState>) -> Result<Fido2StatusDto> {
    if state.check_autolock() || !state.session.lock().is_unlocked() {
        return Err(VaultError::Locked);
    }
    let keys: Vec<Fido2KeyItem> = state
        .open_meta()?
        .get_fido2_keys()?
        .into_iter()
        .map(key_item)
        .collect();
    Ok(Fido2StatusDto {
        enabled: !keys.is_empty(),
        available: crate::auth::fido2::is_fido2_supported(),
        keys,
    })
}

#[tauri::command]
pub async fn register_fido2_key(
    name: Option<String>,
    require_pin: Option<bool>,
    request_id: String,
    state: State<'_, AppState>,
) -> Result<Fido2KeyItem> {
    bind_fido2_key(&state, name, require_pin, &request_id).await
}

/// Привязать FIDO2-ключ к хранилищу на этом устройстве.
///
/// ```text
/// регистрация → RP-проверка (rpIdHash, UP, UV по режиму, credential id,
///               COSE ES256) → проверочный assertion с PRF → RP-проверка
///               подписи → конверт MK под PRF + Device Secret + DPAPI
///             → одна транзакция: строка ключа с публичным ключом и конвертом
/// ```
///
/// Строки без рабочего конверта не бывает: запись делается только после
/// того, как ключ доказал, что открывает хранилище.
pub(crate) async fn bind_fido2_key(
    state: &AppState,
    name: Option<String>,
    require_pin: Option<bool>,
    request_id: &str,
) -> Result<Fido2KeyItem> {
    let _auth_flow = state.auth_flow.lock().await;
    let request_id = crate::commands::request::parse(request_id)?;
    let (master, integrity_key, stamp) = {
        if state.check_autolock() {
            return Err(VaultError::Locked);
        }
        let session = state.session.lock();
        match &*session {
            SessionState::Unlocked {
                master_key,
                integrity_key,
                unlocked_at,
                ..
            } => (master_key.clone(), integrity_key.clone(), *unlocked_at),
            SessionState::Locked => return Err(VaultError::Locked),
        }
    };
    // Повтор уже выполненной привязки возвращает её результат: второй
    // credential на токене не создаётся.
    if let Some(existing) = state.open_meta()?.fido2_key_by_request(&request_id)? {
        return Ok(key_item(existing));
    }
    security::consume(state, SecurityAction::BindFido)?;

    let db = state.open_meta()?;
    let meta = db.vault_load()?.ok_or(VaultError::NotInitialized)?;
    if meta.crypto_version < 2 {
        return Err(VaultError::BadInput(
            "FIDO2-ключ привязывается к устройству через TPM 2.0; на этом компьютере его нет"
                .into(),
        ));
    }
    let pin_mode = require_pin.unwrap_or(true);
    let key_name = name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty());

    // Регистрация.
    let registration_client = ClientData::new(Ceremony::Create);
    let (os, json, prompt_name) = (
        state.os.clone(),
        registration_client.json.clone(),
        key_name.clone().unwrap_or_else(|| "FIDO2".into()),
    );
    let registration =
        crate::blocking::run(move || os.fido_register(&prompt_name, pin_mode, &json)).await?;
    let (public_key, _) = webauthn_rp::verify_registration(
        &registration.authenticator_data,
        &registration.credential_id,
        pin_mode,
    )?;

    // Проверочный assertion: ключ обязан доказать, что откроет хранилище.
    let client = ClientData::new(Ceremony::Get);
    let (os, json, ids) = (
        state.os.clone(),
        client.json.clone(),
        vec![registration.credential_id.clone()],
    );
    let assertion = crate::blocking::run(move || os.fido_assert(&ids, pin_mode, &json)).await?;
    if assertion.credential_id != registration.credential_id {
        return Err(VaultError::FidoFailed("ответил другой ключ".into()));
    }
    webauthn_rp::verify_assertion(
        &public_key,
        &assertion.authenticator_data,
        &client.json,
        &assertion.signature,
        pin_mode,
    )?;
    let prf = assertion.prf_output.ok_or_else(|| {
        VaultError::BadInput(
            "Токен не вернул аппаратный PRF-секрет (hmac-secret). Возможные причины: расширение не поддерживается моделью; на токене не задан собственный ПИН; Windows старше 11 21H2."
                .into(),
        )
    })?;

    let (_, device_secret) =
        crate::commands::vault::helpers::load_device_secret(&state.os, &db).await?;
    let wrapped = crate::crypto::fido::wrap_master(
        &master,
        &prf,
        &device_secret,
        &registration.credential_id,
        &meta.dpapi_entropy,
    )?;

    if state.check_autolock()
        || crate::commands::file_grants::session_stamp(&state.session.lock()) != Some(stamp)
    {
        return Err(VaultError::Locked);
    }
    let model = crate::auth::fido2::aaguid_model_name(&registration.aaguid).to_string();
    let added = db.add_fido2_key(
        &integrity_key,
        key_name.as_deref().unwrap_or(&model),
        &registration.credential_id,
        &public_key,
        &wrapped,
        Some(&hex::encode(registration.aaguid)),
        pin_mode,
        Some(&request_id),
    )?;
    Ok(key_item(added))
}

#[tauri::command]
pub async fn unbind_fido2_key(id: String, state: State<'_, AppState>) -> Result<()> {
    unbind_fido2(&state, &id).await
}

/// Отвязать FIDO2-ключ: одна транзакция удаляет строку вместе с конвертом —
/// фактор либо работает полностью, либо отозван полностью.
///
/// Идемпотентно: уже отвязанный ключ — успех без подтверждения.
pub(crate) async fn unbind_fido2(state: &AppState, id: &str) -> Result<()> {
    let _auth_flow = state.auth_flow.lock().await;
    let integrity_key = session_integrity_key(state)?;
    let db = state.open_meta()?;
    if !db.get_fido2_keys()?.iter().any(|key| key.id == id) {
        return Ok(());
    }
    security::consume(state, SecurityAction::UnbindFido)?;
    db.delete_fido2_key(&integrity_key, id)
}
