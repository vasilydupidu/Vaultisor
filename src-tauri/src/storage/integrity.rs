//! Защита целостности метаданных хранилища.
//!
//! Метаданные лежат в НЕзашифрованной SQLite: backend обязан прочитать
//! `wrapped_master_key` до того, как получит SQLCipher-ключ. Поэтому от
//! незаметной правки мимо приложения их защищает HMAC-SHA256 на
//! integrity-ключе, который сам обёрнут DPAPI.
//!
//! Версия одна. Каскад v1…v9 из ранних сборок удалён вместе с самими
//! сборками: продукт ещё не выпущен, старых хранилищ не существует, а
//! поддержка устаревших форматов MAC — это готовый downgrade-вектор.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Домен подписи. Входит в MAC первым, чтобы значение нельзя было переиспользовать
/// в другом контексте.
const MAC_DOMAIN: &[u8] = b"vaultisor:meta-integrity:v1";

/// Все поля метаданных, которые обязаны быть аутентифицированы.
///
/// Добавляя поле в `vault_meta`, добавьте его и сюда: значение, не попавшее в
/// MAC, можно менять мимо приложения незаметно.
pub struct MacInputs<'a> {
    pub failed_pin_attempts: u32,
    pub pin_next_allowed: i64,
    pub pin_last_failure: i64,
    pub autolock_seconds: u32,
    pub clipboard_clear_seconds: u32,
    pub require_auth_for_copy: bool,
    pub use_windows_hello: bool,
    pub created_at: &'a str,
    pub wrapped_master: &'a [u8],
    pub device_secret_tpm_name: Option<&'a str>,
    pub device_secret_tpm_blob: Option<&'a [u8]>,
    pub crypto_version: u32,
    pub argon2_m_cost: u32,
    pub argon2_t_cost: u32,
    pub argon2_p_cost: u32,
    pub dpapi_entropy: &'a [u8],
    pub fido2_keys_digest: Option<&'a [u8]>,
    pub recovery_generation: u64,
    pub recovery_wrapped_master: Option<&'a [u8]>,
    /// Состояние восстановления: `disabled`, `pending` или `active`.
    pub recovery_state: &'a str,
    pub data_rebase_pending: bool,
    pub pin_change_request_id: Option<&'a str>,
    pub import_records_sha256: Option<&'a [u8]>,
    pub import_web_sha256: Option<&'a [u8]>,
    pub security_epoch: u64,
    pub hello_key_credential_name: Option<&'a str>,
    pub hello_key_credential_public_key: Option<&'a [u8]>,
    pub ui_language: &'a str,
    pub enable_health_check: bool,
    pub enable_password_history: bool,
    pub enable_generator: bool,
    /// Последняя закоммиченная операция с ресурсами ОС (журнал osjournal).
    pub last_op_id: Option<&'a str>,
}

/// Посчитать MAC метаданных.
///
/// Кодирование однозначное: каждое поле идёт с префиксом длины, поэтому
/// перенос данных между соседними полями не может дать ту же подпись.
pub fn compute_meta_mac(integrity_key: &[u8; 32], inputs: &MacInputs<'_>) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(integrity_key).expect("HMAC accepts any key length");
    mac.update(MAC_DOMAIN);

    update_u32(&mut mac, inputs.failed_pin_attempts);
    update_u64(&mut mac, inputs.pin_next_allowed as u64);
    update_u64(&mut mac, inputs.pin_last_failure as u64);
    update_u32(&mut mac, inputs.autolock_seconds);
    update_u32(&mut mac, inputs.clipboard_clear_seconds);
    update_bool(&mut mac, inputs.require_auth_for_copy);
    update_bool(&mut mac, inputs.use_windows_hello);
    update_blob(&mut mac, inputs.created_at.as_bytes());
    update_blob(&mut mac, inputs.wrapped_master);
    update_optional_str(&mut mac, inputs.device_secret_tpm_name);
    update_optional_blob(&mut mac, inputs.device_secret_tpm_blob);
    update_u32(&mut mac, inputs.crypto_version);
    update_u32(&mut mac, inputs.argon2_m_cost);
    update_u32(&mut mac, inputs.argon2_t_cost);
    update_u32(&mut mac, inputs.argon2_p_cost);
    update_blob(&mut mac, inputs.dpapi_entropy);
    update_optional_blob(&mut mac, inputs.fido2_keys_digest);
    update_u64(&mut mac, inputs.recovery_generation);
    update_optional_blob(&mut mac, inputs.recovery_wrapped_master);
    update_blob(&mut mac, inputs.recovery_state.as_bytes());
    update_bool(&mut mac, inputs.data_rebase_pending);
    update_optional_str(&mut mac, inputs.pin_change_request_id);
    update_optional_blob(&mut mac, inputs.import_records_sha256);
    update_optional_blob(&mut mac, inputs.import_web_sha256);
    update_u64(&mut mac, inputs.security_epoch);
    update_optional_str(&mut mac, inputs.hello_key_credential_name);
    update_optional_blob(&mut mac, inputs.hello_key_credential_public_key);
    update_blob(&mut mac, inputs.ui_language.as_bytes());
    update_bool(&mut mac, inputs.enable_health_check);
    update_bool(&mut mac, inputs.enable_password_history);
    update_bool(&mut mac, inputs.enable_generator);
    update_optional_str(&mut mac, inputs.last_op_id);

    mac.finalize().into_bytes().into()
}

/// Сравнение в постоянном времени — MAC не должен утекать по таймингу.
pub fn verify_meta_mac(integrity_key: &[u8; 32], inputs: &MacInputs<'_>, expected: &[u8]) -> bool {
    expected.len() == 32 && bool::from(compute_meta_mac(integrity_key, inputs).ct_eq(expected))
}

fn update_u32(mac: &mut HmacSha256, value: u32) {
    mac.update(&value.to_le_bytes());
}

fn update_u64(mac: &mut HmacSha256, value: u64) {
    mac.update(&value.to_le_bytes());
}

fn update_bool(mac: &mut HmacSha256, value: bool) {
    mac.update(&[value as u8]);
}

fn update_blob(mac: &mut HmacSha256, bytes: &[u8]) {
    mac.update(&(bytes.len() as u64).to_le_bytes());
    mac.update(bytes);
}

fn update_optional_blob(mac: &mut HmacSha256, bytes: Option<&[u8]>) {
    match bytes {
        Some(bytes) => {
            mac.update(&[1]);
            update_blob(mac, bytes);
        }
        None => mac.update(&[0]),
    }
}

fn update_optional_str(mac: &mut HmacSha256, value: Option<&str>) {
    update_optional_blob(mac, value.map(str::as_bytes));
}

#[cfg(test)]
mod tests {
    /// Именованная мутация одного поля MAC-входа.
    type Mutation = (&'static str, Box<dyn Fn(&mut MacInputs<'_>)>);

    use super::*;

    fn sample<'a>() -> MacInputs<'a> {
        MacInputs {
            failed_pin_attempts: 0,
            pin_next_allowed: 1_800_000_030,
            pin_last_failure: 1_800_000_000,
            autolock_seconds: 300,
            clipboard_clear_seconds: 10,
            require_auth_for_copy: false,
            use_windows_hello: true,
            created_at: "2026-06-03T10:38:36Z",
            wrapped_master: b"wrapped-master-blob",
            device_secret_tpm_name: Some("ds-key"),
            device_secret_tpm_blob: Some(b"ds-blob"),
            crypto_version: 2,
            argon2_m_cost: 524288,
            argon2_t_cost: 6,
            argon2_p_cost: 2,
            dpapi_entropy: b"per-vault-entropy-32-bytes-long",
            fido2_keys_digest: Some(b"fido2-digest-sha256-hash-val"),
            recovery_generation: 3,
            recovery_wrapped_master: Some(b"recovery-envelope"),
            recovery_state: "active",
            data_rebase_pending: false,
            pin_change_request_id: Some("pin-change-1"),
            import_records_sha256: Some(b"records-digest"),
            import_web_sha256: Some(b"web-digest"),
            security_epoch: 7,
            hello_key_credential_name: Some("webauthn-platform-v1:abc"),
            hello_key_credential_public_key: Some(b"public-key"),
            ui_language: "ru",
            enable_health_check: true,
            enable_password_history: true,
            enable_generator: true,
            last_op_id: Some("op-1"),
        }
    }

    #[test]
    fn roundtrip_and_wrong_key() {
        let key = [7u8; 32];
        let inputs = sample();
        let mac = compute_meta_mac(&key, &inputs);
        assert!(verify_meta_mac(&key, &inputs, &mac));
        assert!(!verify_meta_mac(&[8u8; 32], &inputs, &mac));
        assert!(!verify_meta_mac(&key, &inputs, &mac[..31]));
        assert!(!verify_meta_mac(&key, &inputs, &[]));
    }

    /// Каждое аутентифицируемое поле обязано влиять на подпись. Тест ловит
    /// ситуацию «добавили колонку, забыли включить её в MAC».
    #[test]
    fn every_field_changes_the_mac() {
        let key = [9u8; 32];
        let base = compute_meta_mac(&key, &sample());

        let mut mutations: Vec<Mutation> = Vec::new();
        mutations.push((
            "failed_pin_attempts",
            Box::new(|i| i.failed_pin_attempts = 1),
        ));
        mutations.push(("pin_next_allowed", Box::new(|i| i.pin_next_allowed = 0)));
        mutations.push(("pin_last_failure", Box::new(|i| i.pin_last_failure = 0)));
        mutations.push(("autolock_seconds", Box::new(|i| i.autolock_seconds = 60)));
        mutations.push((
            "clipboard_clear_seconds",
            Box::new(|i| i.clipboard_clear_seconds = 30),
        ));
        mutations.push((
            "require_auth_for_copy",
            Box::new(|i| i.require_auth_for_copy = true),
        ));
        mutations.push((
            "use_windows_hello",
            Box::new(|i| i.use_windows_hello = false),
        ));
        mutations.push((
            "created_at",
            Box::new(|i| i.created_at = "2020-01-01T00:00:00Z"),
        ));
        mutations.push(("wrapped_master", Box::new(|i| i.wrapped_master = b"other")));
        mutations.push((
            "device_secret_tpm_name",
            Box::new(|i| i.device_secret_tpm_name = None),
        ));
        mutations.push((
            "device_secret_tpm_blob",
            Box::new(|i| i.device_secret_tpm_blob = Some(b"other")),
        ));
        mutations.push(("crypto_version", Box::new(|i| i.crypto_version = 1)));
        mutations.push(("argon2_m_cost", Box::new(|i| i.argon2_m_cost = 1024)));
        mutations.push(("argon2_t_cost", Box::new(|i| i.argon2_t_cost = 1)));
        mutations.push(("argon2_p_cost", Box::new(|i| i.argon2_p_cost = 1)));
        mutations.push(("dpapi_entropy", Box::new(|i| i.dpapi_entropy = b"other")));
        mutations.push((
            "fido2_keys_digest",
            Box::new(|i| i.fido2_keys_digest = None),
        ));
        mutations.push((
            "recovery_generation",
            Box::new(|i| i.recovery_generation = 4),
        ));
        mutations.push((
            "recovery_wrapped_master",
            Box::new(|i| i.recovery_wrapped_master = None),
        ));
        mutations.push(("recovery_state", Box::new(|i| i.recovery_state = "pending")));
        mutations.push((
            "data_rebase_pending",
            Box::new(|i| i.data_rebase_pending = true),
        ));
        mutations.push((
            "pin_change_request_id",
            Box::new(|i| i.pin_change_request_id = None),
        ));
        mutations.push((
            "import_records_sha256",
            Box::new(|i| i.import_records_sha256 = None),
        ));
        mutations.push((
            "import_web_sha256",
            Box::new(|i| i.import_web_sha256 = Some(b"other")),
        ));
        mutations.push(("security_epoch", Box::new(|i| i.security_epoch = 8)));
        mutations.push((
            "hello_key_credential_name",
            Box::new(|i| i.hello_key_credential_name = None),
        ));
        mutations.push((
            "hello_key_credential_public_key",
            Box::new(|i| i.hello_key_credential_public_key = Some(b"evil")),
        ));
        mutations.push(("ui_language", Box::new(|i| i.ui_language = "en")));
        mutations.push((
            "enable_health_check",
            Box::new(|i| i.enable_health_check = false),
        ));
        mutations.push(("enable_generator", Box::new(|i| i.enable_generator = false)));
        mutations.push(("last_op_id", Box::new(|i| i.last_op_id = Some("op-2"))));
        mutations.push((
            "enable_password_history",
            Box::new(|i| i.enable_password_history = false),
        ));

        for (name, mutate) in mutations {
            let mut inputs = sample();
            mutate(&mut inputs);
            assert_ne!(
                compute_meta_mac(&key, &inputs),
                base,
                "поле {name} не влияет на MAC"
            );
        }
    }

    /// Кодирование с префиксом длины: перенос байтов между соседними полями
    /// обязан менять подпись.
    #[test]
    fn field_boundaries_are_unambiguous() {
        let key = [5u8; 32];
        let mut a = sample();
        a.ui_language = "ru";
        a.created_at = "2026";
        let mut b = sample();
        b.ui_language = "";
        b.created_at = "2026ru";
        assert_ne!(compute_meta_mac(&key, &a), compute_meta_mac(&key, &b));
    }
}
