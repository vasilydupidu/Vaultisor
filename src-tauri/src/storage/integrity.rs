// vault_meta integrity protection.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

pub struct MacInputs<'a> {
    pub failed_pin_attempts: u32,
    pub max_pin_attempts: u32,
    pub pin_hash: &'a str,
    pub autolock_seconds: u32,
    pub clipboard_clear_seconds: u32,
    pub require_auth_for_copy: bool,
    pub use_windows_hello: bool,
    pub created_at: &'a str,
    pub wrapped_master: &'a [u8],
    pub hello_wrapped_key: Option<&'a [u8]>,
    pub tpm_credential_name: Option<&'a str>,
    pub tpm_wrapped_key: Option<&'a [u8]>,
    // v0.2: Device Secret включается в MAC
    pub device_secret_tpm_name: Option<&'a str>,
    pub device_secret_tpm_blob: Option<&'a [u8]>,
    // v0.5: ML-KEM (post-quantum Hello) поля включаются в MAC, чтобы
    // защитить их от подмены/downgrade при правке открытой meta.db.
    pub pq_encapsulation_key: Option<&'a [u8]>,
    pub pq_ciphertext: Option<&'a [u8]>,
    pub pq_dk_encrypted: Option<&'a [u8]>,
    // v0.6 (AUDIT L8): версия крипты и Argon2-параметры под MAC — защита от
    // downgrade/подмены при правке открытой meta.db (defense-in-depth).
    pub crypto_version: u32,
    pub argon2_m_cost: u32,
    pub argon2_t_cost: u32,
    pub argon2_p_cost: u32,
}

const MAC_DOMAIN_V4: &[u8] = b"vaultisor:meta-integrity:v4";
const MAC_DOMAIN_V2: &[u8] = b"vaultisor:meta-integrity:v2";
const MAC_DOMAIN_V1: &[u8] = b"vaultisor:meta-integrity:v1";
const SEP: u8 = 0x1F;

/// v0.5 канонический MAC: всё из v2 + ML-KEM поля.
/// Это текущий формат, в который пере-запечатываются все vault'ы при verify.
pub fn compute_meta_mac_v4(integrity_key: &[u8; 32], inputs: &MacInputs<'_>) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(integrity_key)
        .expect("HMAC accepts keys of any length");
    update_common_fields(&mut mac, inputs, MAC_DOMAIN_V4);
    mac.update(&[SEP]);
    update_blob(&mut mac, inputs.wrapped_master);
    mac.update(&[SEP]);
    update_optional_blob(&mut mac, inputs.hello_wrapped_key);
    mac.update(&[SEP]);
    update_optional_str(&mut mac, inputs.tpm_credential_name);
    mac.update(&[SEP]);
    update_optional_blob(&mut mac, inputs.tpm_wrapped_key);
    mac.update(&[SEP]);
    update_optional_str(&mut mac, inputs.device_secret_tpm_name);
    mac.update(&[SEP]);
    update_optional_blob(&mut mac, inputs.device_secret_tpm_blob);
    // v0.5: ML-KEM поля
    mac.update(&[SEP]);
    update_optional_blob(&mut mac, inputs.pq_encapsulation_key);
    mac.update(&[SEP]);
    update_optional_blob(&mut mac, inputs.pq_ciphertext);
    mac.update(&[SEP]);
    update_optional_blob(&mut mac, inputs.pq_dk_encrypted);
    // v0.6 (AUDIT L8): crypto_version + Argon2 params.
    mac.update(&[SEP]);
    mac.update(&inputs.crypto_version.to_le_bytes());
    mac.update(&[SEP]);
    mac.update(&inputs.argon2_m_cost.to_le_bytes());
    mac.update(&inputs.argon2_t_cost.to_le_bytes());
    mac.update(&inputs.argon2_p_cost.to_le_bytes());
    mac.finalize().into_bytes().into()
}

pub fn verify_meta_mac_v4(integrity_key: &[u8; 32], inputs: &MacInputs<'_>, expected: &[u8]) -> bool {
    if expected.len() != 32 {
        return false;
    }
    compute_meta_mac_v4(integrity_key, inputs).ct_eq(expected).into()
}

#[deprecated(note = "Legacy v2 MAC compute function. Used only for migration verification.")]
pub fn compute_meta_mac_v2(integrity_key: &[u8; 32], inputs: &MacInputs<'_>) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(integrity_key)
        .expect("HMAC accepts keys of any length");
    update_common_fields(&mut mac, inputs, MAC_DOMAIN_V2);
    mac.update(&[SEP]);
    update_blob(&mut mac, inputs.wrapped_master);
    mac.update(&[SEP]);
    update_optional_blob(&mut mac, inputs.hello_wrapped_key);
    mac.update(&[SEP]);
    update_optional_str(&mut mac, inputs.tpm_credential_name);
    mac.update(&[SEP]);
    update_optional_blob(&mut mac, inputs.tpm_wrapped_key);
    // v0.2: Device Secret поля
    mac.update(&[SEP]);
    update_optional_str(&mut mac, inputs.device_secret_tpm_name);
    mac.update(&[SEP]);
    update_optional_blob(&mut mac, inputs.device_secret_tpm_blob);
    mac.finalize().into_bytes().into()
}

#[deprecated(note = "Legacy v1 MAC compute function. Used only for migration verification.")]
pub fn compute_meta_mac_v1(integrity_key: &[u8; 32], inputs: &MacInputs<'_>) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(integrity_key)
        .expect("HMAC accepts keys of any length");
    update_common_fields(&mut mac, inputs, MAC_DOMAIN_V1);
    mac.update(&[SEP]);
    mac.update(&(inputs.wrapped_master.len() as u64).to_le_bytes());
    mac.finalize().into_bytes().into()
}

#[deprecated(note = "Legacy v2 MAC verify function. Used only for migration verification.")]
pub fn verify_meta_mac_v2(integrity_key: &[u8; 32], inputs: &MacInputs<'_>, expected: &[u8]) -> bool {
    if expected.len() != 32 {
        return false;
    }
    #[allow(deprecated)]
    let computed = compute_meta_mac_v2(integrity_key, inputs);
    computed.ct_eq(expected).into()
}

#[deprecated(note = "Legacy v1 MAC verify function. Used only for migration verification.")]
pub fn verify_meta_mac_v1(
    integrity_key: &[u8; 32],
    inputs: &MacInputs<'_>,
    expected: &[u8],
) -> bool {
    if expected.len() != 32 {
        return false;
    }
    #[allow(deprecated)]
    let computed = compute_meta_mac_v1(integrity_key, inputs);
    computed.ct_eq(expected).into()
}

fn update_common_fields(mac: &mut HmacSha256, inputs: &MacInputs<'_>, domain: &[u8]) {
    mac.update(domain);
    mac.update(&[SEP]);
    mac.update(&inputs.failed_pin_attempts.to_le_bytes());
    mac.update(&[SEP]);
    mac.update(&inputs.max_pin_attempts.to_le_bytes());
    mac.update(&[SEP]);
    mac.update(inputs.pin_hash.as_bytes());
    mac.update(&[SEP]);
    mac.update(&inputs.autolock_seconds.to_le_bytes());
    mac.update(&[SEP]);
    mac.update(&inputs.clipboard_clear_seconds.to_le_bytes());
    mac.update(&[SEP]);
    mac.update(&[inputs.require_auth_for_copy as u8]);
    mac.update(&[SEP]);
    mac.update(&[inputs.use_windows_hello as u8]);
    mac.update(&[SEP]);
    mac.update(inputs.created_at.as_bytes());
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
    match value {
        Some(value) => {
            mac.update(&[1]);
            update_blob(mac, value.as_bytes());
        }
        None => mac.update(&[0]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample<'a>(pq: Option<&'a [u8]>) -> MacInputs<'a> {
        MacInputs {
            failed_pin_attempts: 0,
            max_pin_attempts: 10,
            pin_hash: "$argon2id$abc",
            autolock_seconds: 300,
            clipboard_clear_seconds: 10,
            require_auth_for_copy: false,
            use_windows_hello: true,
            created_at: "2026-06-03T10:38:36Z",
            wrapped_master: b"wrapped-master-blob",
            hello_wrapped_key: None,
            tpm_credential_name: Some("cng-key"),
            tpm_wrapped_key: None,
            device_secret_tpm_name: Some("ds-key"),
            device_secret_tpm_blob: Some(b"ds-blob"),
            pq_encapsulation_key: pq,
            pq_ciphertext: pq,
            pq_dk_encrypted: pq,
            crypto_version: 2,
            argon2_m_cost: 524288,
            argon2_t_cost: 6,
            argon2_p_cost: 2,
        }
    }

    #[test]
    fn v4_differs_from_v2() {
        let key = [7u8; 32];
        let inp = sample(Some(b"pq-data"));
        #[allow(deprecated)]
        let v2_mac = compute_meta_mac_v2(&key, &inp);
        assert_ne!(
            compute_meta_mac_v4(&key, &inp),
            v2_mac,
            "v4 должен включать pq-поля и отличаться от v2"
        );
    }

    #[test]
    fn pq_fields_change_v4_mac() {
        let key = [7u8; 32];
        let with_pq = compute_meta_mac_v4(&key, &sample(Some(b"pq-data")));
        let no_pq = compute_meta_mac_v4(&key, &sample(None));
        assert_ne!(with_pq, no_pq, "изменение pq-полей должно менять v4-MAC");
    }

    #[test]
    #[allow(deprecated)]
    fn legacy_v2_vault_migrates_via_cascade() {
        // Эмуляция: vault запечатан старым v1 или v2. Каскад verify должен
        // принять его (v4 не сойдётся, старый сойдётся) — значит lockout не будет,
        // а вызывающий код пере-запечатает в v4.
        let key = [9u8; 32];
        let inp = sample(Some(b"pq-present-in-db"));
        
        let stored_v2 = compute_meta_mac_v2(&key, &inp);
        assert!(!verify_meta_mac_v4(&key, &inp, &stored_v2), "v4 не должен сойтись с v2-MAC");
        assert!(verify_meta_mac_v2(&key, &inp, &stored_v2), "v2 fallback должен сойтись");

        let stored_v1 = compute_meta_mac_v1(&key, &inp);
        assert!(!verify_meta_mac_v4(&key, &inp, &stored_v1), "v4 не должен сойтись с v1-MAC");
        assert!(verify_meta_mac_v1(&key, &inp, &stored_v1), "v1 fallback должен сойтись");
    }
}
