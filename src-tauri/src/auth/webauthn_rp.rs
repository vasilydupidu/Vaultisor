//! Проверки WebAuthn на стороне RP — общие для Windows Hello и FIDO2.
//!
//! Windows WebAuthn API проводит церемонию, но проверять её результат обязан
//! RP. Vaultisor — RP для самого себя, поэтому здесь то, что сделал бы сервер:
//!
//! - clientDataJSON: тип церемонии, наш challenge, наш origin;
//! - authenticatorData: `rpIdHash` нашего RP ID, флаг UP, флаг UV по политике;
//! - регистрация: credential id из attested credential data совпадает с
//!   возвращённым, публичный ключ — COSE ES256 (P-256);
//! - assertion: ES256-подпись над `authenticatorData ‖ SHA-256(clientDataJSON)`
//!   сохранённым при регистрации ключом.
//!
//! Подпись проверяется на чистом Rust (RustCrypto `p256`), без FFI.

use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{Result, VaultError};

/// RP ID Vaultisor. Под ним заводятся и ключи Hello, и FIDO2-credential'ы.
pub const RP_ID: &str = "vaultisor.app";
pub const ORIGIN: &str = "https://vaultisor.app";

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;

/// Вид церемонии в clientDataJSON.
#[derive(Clone, Copy)]
pub enum Ceremony {
    Create,
    Get,
}

impl Ceremony {
    fn as_str(self) -> &'static str {
        match self {
            Ceremony::Create => "webauthn.create",
            Ceremony::Get => "webauthn.get",
        }
    }
}

/// Свежий challenge и clientDataJSON для церемонии.
pub struct ClientData {
    pub challenge: [u8; 32],
    pub json: Vec<u8>,
}

impl ClientData {
    pub fn new(ceremony: Ceremony) -> Self {
        let challenge: [u8; 32] = crate::crypto::rng::random_array();
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge);
        let json = format!(
            r#"{{"type":"{}","challenge":"{encoded}","origin":"{ORIGIN}"}}"#,
            ceremony.as_str()
        )
        .into_bytes();
        Self { challenge, json }
    }
}

/// Флаги, подтверждённые проверкой.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    pub user_present: bool,
    pub user_verified: bool,
}

#[derive(Deserialize)]
struct ParsedClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
}

/// clientDataJSON — ровно наша церемония с нашим challenge и origin.
pub fn verify_client_data(json: &[u8], ceremony: Ceremony, challenge: &[u8; 32]) -> Result<()> {
    let parsed: ParsedClientData =
        serde_json::from_slice(json).map_err(|_| rp_error("clientData"))?;
    let received = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parsed.challenge)
        .map_err(|_| rp_error("challenge"))?;
    if parsed.kind != ceremony.as_str()
        || parsed.origin != ORIGIN
        || !bool::from(received.as_slice().ct_eq(challenge.as_slice()))
    {
        return Err(rp_error("clientData mismatch"));
    }
    Ok(())
}

/// Флаги authenticatorData после проверки `rpIdHash` и UP.
fn verify_auth_data_header(auth_data: &[u8], require_uv: bool) -> Result<Verified> {
    if auth_data.len() < 37 {
        return Err(rp_error("authData too short"));
    }
    let rp_hash = Sha256::digest(RP_ID.as_bytes());
    if !bool::from(auth_data[..32].ct_eq(rp_hash.as_slice())) {
        return Err(rp_error("rpIdHash"));
    }
    let flags = auth_data[32];
    let verified = Verified {
        user_present: flags & FLAG_UP != 0,
        user_verified: flags & FLAG_UV != 0,
    };
    if !verified.user_present {
        return Err(rp_error("user presence"));
    }
    if require_uv && !verified.user_verified {
        return Err(VaultError::FidoFailed(
            "аутентификатор не выполнил проверку пользователя".into(),
        ));
    }
    Ok(verified)
}

/// Регистрация: вернуть публичный ключ (несжатый SEC1 P-256) после проверки
/// authenticatorData и совпадения credential id.
pub fn verify_registration(
    auth_data: &[u8],
    credential_id: &[u8],
    require_uv: bool,
) -> Result<(Vec<u8>, Verified)> {
    let verified = verify_auth_data_header(auth_data, require_uv)?;
    if auth_data[32] & FLAG_AT == 0 || auth_data.len() < 55 {
        return Err(rp_error("no attested credential data"));
    }
    let id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let id_end = 55usize
        .checked_add(id_len)
        .filter(|end| *end <= auth_data.len())
        .ok_or_else(|| rp_error("credential id length"))?;
    if !bool::from(auth_data[55..id_end].ct_eq(credential_id)) || credential_id.is_empty() {
        return Err(rp_error("credential id mismatch"));
    }
    let public_key = parse_cose_p256(&auth_data[id_end..])?;
    // Ключ обязан быть точкой кривой — иначе им ничего не проверить.
    VerifyingKey::from_sec1_bytes(&public_key).map_err(|_| rp_error("public key"))?;
    Ok((public_key, verified))
}

/// Assertion: проверить authenticatorData и подпись сохранённым ключом.
pub fn verify_assertion(
    public_key: &[u8],
    auth_data: &[u8],
    client_data_json: &[u8],
    signature_der: &[u8],
    require_uv: bool,
) -> Result<Verified> {
    let verified = verify_auth_data_header(auth_data, require_uv)?;
    let key = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| rp_error("public key"))?;
    let signature = Signature::from_der(signature_der).map_err(|_| rp_error("signature format"))?;
    // Аутентификаторы вправе выдавать подпись с «высоким» s; она валидна.
    let signature = signature.normalize_s().unwrap_or(signature);
    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(auth_data);
    signed.extend_from_slice(&Sha256::digest(client_data_json));
    key.verify(&signed, &signature)
        .map_err(|_| rp_error("signature"))?;
    Ok(verified)
}

fn rp_error(what: &str) -> VaultError {
    VaultError::FidoFailed(format!("WebAuthn: проверка не пройдена ({what})"))
}

// ---------------------------------------------------------------- COSE / CBOR

fn parse_cose_p256(cbor: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = 0;
    let entries = read_len(cbor, &mut cursor, 5)?;
    let (mut kty, mut alg, mut curve) = (None, None, None);
    let (mut x, mut y) = (None, None);
    for _ in 0..entries {
        match read_int(cbor, &mut cursor)? {
            1 => kty = Some(read_int(cbor, &mut cursor)?),
            3 => alg = Some(read_int(cbor, &mut cursor)?),
            -1 => curve = Some(read_int(cbor, &mut cursor)?),
            -2 => x = Some(read_bytes(cbor, &mut cursor)?.to_vec()),
            -3 => y = Some(read_bytes(cbor, &mut cursor)?.to_vec()),
            _ => skip_cbor(cbor, &mut cursor, 0)?,
        }
    }
    let (x, y) = match (kty, alg, curve, x, y) {
        (Some(2), Some(-7), Some(1), Some(x), Some(y)) if x.len() == 32 && y.len() == 32 => (x, y),
        _ => return Err(rp_error("COSE key is not ES256")),
    };
    let mut key = Vec::with_capacity(65);
    key.push(4);
    key.extend_from_slice(&x);
    key.extend_from_slice(&y);
    Ok(key)
}

fn cbor_error() -> VaultError {
    rp_error("CBOR")
}

fn read_int(data: &[u8], cursor: &mut usize) -> Result<i64> {
    let initial = *data.get(*cursor).ok_or_else(cbor_error)?;
    let major = initial >> 5;
    if major > 1 {
        return Err(cbor_error());
    }
    let value = i64::try_from(read_len(data, cursor, major)?).map_err(|_| cbor_error())?;
    Ok(if major == 0 { value } else { -1 - value })
}

fn read_bytes<'a>(data: &'a [u8], cursor: &mut usize) -> Result<&'a [u8]> {
    let len = read_len(data, cursor, 2)?;
    let end = cursor
        .checked_add(len)
        .filter(|end| *end <= data.len())
        .ok_or_else(cbor_error)?;
    let value = &data[*cursor..end];
    *cursor = end;
    Ok(value)
}

fn read_len(data: &[u8], cursor: &mut usize, major: u8) -> Result<usize> {
    let initial = *data.get(*cursor).ok_or_else(cbor_error)?;
    *cursor += 1;
    if initial >> 5 != major {
        return Err(cbor_error());
    }
    let count = match initial & 0x1f {
        n @ 0..=23 => return Ok(usize::from(n)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return Err(cbor_error()),
    };
    let end = cursor
        .checked_add(count)
        .filter(|end| *end <= data.len())
        .ok_or_else(cbor_error)?;
    let mut value = 0u64;
    for byte in &data[*cursor..end] {
        value = (value << 8) | u64::from(*byte);
    }
    *cursor = end;
    usize::try_from(value).map_err(|_| cbor_error())
}

/// Пропустить элемент CBOR. Глубина ограничена: ключ COSE плоский, а
/// неограниченная рекурсия на подложенных данных — переполнение стека.
fn skip_cbor(data: &[u8], cursor: &mut usize, depth: usize) -> Result<()> {
    if depth > 8 {
        return Err(cbor_error());
    }
    let initial = *data.get(*cursor).ok_or_else(cbor_error)?;
    let major = initial >> 5;
    match major {
        0 | 1 => {
            read_len(data, cursor, major)?;
        }
        2 | 3 => {
            let len = read_len(data, cursor, major)?;
            *cursor = cursor
                .checked_add(len)
                .filter(|end| *end <= data.len())
                .ok_or_else(cbor_error)?;
        }
        4 => {
            for _ in 0..read_len(data, cursor, 4)? {
                skip_cbor(data, cursor, depth + 1)?;
            }
        }
        5 => {
            for _ in 0..read_len(data, cursor, 5)? {
                skip_cbor(data, cursor, depth + 1)?;
                skip_cbor(data, cursor, depth + 1)?;
            }
        }
        6 => {
            read_len(data, cursor, 6)?;
            skip_cbor(data, cursor, depth + 1)?;
        }
        _ => {
            let extra = match initial & 0x1f {
                0..=23 => 0,
                24 => 1,
                25 => 2,
                26 => 4,
                27 => 8,
                _ => return Err(cbor_error()),
            };
            *cursor = cursor
                .checked_add(1 + extra)
                .filter(|end| *end <= data.len())
                .ok_or_else(cbor_error)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- тестовый аутентификатор

/// Программный аутентификатор ES256 для тестов: строит authenticatorData и
/// подписи так же, как настоящий, чтобы проверки выше тестировались на
/// корректных и испорченных данных.
#[cfg(test)]
pub mod soft {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use sha2::{Digest, Sha256};

    pub struct SoftAuthenticator {
        pub key: SigningKey,
        pub credential_id: Vec<u8>,
    }

    impl SoftAuthenticator {
        /// Новый ключ со случайным credential id.
        pub fn generate() -> Self {
            Self {
                key: SigningKey::random(&mut rand::rngs::OsRng),
                credential_id: crate::crypto::rng::random_vec(48),
            }
        }

        pub fn public_key(&self) -> Vec<u8> {
            self.key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec()
        }

        fn header(flags: u8) -> Vec<u8> {
            let mut data = Sha256::digest(super::RP_ID.as_bytes()).to_vec();
            data.push(flags);
            data.extend_from_slice(&0u32.to_be_bytes());
            data
        }

        /// authenticatorData регистрации с attested credential data.
        pub fn registration(&self, user_verified: bool) -> Vec<u8> {
            let mut flags = super::FLAG_UP | super::FLAG_AT;
            if user_verified {
                flags |= super::FLAG_UV;
            }
            let mut data = Self::header(flags);
            data.extend_from_slice(&[0u8; 16]);
            data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
            data.extend_from_slice(&self.credential_id);
            let point = self.key.verifying_key().to_encoded_point(false);
            let mut cose = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
            cose.extend_from_slice(point.x().unwrap());
            cose.extend_from_slice(&[0x22, 0x58, 0x20]);
            cose.extend_from_slice(point.y().unwrap());
            data.extend_from_slice(&cose);
            data
        }

        /// (authenticatorData, DER-подпись) assertion'а.
        pub fn assertion(
            &self,
            client_data_json: &[u8],
            user_verified: bool,
        ) -> (Vec<u8>, Vec<u8>) {
            let mut flags = super::FLAG_UP;
            if user_verified {
                flags |= super::FLAG_UV;
            }
            let auth_data = Self::header(flags);
            let mut signed = auth_data.clone();
            signed.extend_from_slice(&Sha256::digest(client_data_json));
            let signature: Signature = self.key.sign(&signed);
            (auth_data, signature.to_der().as_bytes().to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::soft::SoftAuthenticator;
    use super::*;

    #[test]
    fn a_genuine_registration_and_assertion_verify() {
        let authenticator = SoftAuthenticator::generate();
        let (public_key, flags) = verify_registration(
            &authenticator.registration(true),
            &authenticator.credential_id,
            true,
        )
        .unwrap();
        assert_eq!(public_key, authenticator.public_key());
        assert!(flags.user_verified);

        let client = ClientData::new(Ceremony::Get);
        verify_client_data(&client.json, Ceremony::Get, &client.challenge).unwrap();
        let (auth_data, signature) = authenticator.assertion(&client.json, false);
        let flags =
            verify_assertion(&public_key, &auth_data, &client.json, &signature, false).unwrap();
        assert!(!flags.user_verified);
    }

    #[test]
    fn every_forged_part_of_an_assertion_is_rejected() {
        let authenticator = SoftAuthenticator::generate();
        let public_key = authenticator.public_key();
        let client = ClientData::new(Ceremony::Get);
        let (auth_data, signature) = authenticator.assertion(&client.json, true);

        // Чужой ключ.
        let other = SoftAuthenticator::generate().public_key();
        assert!(verify_assertion(&other, &auth_data, &client.json, &signature, false).is_err());
        // Подменённый clientData (другой challenge) — подпись не сходится.
        let replay = ClientData::new(Ceremony::Get);
        assert!(
            verify_assertion(&public_key, &auth_data, &replay.json, &signature, false).is_err()
        );
        // Подменённый флаг в authData — подпись не сходится.
        let mut flipped = auth_data.clone();
        flipped[32] ^= FLAG_UV;
        assert!(verify_assertion(&public_key, &flipped, &client.json, &signature, false).is_err());
        // Чужой RP.
        let mut foreign = auth_data.clone();
        foreign[0] ^= 1;
        assert!(verify_assertion(&public_key, &foreign, &client.json, &signature, false).is_err());
        // UV требуется, а его нет.
        let (no_uv, no_uv_sig) = authenticator.assertion(&client.json, false);
        assert!(verify_assertion(&public_key, &no_uv, &client.json, &no_uv_sig, true).is_err());
        // Challenge не наш.
        assert!(verify_client_data(&client.json, Ceremony::Get, &replay.challenge).is_err());
        assert!(verify_client_data(&client.json, Ceremony::Create, &client.challenge).is_err());
    }

    #[test]
    fn registration_with_a_mismatched_credential_id_is_rejected() {
        let authenticator = SoftAuthenticator::generate();
        let data = authenticator.registration(true);
        assert!(verify_registration(&data, b"another-credential", true).is_err());
        assert!(verify_registration(&data, &authenticator.credential_id, true).is_ok());
        // Без UV при требовании UV — отказ.
        let no_uv = authenticator.registration(false);
        assert!(verify_registration(&no_uv, &authenticator.credential_id, true).is_err());
    }

    #[test]
    fn malformed_cbor_is_rejected_without_panicking() {
        for data in [
            &[][..],
            &[0xa5][..],
            &[0xbf, 0xff][..],
            &[0x5b, 0xff, 0xff][..],
        ] {
            assert!(parse_cose_p256(data).is_err());
        }
        // Глубокая вложенность не переполняет стек.
        let mut nested = vec![0xa1, 0x04];
        nested.extend(std::iter::repeat_n(0x81, 64));
        nested.push(0x00);
        assert!(parse_cose_p256(&nested).is_err());
    }
}
