//! Тестовая ОС: TPM, Windows Hello и FIDO2-токены в памяти.
//!
//! Состояние живёт в `Arc` и переживает «перезапуск» приложения в тесте — как
//! настоящие TPM и хранилище ключей Windows переживают перезапуск процесса.
//! Семантика совпадает с `WindowsPlatform` и закреплена [`super::contract`].

use std::collections::{BTreeMap, BTreeSet};

use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{HelloCredential, Platform, TpmCredential};
use crate::auth::fido2::{Fido2AssertionResult, Fido2Registration};
use crate::error::{Result, VaultError};

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Внешний FIDO2-токен с настоящим ключом ES256: его подписи проходят (или
/// не проходят) ту же RP-проверку, что и подписи железа.
pub struct FakeToken {
    pub authenticator: crate::auth::webauthn_rp::soft::SoftAuthenticator,
    /// Задан ли на токене собственный ПИН (без него UV невозможен).
    pub has_pin: bool,
    /// Отдельные секреты hmac-secret для ответов с UV и без UV, как в CTAP 2.1.
    pub cred_random_uv: [u8; 32],
    pub cred_random_no_uv: [u8; 32],
}

/// Credential Windows Hello: user.id, с которым он создан, и его публичный
/// ключ (проверка Hello сверяет ключ, как настоящая ОС проверяет подпись).
struct FakeHello {
    user: [u8; 16],
    public_key: Vec<u8>,
}

#[derive(Default)]
struct State {
    tpm_supported: bool,
    tpm_keys: BTreeMap<String, [u8; 32]>,
    hello_supported: bool,
    /// Имя credential'а → его user.id и публичный ключ.
    hello_keys: BTreeMap<String, FakeHello>,
    /// Следующая проверка Hello провалится (пользователь отменил).
    hello_refuse: bool,
    /// credential_id → токен, на котором он создан.
    fido: BTreeMap<Vec<u8>, FakeToken>,
    /// Какой credential «поднесут» при следующем assertion.
    presented: Option<Vec<u8>>,
    counter: u64,
    /// Подменённые часы; None — настоящее время.
    clock: Option<i64>,
}

pub struct FakePlatform {
    state: Mutex<State>,
}

impl Default for FakePlatform {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                tpm_supported: true,
                hello_supported: true,
                ..State::default()
            }),
        }
    }
}

impl FakePlatform {
    fn next_id(&self, prefix: &str) -> String {
        let mut state = self.state.lock();
        state.counter += 1;
        format!("{prefix}{}", state.counter)
    }

    pub fn set_tpm_supported(&self, supported: bool) {
        self.state.lock().tpm_supported = supported;
    }

    /// Живые TPM-ключи — для проверки, что ни один не потерян и не осиротел.
    pub fn tpm_keys(&self) -> BTreeSet<String> {
        self.state.lock().tpm_keys.keys().cloned().collect()
    }

    pub fn hello_keys(&self) -> BTreeSet<String> {
        self.state.lock().hello_keys.keys().cloned().collect()
    }

    pub fn fido_credentials(&self) -> BTreeSet<Vec<u8>> {
        self.state.lock().fido.keys().cloned().collect()
    }

    /// Пользователь удалил ключ в «Параметры → Ключи доступа».
    pub fn forget_hello(&self, name: &str) {
        self.state.lock().hello_keys.remove(name);
    }

    pub fn refuse_next_hello(&self) {
        self.state.lock().hello_refuse = true;
    }

    /// Поднести токен с этим credential при следующем assertion.
    pub fn present(&self, credential_id: &[u8]) {
        self.state.lock().presented = Some(credential_id.to_vec());
    }

    /// Выставить часы ОС (секунды UTC).
    pub fn set_clock(&self, unix: i64) {
        self.state.lock().clock = Some(unix);
    }

    /// Сдвинуть часы ОС.
    pub fn advance_clock(&self, seconds: i64) {
        let now = self.now_unix();
        self.state.lock().clock = Some(now + seconds);
    }

    /// Токен, но под «другим экземпляром» ОС: тот же физический ключ, что
    /// поднесут к чужому компьютеру.
    pub fn share_tokens_with(&self, other: &FakePlatform) {
        let mut mine = self.state.lock();
        let theirs = other.state.lock();
        for (id, token) in &theirs.fido {
            mine.fido.insert(
                id.clone(),
                FakeToken {
                    authenticator: crate::auth::webauthn_rp::soft::SoftAuthenticator {
                        key: token.authenticator.key.clone(),
                        credential_id: token.authenticator.credential_id.clone(),
                    },
                    has_pin: token.has_pin,
                    cred_random_uv: token.cred_random_uv,
                    cred_random_no_uv: token.cred_random_no_uv,
                },
            );
        }
        mine.presented = theirs.presented.clone();
    }
}

impl Platform for FakePlatform {
    fn tpm_supported(&self) -> bool {
        self.state.lock().tpm_supported
    }

    fn tpm_new_key_name(&self) -> String {
        format!("cng-platform-rsa-v1:Vaultisor-CNG-{}", uuid::Uuid::new_v4())
    }

    fn tpm_create_device_key(&self, name: &str) -> Result<TpmCredential> {
        {
            let mut state = self.state.lock();
            if !state.tpm_supported {
                return Err(VaultError::TpmUnavailable);
            }
            // Как NCryptCreatePersistedKey без флага перезаписи.
            if state.tpm_keys.contains_key(name) {
                return Err(VaultError::System(
                    "NCryptCreatePersistedKey: exists".into(),
                ));
            }
            state
                .tpm_keys
                .insert(name.to_owned(), crate::crypto::rng::random_array());
        }
        let signature = self.tpm_sign_device_challenge(name)?;
        Ok(TpmCredential {
            name: name.to_owned(),
            signature,
        })
    }

    fn tpm_sign_device_challenge(&self, name: &str) -> Result<Zeroizing<Vec<u8>>> {
        let state = self.state.lock();
        let secret = state.tpm_keys.get(name).ok_or(VaultError::TpmUnavailable)?;
        Ok(Zeroizing::new(
            hmac(secret, crate::crypto::device_secret::DS_KEK_CHALLENGE).to_vec(),
        ))
    }

    fn tpm_exists(&self, name: &str) -> Result<bool> {
        Ok(self.state.lock().tpm_keys.contains_key(name))
    }

    fn tpm_delete(&self, name: &str) -> Result<()> {
        self.state.lock().tpm_keys.remove(name);
        Ok(())
    }

    fn hello_supported(&self) -> bool {
        self.state.lock().hello_supported
    }

    fn hello_create(&self, user_handle: &[u8; 16]) -> Result<HelloCredential> {
        let name = self.next_id("webauthn-platform-v1:fake-");
        // Несжатый SEC1: 0x04 ‖ X ‖ Y; у каждого credential'а свой.
        let mut public_key = vec![4u8];
        public_key.extend_from_slice(&crate::crypto::rng::random_vec(64));
        self.state.lock().hello_keys.insert(
            name.clone(),
            FakeHello {
                user: *user_handle,
                public_key: public_key.clone(),
            },
        );
        Ok(HelloCredential { name, public_key })
    }

    fn hello_verify(&self, name: &str, public_key: &[u8]) -> Result<()> {
        let mut state = self.state.lock();
        if std::mem::take(&mut state.hello_refuse) {
            return Err(VaultError::HelloCancelled);
        }
        match state.hello_keys.get(name) {
            // Подпись чужим ключом настоящая ОС не пропустила бы.
            Some(hello) if hello.public_key == public_key => Ok(()),
            Some(_) => Err(VaultError::CorruptedWrapper),
            None => Err(VaultError::HelloOsError("0x80090011 NotFound".into())),
        }
    }

    fn hello_exists(&self, name: &str) -> Result<bool> {
        Ok(self.state.lock().hello_keys.contains_key(name))
    }

    fn hello_find(&self, user_handle: &[u8; 16]) -> Result<Vec<String>> {
        Ok(self
            .state
            .lock()
            .hello_keys
            .iter()
            .filter(|(_, hello)| hello.user == *user_handle)
            .map(|(name, _)| name.clone())
            .collect())
    }

    fn hello_delete(&self, name: &str) -> Result<()> {
        self.state.lock().hello_keys.remove(name);
        Ok(())
    }

    fn fido_register(
        &self,
        _name: &str,
        require_pin: bool,
        _client_data_json: &[u8],
    ) -> Result<Fido2Registration> {
        let token = FakeToken {
            authenticator: crate::auth::webauthn_rp::soft::SoftAuthenticator::generate(),
            has_pin: require_pin,
            cred_random_uv: crate::crypto::rng::random_array(),
            cred_random_no_uv: crate::crypto::rng::random_array(),
        };
        let credential_id = token.authenticator.credential_id.clone();
        let authenticator_data = token.authenticator.registration(require_pin);
        let mut state = self.state.lock();
        state.fido.insert(credential_id.clone(), token);
        state.presented = Some(credential_id.clone());
        Ok(Fido2Registration {
            credential_id,
            authenticator_data,
            aaguid: [0; 16],
            prf_supported: true,
        })
    }

    fn fido_assert(
        &self,
        credentials: &[Vec<u8>],
        require_pin: bool,
        client_data_json: &[u8],
    ) -> Result<Fido2AssertionResult> {
        let state = self.state.lock();
        let presented = state
            .presented
            .clone()
            .filter(|id| credentials.contains(id))
            .ok_or_else(|| VaultError::FidoFailed("no matching authenticator".into()))?;
        let token = state
            .fido
            .get(&presented)
            .ok_or_else(|| VaultError::FidoFailed("unknown credential".into()))?;
        if require_pin && !token.has_pin {
            return Err(VaultError::FidoFailed("token has no PIN".into()));
        }
        let user_verified = token.has_pin && require_pin;
        let cred_random = if user_verified {
            &token.cred_random_uv
        } else {
            &token.cred_random_no_uv
        };
        let (authenticator_data, signature) = token
            .authenticator
            .assertion(client_data_json, user_verified);
        Ok(Fido2AssertionResult {
            credential_id: presented.clone(),
            authenticator_data,
            signature,
            prf_output: Some(Zeroizing::new(
                hmac(cred_random, crate::auth::fido2::PRF_SALT).to_vec(),
            )),
        })
    }

    fn now_unix(&self) -> i64 {
        self.state
            .lock()
            .clock
            .unwrap_or_else(|| chrono::Utc::now().timestamp())
    }

    fn on_lock(&self) {}
}
