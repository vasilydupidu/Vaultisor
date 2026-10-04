//! Операции ОС, от которых зависит хранилище: TPM, Windows Hello, FIDO2.
//!
//! Команды обращаются к ним только через [`Os`]. Это даёт две вещи:
//! - тесты подменяют ОС ([`fake::FakePlatform`]) и проверяют сценарии
//!   целиком, включая сбой на каждом шаге;
//! - каждая операция, меняющая состояние ОС (создание и удаление ключей),
//!   проходит через точку отказа — ровно как запись на диск.
//!
//! Семантика, одинаковая для настоящей и тестовой ОС, закреплена контрактными
//! тестами ([`contract`]): удаление идемпотентно, `exists` отражает создание и
//! удаление, подпись детерминирована, найденный по user.id ключ — тот самый.
//!
//! Все методы блокирующие; из async-кода их вызывают через
//! [`crate::blocking::run`].

use std::sync::Arc;

use zeroize::Zeroizing;

use crate::auth::fido2::{Fido2AssertionResult, Fido2Registration};
use crate::error::Result;
use crate::failpoint;

#[cfg(test)]
pub mod contract;
#[cfg(test)]
pub mod fake;
#[cfg(windows)]
pub mod windows;

/// Неэкспортируемый TPM-ключ Device Secret и его подпись фиксированного
/// challenge (входной материал KEK).
pub struct TpmCredential {
    pub name: String,
    pub signature: Zeroizing<Vec<u8>>,
}

/// Платформенный WebAuthn-credential Windows Hello.
pub struct HelloCredential {
    pub name: String,
    /// Несжатый SEC1 P-256: 0x04 ‖ X ‖ Y.
    pub public_key: Vec<u8>,
}

/// То, что хранилищу нужно от операционной системы.
pub trait Platform: Send + Sync + 'static {
    fn tpm_supported(&self) -> bool;
    /// Имя для нового ключа. Выдаётся до создания, чтобы журнал операций
    /// записал его заранее.
    fn tpm_new_key_name(&self) -> String;
    fn tpm_create_device_key(&self, name: &str) -> Result<TpmCredential>;
    fn tpm_sign_device_challenge(&self, name: &str) -> Result<Zeroizing<Vec<u8>>>;
    fn tpm_exists(&self, name: &str) -> Result<bool>;
    /// Удалить ключ; отсутствие ключа — не ошибка.
    fn tpm_delete(&self, name: &str) -> Result<()>;

    fn hello_supported(&self) -> bool;
    /// Создать credential с заданным user.id и доказать его assertion.
    fn hello_create(&self, user_handle: &[u8; 16]) -> Result<HelloCredential>;
    fn hello_verify(&self, name: &str, public_key: &[u8]) -> Result<()>;
    fn hello_exists(&self, name: &str) -> Result<bool>;
    /// Имена credential'ов Vaultisor с данным user.id.
    fn hello_find(&self, user_handle: &[u8; 16]) -> Result<Vec<String>>;
    /// Удалить credential; отсутствие — не ошибка.
    fn hello_delete(&self, name: &str) -> Result<()>;

    /// `client_data_json` строит вызывающий: challenge — его, и проверять
    /// ответ будет он (`auth::webauthn_rp`).
    fn fido_register(
        &self,
        name: &str,
        require_pin: bool,
        client_data_json: &[u8],
    ) -> Result<Fido2Registration>;
    fn fido_assert(
        &self,
        credentials: &[Vec<u8>],
        require_pin: bool,
        client_data_json: &[u8],
    ) -> Result<Fido2AssertionResult>;

    /// Время UTC в секундах — для задержек после неверного PIN.
    fn now_unix(&self) -> i64;

    /// Побочные эффекты блокировки хранилища вне диска (буфер обмена).
    fn on_lock(&self);
}

/// Доступ команд к ОС. Операции, меняющие состояние ОС, начинаются с точки
/// отказа; чтение и проверки — без неё.
#[derive(Clone)]
pub struct Os(Arc<dyn Platform>);

impl Os {
    pub fn new(platform: Arc<dyn Platform>) -> Self {
        Self(platform)
    }

    pub fn tpm_supported(&self) -> bool {
        self.0.tpm_supported()
    }

    pub fn tpm_new_key_name(&self) -> String {
        self.0.tpm_new_key_name()
    }

    pub fn tpm_create_device_key(&self, name: &str) -> Result<TpmCredential> {
        failpoint::hit("tpm.create")?;
        self.0.tpm_create_device_key(name)
    }

    pub fn tpm_sign_device_challenge(&self, name: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.0.tpm_sign_device_challenge(name)
    }

    pub fn tpm_exists(&self, name: &str) -> Result<bool> {
        self.0.tpm_exists(name)
    }

    pub fn tpm_delete(&self, name: &str) -> Result<()> {
        failpoint::hit("tpm.delete")?;
        self.0.tpm_delete(name)
    }

    pub fn hello_supported(&self) -> bool {
        self.0.hello_supported()
    }

    pub fn hello_create(&self, user_handle: &[u8; 16]) -> Result<HelloCredential> {
        failpoint::hit("hello.create")?;
        self.0.hello_create(user_handle)
    }

    pub fn hello_verify(&self, name: &str, public_key: &[u8]) -> Result<()> {
        self.0.hello_verify(name, public_key)
    }

    pub fn hello_exists(&self, name: &str) -> Result<bool> {
        self.0.hello_exists(name)
    }

    pub fn hello_find(&self, user_handle: &[u8; 16]) -> Result<Vec<String>> {
        self.0.hello_find(user_handle)
    }

    pub fn hello_delete(&self, name: &str) -> Result<()> {
        failpoint::hit("hello.delete")?;
        self.0.hello_delete(name)
    }

    pub fn fido_register(
        &self,
        name: &str,
        require_pin: bool,
        client_data_json: &[u8],
    ) -> Result<Fido2Registration> {
        failpoint::hit("fido.register")?;
        self.0.fido_register(name, require_pin, client_data_json)
    }

    pub fn fido_assert(
        &self,
        credentials: &[Vec<u8>],
        require_pin: bool,
        client_data_json: &[u8],
    ) -> Result<Fido2AssertionResult> {
        self.0
            .fido_assert(credentials, require_pin, client_data_json)
    }

    pub fn now_unix(&self) -> i64 {
        self.0.now_unix()
    }

    pub fn on_lock(&self) {
        self.0.on_lock()
    }
}
