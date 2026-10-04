//! Настоящая ОС: CNG/TPM, WebAuthn (Windows Hello и внешние FIDO2-ключи).

use zeroize::Zeroizing;

use super::{HelloCredential, Platform, TpmCredential};
use crate::auth::fido2::{self, Fido2AssertionResult, Fido2Registration};
use crate::error::Result;
use crate::windows_api::{cng_hello, hello, key_credential};

pub struct WindowsPlatform {
    /// Приложение — для окна-родителя системных диалогов и очистки буфера.
    /// В аппаратных тестах приложения нет, родителем служит окно консоли.
    app: Option<tauri::AppHandle>,
}

impl WindowsPlatform {
    pub fn new(app: tauri::AppHandle) -> Self {
        Self { app: Some(app) }
    }

    /// Без приложения — для контрактных тестов на настоящем железе.
    #[cfg(test)]
    pub fn detached() -> Self {
        Self { app: None }
    }

    fn parent_window(&self) -> Result<isize> {
        match &self.app {
            Some(app) => hello::main_window_hwnd(app),
            None => Ok(console_window()),
        }
    }
}

#[cfg(test)]
fn console_window() -> isize {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetConsoleWindow() -> *mut std::ffi::c_void;
    }
    // SAFETY: функция без аргументов; NULL допустим как «нет окна».
    unsafe { GetConsoleWindow() as isize }
}

#[cfg(not(test))]
fn console_window() -> isize {
    0
}

impl Platform for WindowsPlatform {
    fn tpm_supported(&self) -> bool {
        cng_hello::is_supported()
    }

    fn tpm_new_key_name(&self) -> String {
        cng_hello::new_device_key_id()
    }

    fn tpm_create_device_key(&self, name: &str) -> Result<TpmCredential> {
        let created = cng_hello::create_device_key(name)?;
        Ok(TpmCredential {
            name: created.stored_id,
            signature: created.signature,
        })
    }

    fn tpm_sign_device_challenge(&self, name: &str) -> Result<Zeroizing<Vec<u8>>> {
        cng_hello::sign_device_challenge(name)
    }

    fn tpm_exists(&self, name: &str) -> Result<bool> {
        cng_hello::exists(name)
    }

    fn tpm_delete(&self, name: &str) -> Result<()> {
        cng_hello::delete(name)
    }

    fn hello_supported(&self) -> bool {
        key_credential::is_supported()
    }

    fn hello_create(&self, user_handle: &[u8; 16]) -> Result<HelloCredential> {
        let created = key_credential::create(self.parent_window()?, user_handle)?;
        Ok(HelloCredential {
            name: created.name,
            public_key: created.public_key,
        })
    }

    fn hello_verify(&self, name: &str, public_key: &[u8]) -> Result<()> {
        key_credential::verify(self.parent_window()?, name, public_key)
    }

    fn hello_exists(&self, name: &str) -> Result<bool> {
        key_credential::exists(name)
    }

    fn hello_find(&self, user_handle: &[u8; 16]) -> Result<Vec<String>> {
        key_credential::find_by_user(user_handle)
    }

    fn hello_delete(&self, name: &str) -> Result<()> {
        key_credential::delete(name)
    }

    fn fido_register(
        &self,
        name: &str,
        require_pin: bool,
        client_data_json: &[u8],
    ) -> Result<Fido2Registration> {
        fido2::register_fido2_key_prompt(name, require_pin, client_data_json)
    }

    fn fido_assert(
        &self,
        credentials: &[Vec<u8>],
        require_pin: bool,
        client_data_json: &[u8],
    ) -> Result<Fido2AssertionResult> {
        fido2::assert_fido2_key_prompt(credentials, require_pin, client_data_json)
    }

    fn now_unix(&self) -> i64 {
        chrono::Utc::now().timestamp()
    }

    fn on_lock(&self) {
        if let Some(app) = &self.app {
            crate::commands::clipboard::clear_on_lock(app);
        }
    }
}
