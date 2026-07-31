// TPM-backed Windows Hello unlock through CNG/NCrypt.
//
// This backend intentionally avoids WinRT KeyCredentialManager and WebAuthn PRF:
// both can recognize the user and still fail later in the platform credential
// layer on some Windows 11 systems. Here the cryptographic boundary is a
// persisted, non-exportable RSA signing key in the Microsoft Platform Crypto
// Provider. Windows Hello consent is requested through UserConsentVerifier
// before key use; raw CNG UI policy is intentionally not used because it asks
// the user to create a separate key password instead of using the Windows PIN.
//
// Security boundary: the private key is TPM-backed and non-exportable, but
// UserConsentVerifier is enforced by Vaultisor code, not by the key provider.
// This protects the normal app flow and prevents key extraction, but it is not
// equivalent to hardware-enforced per-use authorization against same-user code
// that can call CNG directly.

use sha2::{Digest, Sha256};
use uuid::Uuid;
use windows::core::HSTRING;
use windows::Win32::Foundation::HWND;
use windows::Win32::Security::Cryptography::*;
use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;
use windows_core::PCWSTR;

use crate::error::{Result, VaultError};

const CNG_PREFIX: &str = "cng-platform-rsa-v1:";
const KEY_BITS: u32 = 2048;

static CNG_OPERATION_LOCK: once_cell::sync::Lazy<std::sync::Mutex<()>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(()));

#[derive(Debug)]
pub struct CreatedCredential {
    pub stored_id: String,
    pub signature: Vec<u8>,
}

pub fn is_supported() -> bool {
    // Требуем именно TPM 2.0: Device Secret и PQ-Hello рассчитаны на надёжный
    // TPM 2.0. На TPM 1.x (SHA-1, меньше слотов, хрупкий RSA) уходим в режим
    // мастер-пароля — это чище, чем полагаться на нестабильный 1.x-путь.
    if !tpm_is_v2() {
        return false;
    }
    with_cng_lock(|| {
        let provider = ProviderHandle::open_platform()?;
        provider.require_hardware_backed()
    })
    .is_ok()
}

/// Версия физического TPM == 2.0? Через TBS (Tbsi_GetDeviceInfo). false, если
/// TPM нет, версия ниже 2.0, или TBS недоступен.
fn tpm_is_v2() -> bool {
    use windows::Win32::System::TpmBaseServices::{
        Tbsi_GetDeviceInfo, TPM_DEVICE_INFO, TPM_VERSION_20,
    };
    let mut info = TPM_DEVICE_INFO::default();
    // SAFETY: Calling Tbsi_GetDeviceInfo with valid size and mutable pointer to a local TPM_DEVICE_INFO struct.
    let rc = unsafe {
        Tbsi_GetDeviceInfo(
            std::mem::size_of::<TPM_DEVICE_INFO>() as u32,
            &mut info as *mut _ as *mut core::ffi::c_void,
        )
    };
    // TBS_SUCCESS == 0.
    if rc != 0 {
        log::warn!("Tbsi_GetDeviceInfo failed (rc=0x{rc:x}) — treating TPM as unavailable");
        return false;
    }
    let is_v2 = info.tpmVersion == TPM_VERSION_20;
    log::info!(
        "TPM device info: tpmVersion={} (2.0 required → supported={})",
        info.tpmVersion,
        is_v2
    );
    is_v2
}

pub async fn create_and_sign(
    app: &tauri::AppHandle,
    challenge: &'static [u8],
) -> Result<CreatedCredential> {
    let hwnd = crate::windows_api::hello::main_window_hwnd(app)?;
    crate::windows_api::hello::verify_with_window(
        app,
        hwnd,
        "Подтвердите Windows Hello для создания TPM-ключа Vaultisor",
    )
    .await?;
    tauri::async_runtime::spawn_blocking(move || {
        with_cng_lock(|| create_and_sign_blocking(hwnd, challenge))
    })
    .await
    .map_err(|e| VaultError::System(format!("CNG Hello create task failed: {e}")))?
}

pub async fn sign(
    app: &tauri::AppHandle,
    stored_id: &str,
    challenge: &'static [u8],
) -> Result<Vec<u8>> {
    let key_name = decode_key_name(stored_id)?.to_owned();
    let hwnd = crate::windows_api::hello::main_window_hwnd(app)?;
    crate::windows_api::hello::verify_with_window(
        app,
        hwnd,
        "Подтвердите Windows Hello для разблокировки Vaultisor",
    )
    .await?;
    tauri::async_runtime::spawn_blocking(move || {
        with_cng_lock(|| sign_blocking(hwnd, &key_name, challenge))
    })
    .await
    .map_err(|e| VaultError::System(format!("CNG Hello sign task failed: {e}")))?
}

pub async fn create_and_sign_silent(
    challenge: &'static [u8],
) -> Result<CreatedCredential> {
    tauri::async_runtime::spawn_blocking(move || {
        with_cng_lock(|| create_and_sign_silent_blocking(challenge))
    })
    .await
    .map_err(|e| VaultError::System(format!("CNG silent create task failed: {e}")))?
}

pub async fn sign_silent(
    stored_id: &str,
    challenge: &'static [u8],
) -> Result<Vec<u8>> {
    let key_name = decode_key_name(stored_id)?.to_owned();
    tauri::async_runtime::spawn_blocking(move || {
        with_cng_lock(|| sign_silent_blocking(&key_name, challenge))
    })
    .await
    .map_err(|e| VaultError::System(format!("CNG silent sign task failed: {e}")))?
}

pub fn delete(stored_id: &str) -> Result<()> {
    let key_name = decode_key_name(stored_id)?.to_owned();
    with_cng_lock(|| {
        let provider = ProviderHandle::open_platform()?;
        let mut key = provider.open_key(&key_name)?;
        // SAFETY: key.raw() is a valid handle from a successful NCryptOpenKey. NCryptDeleteKey frees the key in the provider.
        unsafe {
            NCryptDeleteKey(key.raw(), 0)
                .map_err(|e| VaultError::System(format!("NCryptDeleteKey: {e}")))?;
        }
        key.disarm();
        Ok(())
    })
}

fn create_and_sign_blocking(hwnd_raw: isize, challenge: &[u8]) -> Result<CreatedCredential> {
    log::info!("CNG Hello: create TPM key");
    let provider = ProviderHandle::open_platform()?;
    provider.require_hardware_backed()?;

    let key_name = format!("Vaultisor-CNG-{}", Uuid::new_v4());
    let key = provider.create_key(&key_name)?;
    key.set_window(hwnd_raw)?;
    key.set_u32(NCRYPT_LENGTH_PROPERTY, KEY_BITS, "NCRYPT_LENGTH_PROPERTY")?;
    key.set_u32(
        NCRYPT_KEY_USAGE_PROPERTY,
        NCRYPT_ALLOW_SIGNING_FLAG,
        "NCRYPT_KEY_USAGE_PROPERTY",
    )?;
    key.set_u32(NCRYPT_EXPORT_POLICY_PROPERTY, 0, "NCRYPT_EXPORT_POLICY_PROPERTY")?;
    // AUDIT H2/H3: НАМЕРЕННО НЕ ставим NCRYPT_UI_POLICY.
    //
    // Прежний код выставлял NcryptUiPolicy с flags=0x4 и комментарием «enforced
    // by the platform crypto provider» — это было и неверно (0x4 — неопределённый
    // бит, реальный NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG = 0x2), и вредно: на
    // Platform-провайдере эта политика показывает диалог «создать отдельный
    // пароль ключа», а НЕ Windows Hello с лицом/PIN (см. шапку файла). То есть
    // включение флага сломало бы биометрический вход по лицу.
    //
    // Поэтому согласие пользователя запрашивается на уровне приложения через
    // UserConsentVerifier (hello::verify_with_window), который и показывает лицо.
    // Остаточный риск (H3): код в той же сессии Windows может вызвать
    // NCryptSignHash напрямую без биометрии. Это тот же принятый класс угроз
    // «same-user malware», что задокументирован в шапке файла; закрыть его
    // платформенным принуждением нельзя без потери лицо-входа.
    // SAFETY: key.raw() is a valid handle to a newly created key. NCryptFinalizeKey finalizes the key setup without memory unsafety.
    unsafe {
        NCryptFinalizeKey(key.raw(), NCRYPT_FLAGS(0))
            .map_err(|e| VaultError::System(format!("NCryptFinalizeKey: {e}")))?;
    }
    key.assert_private_export_denied()?;

    let signature = sign_with_key(&key, challenge)?;
    let stored_id = format!("{}{}", CNG_PREFIX, key_name);
    log::info!("CNG Hello: TPM key created and signed");
    Ok(CreatedCredential {
        stored_id,
        signature,
    })
}

fn sign_blocking(hwnd_raw: isize, key_name: &str, challenge: &[u8]) -> Result<Vec<u8>> {
    log::info!("CNG Hello: open TPM key");
    let provider = ProviderHandle::open_platform()?;
    provider.require_hardware_backed()?;
    let key = provider.open_key(key_name)?;
    key.set_window(hwnd_raw)?;
    key.assert_private_export_denied()?;
    sign_with_key(&key, challenge)
}

fn create_and_sign_silent_blocking(challenge: &[u8]) -> Result<CreatedCredential> {
    log::info!("CNG silent: create TPM key");
    let provider = ProviderHandle::open_platform()?;
    provider.require_hardware_backed()?;

    let key_name = format!("Vaultisor-CNG-{}", Uuid::new_v4());
    let key = provider.create_key(&key_name)?;
    key.set_u32(NCRYPT_LENGTH_PROPERTY, KEY_BITS, "NCRYPT_LENGTH_PROPERTY")?;
    key.set_u32(
        NCRYPT_KEY_USAGE_PROPERTY,
        NCRYPT_ALLOW_SIGNING_FLAG,
        "NCRYPT_KEY_USAGE_PROPERTY",
    )?;
    key.set_u32(NCRYPT_EXPORT_POLICY_PROPERTY, 0, "NCRYPT_EXPORT_POLICY_PROPERTY")?;
    
    // SAFETY: key.raw() is a valid handle. Finalizes the key setup.
    unsafe {
        NCryptFinalizeKey(key.raw(), NCRYPT_FLAGS(0))
            .map_err(|e| VaultError::System(format!("NCryptFinalizeKey: {e}")))?;
    }
    key.assert_private_export_denied()?;

    let signature = sign_with_key(&key, challenge)?;
    let stored_id = format!("{}{}", CNG_PREFIX, key_name);
    log::info!("CNG silent: TPM key created and signed silently");
    Ok(CreatedCredential {
        stored_id,
        signature,
    })
}

fn sign_silent_blocking(key_name: &str, challenge: &[u8]) -> Result<Vec<u8>> {
    log::info!("CNG silent: open TPM key");
    let provider = ProviderHandle::open_platform()?;
    provider.require_hardware_backed()?;
    let key = provider.open_key(key_name)?;
    key.assert_private_export_denied()?;
    sign_with_key(&key, challenge)
}

fn sign_with_key(key: &KeyHandle, challenge: &[u8]) -> Result<Vec<u8>> {
    let digest = Sha256::digest(challenge);
    let padding = BCRYPT_PKCS1_PADDING_INFO {
        pszAlgId: NCRYPT_SHA256_ALGORITHM,
    };
    let mut required = 0u32;
    // SAFETY: First call to NCryptSignHash with a null output buffer gets the required size. Pointers point to valid local variables.
    unsafe {
        NCryptSignHash(
            key.raw(),
            Some((&padding as *const BCRYPT_PKCS1_PADDING_INFO).cast()),
            &digest,
            None,
            &mut required,
            NCRYPT_PAD_PKCS1_FLAG,
        )
        .map_err(|e| VaultError::System(format!("NCryptSignHash(size): {e}")))?;
    }
    if required == 0 {
        return Err(VaultError::System(
            "NCryptSignHash returned empty signature size".into(),
        ));
    }

    let mut signature = vec![0u8; required as usize];
    let mut written = 0u32;
    // SAFETY: Second call to NCryptSignHash fills the allocated signature buffer. Buffer is properly sized from the first call.
    unsafe {
        NCryptSignHash(
            key.raw(),
            Some((&padding as *const BCRYPT_PKCS1_PADDING_INFO).cast()),
            &digest,
            Some(&mut signature),
            &mut written,
            NCRYPT_PAD_PKCS1_FLAG,
        )
        .map_err(|e| VaultError::System(format!("NCryptSignHash: {e}")))?;
    }
    signature.truncate(written as usize);
    log::info!("CNG Hello: Sign OK ({} bytes)", signature.len());
    Ok(signature)
}

fn decode_key_name(stored_id: &str) -> Result<&str> {
    stored_id
        .strip_prefix(CNG_PREFIX)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| VaultError::System("not a CNG TPM credential id".into()))
}

fn with_cng_lock<R>(f: impl FnOnce() -> Result<R>) -> Result<R> {
    let _guard = CNG_OPERATION_LOCK
        .lock()
        .map_err(|_| VaultError::System("CNG operation lock poisoned".into()))?;
    f()
}

struct ProviderHandle(Option<NCRYPT_PROV_HANDLE>);

impl ProviderHandle {
    fn open_platform() -> Result<Self> {
        let mut handle = NCRYPT_PROV_HANDLE::default();
        // SAFETY: Passes a mutable pointer to a local handle, initialized by the FFI call if successful.
        unsafe {
            NCryptOpenStorageProvider(&mut handle, MS_PLATFORM_CRYPTO_PROVIDER, 0)
                .map_err(|e| VaultError::System(format!("NCryptOpenStorageProvider(Platform): {e}")))?;
        }
        Ok(Self(Some(handle)))
    }

    fn raw(&self) -> NCRYPT_PROV_HANDLE {
        self.0.expect("provider handle already released")
    }

    fn require_hardware_backed(&self) -> Result<()> {
        let impl_type = get_u32_property(self.raw().into(), NCRYPT_IMPL_TYPE_PROPERTY)?;
        if impl_type & NCRYPT_IMPL_HARDWARE_FLAG == 0 {
            return Err(VaultError::System(format!(
                "Microsoft Platform Crypto Provider is not hardware-backed (Impl Type=0x{impl_type:x})"
            )));
        }
        log::info!("CNG Hello: platform provider hardware-backed (Impl Type=0x{impl_type:x})");
        Ok(())
    }

    fn create_key(&self, key_name: &str) -> Result<KeyHandle> {
        let mut handle = NCRYPT_KEY_HANDLE::default();
        let name = HSTRING::from(key_name);
        // SAFETY: Passes valid provider handle and mutable pointer to a local key handle. Key name HSTRING outlives the call.
        unsafe {
            NCryptCreatePersistedKey(
                self.raw(),
                &mut handle,
                NCRYPT_RSA_ALGORITHM,
                &name,
                CERT_KEY_SPEC(0),
                NCRYPT_OVERWRITE_KEY_FLAG,
            )
            .map_err(|e| VaultError::System(format!("NCryptCreatePersistedKey(Platform/RSA): {e}")))?;
        }
        Ok(KeyHandle(Some(handle)))
    }

    fn open_key(&self, key_name: &str) -> Result<KeyHandle> {
        let mut handle = NCRYPT_KEY_HANDLE::default();
        let name = HSTRING::from(key_name);
        // SAFETY: Passes valid provider handle and mutable pointer to a local key handle. Key name HSTRING outlives the call.
        unsafe {
            NCryptOpenKey(
                self.raw(),
                &mut handle,
                &name,
                windows::Win32::Security::Cryptography::CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
            .map_err(|e| VaultError::System(format!("NCryptOpenKey: {e}")))?;
        }
        Ok(KeyHandle(Some(handle)))
    }
}

impl Drop for ProviderHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            // SAFETY: We own the handle which was successfully opened, and we take it to ensure it is freed exactly once.
            unsafe {
                let _ = NCryptFreeObject(handle.into());
            }
        }
    }
}

struct KeyHandle(Option<NCRYPT_KEY_HANDLE>);

impl KeyHandle {
    fn raw(&self) -> NCRYPT_KEY_HANDLE {
        self.0.expect("key handle already released")
    }

    fn disarm(&mut self) {
        self.0 = None;
    }

    fn set_window(&self, hwnd_raw: isize) -> Result<()> {
        let hwnd = HWND(hwnd_raw as *mut _);
        set_property(
            self.raw().into(),
            NCRYPT_WINDOW_HANDLE_PROPERTY,
            bytes_of(&hwnd),
            NCRYPT_FLAGS(0),
            "NCRYPT_WINDOW_HANDLE_PROPERTY",
        )
    }

    fn set_u32(&self, property: PCWSTR, value: u32, label: &str) -> Result<()> {
        set_property(
            self.raw().into(),
            property,
            bytes_of(&value),
            NCRYPT_PERSIST_FLAG,
            label,
        )
    }

    fn assert_private_export_denied(&self) -> Result<()> {
        let mut required = 0u32;
        // SAFETY: Calling NCryptExportKey to check exportability. Null output buffer safely checks required size or returns failure.
        let export_result = unsafe {
            NCryptExportKey(
                self.raw(),
                None,
                BCRYPT_PRIVATE_KEY_BLOB,
                None,
                None,
                &mut required,
                NCRYPT_FLAGS(0),
            )
        };
        if export_result.is_ok() {
            return Err(VaultError::System(
                "TPM key private export unexpectedly succeeded".into(),
            ));
        }
        log::info!("CNG Hello: private key export denied as expected");
        Ok(())
    }
}

impl Drop for KeyHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            // SAFETY: We own the handle which was successfully opened, and we take it to ensure it is freed exactly once.
            unsafe {
                let _ = NCryptFreeObject(handle.into());
            }
        }
    }
}

fn set_property(
    handle: NCRYPT_HANDLE,
    property: PCWSTR,
    bytes: &[u8],
    flags: NCRYPT_FLAGS,
    label: &str,
) -> Result<()> {
    // SAFETY: handle is valid, property points to valid wide string, and bytes slice is valid for the duration of the call.
    unsafe {
        NCryptSetProperty(handle, property, bytes, flags)
            .map_err(|e| VaultError::System(format!("{label}: {e}")))
    }
}

fn get_u32_property(handle: NCRYPT_HANDLE, property: PCWSTR) -> Result<u32> {
    let mut value = 0u32;
    let mut written = 0u32;
    // SAFETY: Retrieves property size into a mutable reference to a valid local u32 variable.
    unsafe {
        NCryptGetProperty(
            handle,
            property,
            Some(bytes_of_mut(&mut value)),
            &mut written,
            OBJECT_SECURITY_INFORMATION(0),
        )
        .map_err(|e| VaultError::System(format!("NCryptGetProperty(u32): {e}")))?;
    }
    if written as usize != std::mem::size_of::<u32>() {
        return Err(VaultError::System(format!(
            "NCryptGetProperty returned {} bytes for u32 property",
            written
        )));
    }
    Ok(value)
}

fn bytes_of<T>(value: &T) -> &[u8] {
    // SAFETY: The reference value is valid for size_of::<T>() bytes. Returns a slice with the same lifetime.
    unsafe {
        std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
    }
}

fn bytes_of_mut<T>(value: &mut T) -> &mut [u8] {
    // SAFETY: The mutable reference value is valid for size_of::<T>() bytes. Returns a mutable slice with the same lifetime.
    unsafe {
        std::slice::from_raw_parts_mut(
            (value as *mut T).cast::<u8>(),
            std::mem::size_of::<T>(),
        )
    }
}
