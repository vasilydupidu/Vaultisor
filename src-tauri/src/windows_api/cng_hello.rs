// TPM-ключ Device Secret через CNG/NCrypt (Microsoft Platform Crypto Provider).
//
// Неэкспортируемый RSA-2048 в Platform KSP подписывает фиксированный challenge
// домена Device Secret; из подписи выводится KEK секрета устройства. Подпись
// выполняется без жеста пользователя: ключ привязывает хранилище к этой
// машине, но не подтверждает присутствие человека. Любой код, работающий под
// той же учётной записью, может вызвать ту же подпись — это граница модели
// угроз, описанная в SECURITY.md.

use sha2::{Digest, Sha256};
use uuid::Uuid;
use windows::core::HSTRING;
use windows::Win32::Security::Cryptography::*;
use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;
use windows_core::PCWSTR;

use crate::error::{Result, VaultError};

const CNG_PREFIX: &str = "cng-platform-rsa-v1:";
const KEY_BITS: u32 = 2048;

static CNG_OPERATION_LOCK: once_cell::sync::Lazy<std::sync::Mutex<()>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(()));

pub struct CreatedCredential {
    pub stored_id: String,
    /// AUDIT 3.1.1: подпись — это входной материал KEK, поэтому она живёт в
    /// Zeroizing и не попадает в Debug-вывод.
    pub signature: zeroize::Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for CreatedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedCredential")
            .field("stored_id", &self.stored_id)
            .field("signature_len", &self.signature.len())
            .finish()
    }
}

pub fn is_supported() -> bool {
    // Требуем именно TPM 2.0. На TPM 1.x (SHA-1, хрупкий RSA) хранилище
    // создаётся в режиме мастер-пароля, а не на ненадёжном аппаратном якоре.
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

/// Создать TPM-ключ Device Secret и подписать им challenge домена DS.
///
/// Домен подписи зафиксирован: универсального примитива «подпиши что угодно
/// ключом без жеста пользователя» здесь нет.
///
/// Имя выбирает вызывающий: журнал операций записывает его ДО создания ключа,
/// чтобы после сбоя можно было найти и удалить ключ, не попавший в метаданные.
pub(crate) fn create_device_key(stored_id: &str) -> Result<CreatedCredential> {
    let key_name = decode_key_name(stored_id)?.to_owned();
    with_cng_lock(|| {
        create_platform_credential(&key_name, crate::crypto::device_secret::DS_KEK_CHALLENGE)
    })
}

/// Новое имя ключа Device Secret в формате хранимого идентификатора.
pub(crate) fn new_device_key_id() -> String {
    format!("{CNG_PREFIX}Vaultisor-CNG-{}", Uuid::new_v4())
}

/// Существует ли ключ в Platform KSP.
pub(crate) fn exists(stored_id: &str) -> Result<bool> {
    let key_name = decode_key_name(stored_id)?.to_owned();
    with_cng_lock(|| {
        let provider = ProviderHandle::open_platform()?;
        Ok(provider.try_open_key(&key_name)?.is_some())
    })
}

/// Подписать challenge домена Device Secret существующим TPM-ключом.
pub(crate) fn sign_device_challenge(stored_id: &str) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let key_name = decode_key_name(stored_id)?.to_owned();
    with_cng_lock(|| {
        sign_silent_blocking(&key_name, crate::crypto::device_secret::DS_KEK_CHALLENGE)
    })
}

/// Удалить ключ. Отсутствующий ключ — не ошибка: очистка после сбоя должна
/// быть идемпотентной и безопасно повторяться.
pub fn delete(stored_id: &str) -> Result<()> {
    let key_name = decode_key_name(stored_id)?.to_owned();
    with_cng_lock(|| {
        let provider = ProviderHandle::open_platform()?;
        let Some(mut key) = provider.try_open_key(&key_name)? else {
            return Ok(());
        };
        // SAFETY: key.raw() is a valid handle from a successful NCryptOpenKey. NCryptDeleteKey frees the key in the provider.
        unsafe {
            NCryptDeleteKey(key.raw(), 0)
                .map_err(|e| VaultError::System(format!("NCryptDeleteKey: {e}")))?;
        }
        key.disarm();
        drop(provider);
        Ok(())
    })
}

fn create_platform_credential(key_name: &str, challenge: &[u8]) -> Result<CreatedCredential> {
    log::info!("CNG: create TPM key");
    // Постоянные ключи приложения живут в Platform KSP: Passport KSP на
    // потребительских сборках открывается, но отвергает
    // NCryptCreatePersistedKey с NTE_INVALID_PARAMETER.
    let provider = ProviderHandle::open_platform()?;
    provider.require_hardware_backed()?;

    let mut key = provider.create_key(key_name)?;
    key.set_u32(NCRYPT_LENGTH_PROPERTY, KEY_BITS, "NCRYPT_LENGTH_PROPERTY")?;
    key.set_u32(
        NCRYPT_KEY_USAGE_PROPERTY,
        NCRYPT_ALLOW_SIGNING_FLAG,
        "NCRYPT_KEY_USAGE_PROPERTY",
    )?;
    key.set_u32(
        NCRYPT_EXPORT_POLICY_PROPERTY,
        0,
        "NCRYPT_EXPORT_POLICY_PROPERTY",
    )?;

    // SAFETY: key.raw() is a valid handle to a newly created key. NCryptFinalizeKey finalizes the key setup without memory unsafety.
    unsafe {
        NCryptFinalizeKey(key.raw(), NCRYPT_FLAGS(0))
            .map_err(|e| VaultError::System(format!("NCryptFinalizeKey: {e}")))?;
    }
    key.assert_private_export_denied()?;

    let signature = sign_with_key(&key, challenge)?;
    let stored_id = format!("{}{}", CNG_PREFIX, key_name);
    key.1 = false; // Keep the persisted key only after setup and signing succeed.
    log::info!("CNG: TPM key created and signed");
    Ok(CreatedCredential {
        stored_id,
        signature,
    })
}

fn sign_silent_blocking(key_name: &str, challenge: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    log::info!("CNG silent: open TPM key");
    let provider = ProviderHandle::open_platform()?;
    provider.require_hardware_backed()?;
    let key = provider.open_key(key_name)?;
    key.assert_private_export_denied()?;
    sign_with_key(&key, challenge)
}

fn sign_with_key(key: &KeyHandle, challenge: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
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
    Ok(zeroize::Zeroizing::new(signature))
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
            NCryptOpenStorageProvider(&mut handle, MS_PLATFORM_CRYPTO_PROVIDER, 0).map_err(
                |e| VaultError::System(format!("NCryptOpenStorageProvider(Platform): {e}")),
            )?;
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
                // AUDIT 3.1.1: имя ключа — свежий UUID v4, поэтому коллизия
                // означала бы аномалию. Тихо перезаписывать чужой ключ нельзя.
                NCRYPT_FLAGS(0),
            )
            .map_err(|e| VaultError::System(format!("NCryptCreatePersistedKey(RSA): {e}")))?;
        }
        Ok(KeyHandle(Some(handle), true))
    }

    /// Открыть ключ; `None`, если такого ключа нет.
    fn try_open_key(&self, key_name: &str) -> Result<Option<KeyHandle>> {
        let mut handle = NCRYPT_KEY_HANDLE::default();
        let name = HSTRING::from(key_name);
        // SAFETY: Passes valid provider handle and mutable pointer to a local key handle. Key name HSTRING outlives the call.
        let opened = unsafe {
            NCryptOpenKey(
                self.raw(),
                &mut handle,
                &name,
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
        };
        match opened {
            Ok(()) => Ok(Some(KeyHandle(Some(handle), false))),
            Err(error) if error.code() == windows::Win32::Foundation::NTE_BAD_KEYSET => Ok(None),
            Err(error) => Err(VaultError::System(format!("NCryptOpenKey: {error}"))),
        }
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
        Ok(KeyHandle(Some(handle), false))
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

// The second field marks an uncommitted new key: failed setup must delete it.
struct KeyHandle(Option<NCRYPT_KEY_HANDLE>, bool);

impl KeyHandle {
    fn raw(&self) -> NCRYPT_KEY_HANDLE {
        self.0.expect("key handle already released")
    }

    fn disarm(&mut self) {
        self.0 = None;
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
        // AUDIT 3.1.1: одной неудачи NCryptExportKey недостаточно — провайдер
        // может отклонить сам тип blob (NTE_BAD_TYPE) независимо от политики
        // экспорта, и тогда «проверка» проходила бы даже у экспортируемого
        // ключа. Проверяем политику явно.
        let policy = get_u32_property(self.raw().into(), NCRYPT_EXPORT_POLICY_PROPERTY)?;
        let exportable = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
        if policy & exportable != 0 {
            return Err(VaultError::System(format!(
                "TPM key export policy allows export (0x{policy:x})"
            )));
        }
        log::info!("CNG Hello: private key export denied as expected (policy=0x{policy:x})");
        Ok(())
    }
}

impl Drop for KeyHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            // SAFETY: We exclusively own this newly created key handle.
            // Successful deletion also frees the handle.
            if self.1 && unsafe { NCryptDeleteKey(handle, 0) }.is_ok() {
                return;
            }
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
        std::slice::from_raw_parts_mut((value as *mut T).cast::<u8>(), std::mem::size_of::<T>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Аппаратный smoke-тест ровно той операции, что идёт при создании
    /// хранилища и при разблокировке. В обычном прогоне пропускается: нужен TPM 2.0.
    #[test]
    #[ignore = "requires a provisioned Windows TPM 2.0"]
    fn platform_tpm_rsa_create_sign_delete_roundtrip() {
        assert!(tpm_is_v2(), "TPM 2.0 is unavailable");
        let credential =
            create_device_key(&new_device_key_id()).expect("Platform KSP must create and sign");
        let reopened = sign_device_challenge(&credential.stored_id);
        let signature_len = credential.signature.len();
        delete(&credential.stored_id).expect("temporary TPM key must be deleted");
        assert_eq!(
            reopened.expect("re-signing with the persisted key must succeed"),
            credential.signature
        );
        assert_eq!(signature_len, (KEY_BITS / 8) as usize);
    }
}
