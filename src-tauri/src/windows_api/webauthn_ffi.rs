//! Единственный биндинг к `webauthn.dll`.
//!
//! Раньше у продукта было два независимых биндинга: `auth::fido2` для внешних
//! токенов и `windows_api::key_credential` для платформенного Windows Hello.
//! Они объявляли одни и те же структуры и функции дважды, расходясь в мелочах
//! (`hWnd` как `*mut` и как `*const`), и предупреждение
//! `clashing_extern_declarations` было подавлено. Компилятор такое расхождение
//! не ловит: переставленное поле в одной из копий заставило бы Windows читать
//! мусор по нашему указателю.
//!
//! Теперь каждая структура и функция объявлена ровно один раз. Разметка
//! сверена с `webauthn.h` тестами в `webauthn_layout`.
//!
//! Структуры версионированы, как в SDK: вызывающий заполняет `dwVersion` и
//! передаёт указатель на расширенную версию, приведённый к базовой — так
//! Windows понимает, до какого поля можно читать.

// Имена полей и констант повторяют webauthn.h дословно — так их проще сверять
// с SDK. `dead_code` не подавлен намеренно: неиспользуемая константа или
// функция здесь — повод удалить её, а не прятать.
#![allow(non_snake_case, non_upper_case_globals)]

use std::ffi::c_void;

// --- Константы ---

pub const WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION: u32 = 1;
pub const WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION: u32 = 1;
pub const WEBAUTHN_CLIENT_DATA_CURRENT_VERSION: u32 = 1;

pub const WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256: i32 = -7;
pub const WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY: &str = "public-key";

pub const WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM: u32 = 1;
pub const WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM: u32 = 2;

pub const WEBAUTHN_CTAP_TRANSPORT_USB: u32 = 0x00000001;
pub const WEBAUTHN_CTAP_TRANSPORT_NFC: u32 = 0x00000002;

pub const WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED: u32 = 1;
pub const WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED: u32 = 2;
pub const WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED: u32 = 3;

/// Режим hmac-secret с «сырыми» солями (webauthn.h, WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG).
pub const WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG: u32 = 0x00100000;

// --- Сущности церемонии ---

#[repr(C)]
pub struct WEBAUTHN_RP_ENTITY_INFORMATION {
    pub dwVersion: u32,
    pub pwszId: *const u16,
    pub pwszName: *const u16,
    pub pwszIcon: *const u16,
}

#[repr(C)]
pub struct WEBAUTHN_USER_ENTITY_INFORMATION {
    pub dwVersion: u32,
    pub cbId: u32,
    pub pbId: *const u8,
    pub pwszName: *const u16,
    pub pwszIcon: *const u16,
    pub pwszDisplayName: *const u16,
}

#[repr(C)]
pub struct WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
    pub dwVersion: u32,
    pub pwszCredentialType: *const u16,
    pub lAlg: i32,
}

#[repr(C)]
pub struct WEBAUTHN_COSE_CREDENTIAL_PARAMETER_LIST {
    pub cCredentialParameters: u32,
    pub pCredentialParameters: *const WEBAUTHN_COSE_CREDENTIAL_PARAMETER,
}

#[repr(C)]
pub struct WEBAUTHN_CLIENT_DATA {
    pub dwVersion: u32,
    pub cbClientDataJSON: u32,
    pub pbClientDataJSON: *const u8,
    pub pwszHashAlgId: *const u16,
}

// --- Credential'ы и списки ---

#[repr(C)]
pub struct WEBAUTHN_CREDENTIAL {
    pub dwVersion: u32,
    pub cbId: u32,
    pub pbId: *const u8,
    pub pwszCredentialType: *const u16,
}

#[repr(C)]
pub struct WEBAUTHN_CREDENTIALS {
    pub cCredentials: u32,
    pub pCredentials: *const WEBAUTHN_CREDENTIAL,
}

/// Credential с подсказкой транспорта — для `pAllowCredentialList` (V4+).
#[repr(C)]
pub struct WEBAUTHN_CREDENTIAL_EX {
    pub dwVersion: u32,
    pub cbId: u32,
    pub pbId: *const u8,
    pub pwszCredentialType: *const u16,
    pub dwTransports: u32,
}

#[repr(C)]
pub struct WEBAUTHN_CREDENTIAL_LIST {
    pub cCredentials: u32,
    pub ppCredentials: *const *const WEBAUTHN_CREDENTIAL_EX,
}

#[repr(C)]
pub struct WEBAUTHN_EXTENSIONS {
    pub cExtensions: u32,
    pub pExtensions: *const c_void,
}

// --- hmac-secret / PRF ---

#[repr(C)]
pub struct WEBAUTHN_HMAC_SECRET_SALT {
    pub cbFirst: u32,
    pub pbFirst: *mut u8,
    pub cbSecond: u32,
    pub pbSecond: *mut u8,
}

#[repr(C)]
pub struct WEBAUTHN_HMAC_SECRET_SALT_VALUES {
    pub pGlobalHmacSalt: *mut WEBAUTHN_HMAC_SECRET_SALT,
    pub cCredWithHmacSecretSaltList: u32,
    pub pCredWithHmacSecretSaltList: *mut c_void,
}

// --- Параметры регистрации ---

#[repr(C)]
pub struct WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_V1 {
    pub dwVersion: u32,
    pub dwTimeoutMilliseconds: u32,
    pub CredentialList: WEBAUTHN_CREDENTIALS,
    pub Extensions: WEBAUTHN_EXTENSIONS,
    pub dwAuthenticatorAttachment: u32,
    pub bRequireResidentKey: i32,
    pub dwUserVerificationRequirement: u32,
    pub dwAttestationConveyancePreference: u32,
    pub dwFlags: u32,
}

/// V6 добавляет `bEnablePrf` — запрос hmac-secret при регистрации.
#[repr(C)]
pub struct WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_V6 {
    pub dwVersion: u32,
    pub dwTimeoutMilliseconds: u32,
    pub CredentialList: WEBAUTHN_CREDENTIALS,
    pub Extensions: WEBAUTHN_EXTENSIONS,
    pub dwAuthenticatorAttachment: u32,
    pub bRequireResidentKey: i32,
    pub dwUserVerificationRequirement: u32,
    pub dwAttestationConveyancePreference: u32,
    pub dwFlags: u32,
    // V2
    pub pCancellationId: *const [u8; 16],
    // V3
    pub pExcludeCredentialList: *const WEBAUTHN_CREDENTIAL_LIST,
    // V4
    pub dwEnterpriseAttestation: u32,
    pub dwLargeBlobSupport: u32,
    pub bPreferResidentKey: i32,
    // V5
    pub bBrowserInPrivateMode: i32,
    // V6
    pub bEnablePrf: i32,
}

// --- Параметры входа ---

#[repr(C)]
pub struct WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_V1 {
    pub dwVersion: u32,
    pub dwTimeoutMilliseconds: u32,
    pub CredentialList: WEBAUTHN_CREDENTIALS,
    pub Extensions: WEBAUTHN_EXTENSIONS,
    pub dwAuthenticatorAttachment: u32,
    pub dwUserVerificationRequirement: u32,
    pub dwFlags: u32,
}

/// V4 добавляет `pAllowCredentialList` с подсказками транспорта.
#[repr(C)]
pub struct WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_V4 {
    pub dwVersion: u32,
    pub dwTimeoutMilliseconds: u32,
    pub CredentialList: WEBAUTHN_CREDENTIALS,
    pub Extensions: WEBAUTHN_EXTENSIONS,
    pub dwAuthenticatorAttachment: u32,
    pub dwUserVerificationRequirement: u32,
    pub dwFlags: u32,
    // V2
    pub pwszU2fAppId: *const u16,
    pub pbU2fAppId: *mut i32,
    // V3
    pub pCancellationId: *const [u8; 16],
    // V4
    pub pAllowCredentialList: *const WEBAUTHN_CREDENTIAL_LIST,
}

/// V6 добавляет `pHmacSecretSaltValues` — запрос PRF-секрета при входе.
#[repr(C)]
pub struct WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_V6 {
    pub dwVersion: u32,
    pub dwTimeoutMilliseconds: u32,
    pub CredentialList: WEBAUTHN_CREDENTIALS,
    pub Extensions: WEBAUTHN_EXTENSIONS,
    pub dwAuthenticatorAttachment: u32,
    pub dwUserVerificationRequirement: u32,
    pub dwFlags: u32,
    // V2
    pub pwszU2fAppId: *const u16,
    pub pbU2fAppId: *mut i32,
    // V3
    pub pCancellationId: *const [u8; 16],
    // V4
    pub pAllowCredentialList: *const WEBAUTHN_CREDENTIAL_LIST,
    // V5
    pub dwCredLargeBlobOperation: u32,
    pub cbCredLargeBlob: u32,
    pub pbCredLargeBlob: *mut u8,
    // V6
    pub pHmacSecretSaltValues: *mut WEBAUTHN_HMAC_SECRET_SALT_VALUES,
    pub bBrowserInPrivateMode: i32,
}

// --- Ответ на регистрацию ---

#[repr(C)]
pub struct WEBAUTHN_CREDENTIAL_ATTESTATION_V1 {
    pub dwVersion: u32,
    pub pwszFormatType: *const u16,
    pub cbAuthenticatorData: u32,
    pub pbAuthenticatorData: *const u8,
    pub cbAttestation: u32,
    pub pbAttestation: *const u8,
    pub dwAttestationDecodeType: u32,
    pub pvAttestationDecode: *const c_void,
    pub cbAttestationObject: u32,
    pub pbAttestationObject: *const u8,
    pub cbCredentialId: u32,
    pub pbCredentialId: *const u8,
}

/// V5 добавляет `bPrfEnabled`. Читать его можно только при `dwVersion >= 5`.
#[repr(C)]
pub struct WEBAUTHN_CREDENTIAL_ATTESTATION_V5 {
    pub dwVersion: u32,
    pub pwszFormatType: *const u16,
    pub cbAuthenticatorData: u32,
    pub pbAuthenticatorData: *const u8,
    pub cbAttestation: u32,
    pub pbAttestation: *const u8,
    pub dwAttestationDecodeType: u32,
    pub pvAttestationDecode: *const c_void,
    pub cbAttestationObject: u32,
    pub pbAttestationObject: *const u8,
    pub cbCredentialId: u32,
    pub pbCredentialId: *const u8,
    // V2
    pub Extensions: WEBAUTHN_EXTENSIONS,
    // V3
    pub dwUsedTransport: u32,
    // V4
    pub bEpAtt: i32,
    pub bLargeBlobSupported: i32,
    pub bResidentKey: i32,
    // V5
    pub bPrfEnabled: i32,
}

// --- Ответ на вход ---

#[repr(C)]
pub struct WEBAUTHN_ASSERTION_V1 {
    pub dwVersion: u32,
    pub cbAuthenticatorData: u32,
    pub pbAuthenticatorData: *const u8,
    pub cbSignature: u32,
    pub pbSignature: *const u8,
    pub Credential: WEBAUTHN_CREDENTIAL,
    pub cbUserId: u32,
    pub pbUserId: *const u8,
}

/// V3 добавляет `pHmacSecret` — PRF-секрет. Читать только при `dwVersion >= 3`.
#[repr(C)]
pub struct WEBAUTHN_ASSERTION_V3 {
    pub dwVersion: u32,
    pub cbAuthenticatorData: u32,
    pub pbAuthenticatorData: *const u8,
    pub cbSignature: u32,
    pub pbSignature: *const u8,
    pub Credential: WEBAUTHN_CREDENTIAL,
    pub cbUserId: u32,
    pub pbUserId: *const u8,
    // V2
    pub Extensions: WEBAUTHN_EXTENSIONS,
    pub cbCredLargeBlob: u32,
    pub pbCredLargeBlob: *const u8,
    pub dwCredLargeBlobStatus: u32,
    // V3
    pub pHmacSecret: *const WEBAUTHN_HMAC_SECRET_SALT,
}

// --- Удобные пустые значения ---

pub fn empty_credentials() -> WEBAUTHN_CREDENTIALS {
    WEBAUTHN_CREDENTIALS {
        cCredentials: 0,
        pCredentials: std::ptr::null(),
    }
}

pub fn empty_extensions() -> WEBAUTHN_EXTENSIONS {
    WEBAUTHN_EXTENSIONS {
        cExtensions: 0,
        pExtensions: std::ptr::null(),
    }
}

// --- Перечисление платформенных credential'ов (API v4+) ---

pub const WEBAUTHN_GET_CREDENTIALS_OPTIONS_VERSION_1: u32 = 1;

#[repr(C)]
pub struct WEBAUTHN_GET_CREDENTIALS_OPTIONS {
    pub dwVersion: u32,
    /// Фильтр по RP; NULL — все.
    pub pwszRpId: *const u16,
    pub bBrowserInPrivateMode: i32,
}

/// Версия 1 структуры; поля старших версий не читаются.
#[repr(C)]
pub struct WEBAUTHN_CREDENTIAL_DETAILS {
    pub dwVersion: u32,
    pub cbCredentialID: u32,
    pub pbCredentialID: *const u8,
    pub pRpInformation: *const WEBAUTHN_RP_ENTITY_INFORMATION,
    pub pUserInformation: *const WEBAUTHN_USER_ENTITY_INFORMATION,
    pub bRemovable: i32,
}

#[repr(C)]
pub struct WEBAUTHN_CREDENTIAL_DETAILS_LIST {
    pub cCredentialDetails: u32,
    pub ppCredentialDetails: *const *const WEBAUTHN_CREDENTIAL_DETAILS,
}

// --- Функции ---

/// Символы, появившиеся только в WebAuthn API v4 (Windows 11 22H2).
/// Статический импорт заставил бы загрузчик отказаться запускать весь exe на
/// более старых системах («точка входа не найдена»), даже если пользователь
/// никогда не включал Windows Hello. Поэтому они резолвятся во время выполнения.
pub type DeletePlatformCredentialFn = unsafe extern "system" fn(u32, *const u8) -> i32;
pub type GetPlatformCredentialListFn = unsafe extern "system" fn(
    *const WEBAUTHN_GET_CREDENTIALS_OPTIONS,
    *mut *mut WEBAUTHN_CREDENTIAL_DETAILS_LIST,
) -> i32;
pub type FreePlatformCredentialListFn =
    unsafe extern "system" fn(*mut WEBAUTHN_CREDENTIAL_DETAILS_LIST);

/// Адрес экспорта webauthn.dll или `None`, если на этой сборке Windows его нет.
fn resolve(name: windows::core::PCSTR) -> Option<unsafe extern "system" fn() -> isize> {
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    // SAFETY: webauthn.dll уже загружена статическими импортами ниже;
    // GetProcAddress возвращает None, если символа нет.
    unsafe {
        let module = GetModuleHandleW(windows::core::w!("webauthn.dll")).ok()?;
        GetProcAddress(module, name)
    }
}

pub fn delete_platform_credential_fn() -> Option<DeletePlatformCredentialFn> {
    let address = resolve(windows::core::s!("WebAuthNDeletePlatformCredential"))?;
    // SAFETY: сигнатура совпадает с webauthn.h.
    Some(unsafe {
        std::mem::transmute::<unsafe extern "system" fn() -> isize, DeletePlatformCredentialFn>(
            address,
        )
    })
}

pub fn platform_credential_list_fns(
) -> Option<(GetPlatformCredentialListFn, FreePlatformCredentialListFn)> {
    let get = resolve(windows::core::s!("WebAuthNGetPlatformCredentialList"))?;
    let free = resolve(windows::core::s!("WebAuthNFreePlatformCredentialList"))?;
    // SAFETY: сигнатуры совпадают с webauthn.h.
    unsafe {
        Some((
            std::mem::transmute::<unsafe extern "system" fn() -> isize, GetPlatformCredentialListFn>(
                get,
            ),
            std::mem::transmute::<unsafe extern "system" fn() -> isize, FreePlatformCredentialListFn>(
                free,
            ),
        ))
    }
}

#[link(name = "webauthn")]
extern "system" {
    pub fn WebAuthNGetApiVersionNumber() -> u32;

    pub fn WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(
        pbIsUserVerifyingPlatformAuthenticatorAvailable: *mut i32,
    ) -> i32;

    /// `pOptions` и `ppCredentialAttestation` передаются как указатели на V1;
    /// расширенные версии приводятся к ним, а версию сообщает `dwVersion`.
    pub fn WebAuthNAuthenticatorMakeCredential(
        hWnd: *mut c_void,
        pRpInformation: *const WEBAUTHN_RP_ENTITY_INFORMATION,
        pUserInformation: *const WEBAUTHN_USER_ENTITY_INFORMATION,
        pPubKeyCredParams: *const WEBAUTHN_COSE_CREDENTIAL_PARAMETER_LIST,
        pClientData: *const WEBAUTHN_CLIENT_DATA,
        pOptions: *const WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_V1,
        ppCredentialAttestation: *mut *mut WEBAUTHN_CREDENTIAL_ATTESTATION_V1,
    ) -> i32;

    pub fn WebAuthNFreeCredentialAttestation(
        pCredentialAttestation: *mut WEBAUTHN_CREDENTIAL_ATTESTATION_V1,
    );

    /// Те же правила версий, что и для регистрации.
    pub fn WebAuthNAuthenticatorGetAssertion(
        hWnd: *mut c_void,
        pwszRpId: *const u16,
        pClientData: *const WEBAUTHN_CLIENT_DATA,
        pOptions: *const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_V1,
        ppAssertion: *mut *mut WEBAUTHN_ASSERTION_V1,
    ) -> i32;

    pub fn WebAuthNFreeAssertion(pAssertion: *mut WEBAUTHN_ASSERTION_V1);

    /// Статическая строка с именем ошибки WebAuthn (`NotAllowedError` и т.п.).
    pub fn WebAuthNGetErrorName(hr: i32) -> *const u16;
}
