// FIDO2 / WebAuthn native Windows integration.
// Использует системную библиотеку `webauthn.dll` (Windows 10 1903+ / Windows 11).
//
// AUDIT: все FFI-структуры точно соответствуют определениям из Windows SDK
// webauthn.h (10.0.26100.0). Любые изменения должны сверяться с заголовком.

use crate::error::{Result, VaultError};

pub struct Fido2Registration {
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    /// AAGUID аутентификатора (16 байт), извлечённый из authenticatorData.
    /// Позволяет определить модель ключа (Рутокен MFA, YubiKey 5 и т.д.).
    pub aaguid: [u8; 16],
}

/// Определить имя модели ключа по AAGUID.
/// Список пополняется по мере добавления поддержки новых ключей.
pub fn aaguid_model_name(aaguid: &[u8; 16]) -> &'static str {
    let hex = hex::encode(aaguid);
    match hex.as_str() {
        // --- Рутокен ---
        "3e22415d7fdf4ea48a0c dd60c4249b9" => "Рутокен MFA",
        // Собранные AAGUID Рутокен MFA (могут отличаться по ревизиям):
        "3e22415d7fdf4ea48a0cdd60c4249b9d" => "Рутокен MFA",
        // --- YubiKey 5 Series ---
        "cb69481e8ff7403993ec0a2729a154a8" => "YubiKey 5 NFC",
        "ee882879721c491397753dfcce97072a" => "YubiKey 5 Nano",
        "2fc0579f811347eab116bb5a8db9202a" => "YubiKey 5 NFC FIPS",
        "73bb0cd4e50249b89c6fb59445bf720b" => "YubiKey 5 FIPS Series",
        "c5ef55ffad9a4b9fb580adebafe026d0" => "YubiKey 5Ci FIPS",
        "85203421489f4a05b8be17fd9cac9fb6" => "YubiKey 5 Series (USB-C, Nano)",
        "d8522d9f575b486688a9ba99fa02f35b" => "YubiKey Bio",
        "f8a011f38c0a4d15800617111f9edc7d" => "Security Key by Yubico",
        "b92c3f9ac0144056887f140a2501163b" => "Security Key NFC by Yubico",
        "0bb43545fd2c418587dda368d2cd015f" => "Security Key NFC by Yubico (USB-A)",
        _ => "FIDO2 Security Key",
    }
}

#[cfg(target_os = "windows")]
pub fn is_fido2_supported() -> bool {
    unsafe {
        let version = win_webauthn::WebAuthNGetApiVersionNumber();
        version >= 1
    }
}

#[cfg(not(target_os = "windows"))]
pub fn is_fido2_supported() -> bool {
    false
}

/// Зарегистрировать FIDO2-ключ через Windows Security диалог.
///
/// `require_pin`:
///   - `true`  → ПИН + Touch (resident key, UserVerification = REQUIRED)
///   - `false` → Touch-only (non-resident key, UserVerification = DISCOURAGED)
#[cfg(target_os = "windows")]
pub fn register_fido2_key_prompt(key_name: &str, require_pin: bool) -> Result<Fido2Registration> {
    use std::ptr;
    use win_webauthn::*;

    if !is_fido2_supported() {
        return Err(VaultError::BadInput("FIDO2/WebAuthn API недоступен в данной версии ОС".into()));
    }

    unsafe {
        let rp_id: Vec<u16> = "vaultisor.app\0".encode_utf16().collect();
        let rp_name: Vec<u16> = "Vaultisor\0".encode_utf16().collect();
        let rp_info = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: rp_id.as_ptr(),
            pwszName: rp_name.as_ptr(),
            pwszIcon: ptr::null(),
        };

        let user_uuid = uuid::Uuid::new_v4();
        let user_id_bytes = user_uuid.as_bytes();
        let user_name_str = format!("{key_name}\0");
        let user_display_str = format!("Vaultisor — {key_name}\0");

        let user_name: Vec<u16> = user_name_str.encode_utf16().collect();
        let user_display: Vec<u16> = user_display_str.encode_utf16().collect();
        let user_info = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: user_id_bytes.len() as u32,
            pbId: user_id_bytes.as_ptr(),
            pwszName: user_name.as_ptr(),
            pwszIcon: ptr::null(),
            pwszDisplayName: user_display.as_ptr(),
        };

        let cred_type: Vec<u16> = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY.encode_utf16().chain(std::iter::once(0)).collect();
        let cose_param = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: 1,
            pwszCredentialType: cred_type.as_ptr(),
            lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
        };
        let param_list = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_LIST {
            cCredentialParameters: 1,
            pCredentialParameters: &cose_param,
        };

        // Random 32-byte challenge
        let mut challenge = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut challenge);
        let challenge_b64 = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &challenge);
        let client_json = format!(
            r#"{{"type":"webauthn.create","challenge":"{}","origin":"https://vaultisor.app"}}"#,
            challenge_b64
        );
        let client_json_bytes = client_json.as_bytes();

        let hash_alg: Vec<u16> = "SHA-256\0".encode_utf16().collect();
        let client_data = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: client_json_bytes.len() as u32,
            pbClientDataJSON: client_json_bytes.as_ptr(),
            pwszHashAlgId: hash_alg.as_ptr(),
        };

        // AUDIT: поля точно соответствуют webauthn.h Version 1 layout.
        // bRequireResidentKey: TRUE для passwordless (ПИН+Touch), FALSE для 2FA (Touch-only)
        // dwUserVerificationRequirement: REQUIRED(1) для ПИН, DISCOURAGED(3) для без ПИН
        let options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
            dwVersion: 1,
            dwTimeoutMilliseconds: 60_000,
            CredentialList: WEBAUTHN_CREDENTIALS { cCredentials: 0, pCredentials: ptr::null() },
            Extensions: WEBAUTHN_EXTENSIONS { cExtensions: 0, pExtensions: ptr::null() },
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            bRequireResidentKey: if require_pin { 1 } else { 0 },
            dwUserVerificationRequirement: if require_pin {
                WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
            } else {
                WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
            },
            dwAttestationConveyancePreference: 0, // NONE
            dwFlags: 0,
        };

        let hwnd = GetForegroundWindow();
        let mut p_attestation: *mut WEBAUTHN_CREDENTIAL_ATTESTATION = ptr::null_mut();
        let hr = WebAuthNAuthenticatorMakeCredential(
            hwnd,
            &rp_info,
            &user_info,
            &param_list,
            &client_data,
            &options,
            &mut p_attestation,
        );

        if hr != 0 || p_attestation.is_null() {
            let hr_u = hr as u32;
            let err_msg = match hr_u {
                0x800704C7 | 0x80090030 => "Привязка FIDO2-ключа отменена пользователем".to_string(),
                0x800705B4 => "Превышено время ожидания подсоединения/касания FIDO2-ключа".to_string(),
                _ => format!("Ошибка FIDO2 (код {hr:#X})"),
            };
            return Err(VaultError::BadInput(err_msg));
        }

        let mut credential_id = Vec::new();
        let mut public_key = Vec::new();
        let mut aaguid = [0u8; 16];

        if !p_attestation.is_null() {
            let att = &*p_attestation;

            // 1. Извлекаем Credential ID прямо из поля структуры Windows API
            if att.cbCredentialId > 0 && !att.pbCredentialId.is_null() {
                credential_id = std::slice::from_raw_parts(att.pbCredentialId, att.cbCredentialId as usize).to_vec();
            }

            // 2. Из authenticatorData извлекаем AAGUID (байты 37-52) и
            //    резервный Credential ID (если прямое поле пустое)
            if att.cbAuthenticatorData >= 55 && !att.pbAuthenticatorData.is_null() {
                let auth_data = std::slice::from_raw_parts(att.pbAuthenticatorData, att.cbAuthenticatorData as usize);

                // AAGUID: 16 байт начиная с offset 37
                if auth_data.len() >= 53 {
                    aaguid.copy_from_slice(&auth_data[37..53]);
                }

                // Резервный парсинг Credential ID из authData по спецификации CTAP2
                if credential_id.is_empty() {
                    let flags = auth_data[32];
                    if (flags & 0x40) != 0 && auth_data.len() >= 55 {
                        let cred_id_len = ((auth_data[53] as usize) << 8) | (auth_data[54] as usize);
                        if auth_data.len() >= 55 + cred_id_len {
                            credential_id = auth_data[55..55 + cred_id_len].to_vec();
                        }
                    }
                }
            }

            if att.cbAuthenticatorData > 0 && !att.pbAuthenticatorData.is_null() {
                public_key = std::slice::from_raw_parts(att.pbAuthenticatorData, att.cbAuthenticatorData as usize).to_vec();
            }

            WebAuthNFreeCredentialAttestation(p_attestation);
        }

        if credential_id.is_empty() {
            return Err(VaultError::BadInput("Не удалось получить Credential ID от FIDO2-ключа".into()));
        }

        let model = aaguid_model_name(&aaguid);
        log::info!("register_fido2_key_prompt: credential_id len={}, aaguid={}, model={}, require_pin={}",
            credential_id.len(), hex::encode(&aaguid), model, require_pin);

        Ok(Fido2Registration {
            credential_id,
            public_key,
            aaguid,
        })
    }
}

/// Аутентификация через FIDO2-ключ (assertion).
///
/// `require_pin`:
///   - `true`  → UserVerification = REQUIRED (ПИН + Touch)
///   - `false` → UserVerification = DISCOURAGED (Touch-only)
///
/// `registered_credentials` — список credential_id всех привязанных ключей.
/// Для non-resident ключей (touch-only) передаётся в allowCredentials.
/// Для resident ключей (ПИН+Touch) список может быть пустым.
pub fn assert_fido2_key_prompt(registered_credentials: &[Vec<u8>], require_pin: bool) -> Result<Vec<u8>> {
    use std::ptr;
    use win_webauthn::*;

    if !is_fido2_supported() {
        return Err(VaultError::BadInput("FIDO2/WebAuthn API недоступен в данной версии ОС".into()));
    }

    unsafe {
        let rp_id: Vec<u16> = "vaultisor.app\0".encode_utf16().collect();

        // Random 32-byte challenge
        let mut challenge = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut challenge);
        let challenge_b64 = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &challenge);
        let client_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://vaultisor.app"}}"#,
            challenge_b64
        );
        let client_json_bytes = client_json.as_bytes();

        let hash_alg: Vec<u16> = "SHA-256\0".encode_utf16().collect();
        let client_data = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: client_json_bytes.len() as u32,
            pbClientDataJSON: client_json_bytes.as_ptr(),
            pwszHashAlgId: hash_alg.as_ptr(),
        };

        // Для non-resident ключей: передаём allowCredentials (Version 1 CredentialList)
        let cred_type_str: Vec<u16> = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let allow_creds: Vec<WEBAUTHN_CREDENTIAL> = registered_credentials
            .iter()
            .map(|cid| WEBAUTHN_CREDENTIAL {
                dwVersion: 1,
                cbId: cid.len() as u32,
                pbId: cid.as_ptr(),
                pwszCredentialType: cred_type_str.as_ptr(),
            })
            .collect();

        let uv_requirement = if require_pin {
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
        } else {
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
        };

        // AUDIT: V1 struct layout точно совпадает с webauthn.h
        let options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
            dwVersion: 1,
            dwTimeoutMilliseconds: 60_000,
            CredentialList: if !require_pin && !allow_creds.is_empty() {
                // Для non-resident: передаём список cred_id через CredentialList
                WEBAUTHN_CREDENTIALS {
                    cCredentials: allow_creds.len() as u32,
                    pCredentials: allow_creds.as_ptr(),
                }
            } else {
                // Для resident ключей: пустой список, аутентификатор сам найдёт
                WEBAUTHN_CREDENTIALS {
                    cCredentials: 0,
                    pCredentials: ptr::null(),
                }
            },
            Extensions: WEBAUTHN_EXTENSIONS { cExtensions: 0, pExtensions: ptr::null() },
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            dwUserVerificationRequirement: uv_requirement,
            dwFlags: 0,
        };

        let hwnd = GetForegroundWindow();
        let mut p_assertion: *mut WEBAUTHN_ASSERTION = ptr::null_mut();
        let hr = WebAuthNAuthenticatorGetAssertion(
            hwnd,
            rp_id.as_ptr(),
            &client_data,
            &options,
            &mut p_assertion,
        );

        if hr != 0 || p_assertion.is_null() {
            let hr_u = hr as u32;
            let err_msg = match hr_u {
                0x800704C7 | 0x80090030 => "Проверка FIDO2-ключа отменена пользователем".to_string(),
                0x800705B4 => "Превышено время ожидания подсоединения/касания FIDO2-ключа".to_string(),
                _ => format!("Ошибка FIDO2 (код {hr:#X})"),
            };
            return Err(VaultError::BadInput(err_msg));
        }

        let mut matched_cid = if !registered_credentials.is_empty() {
            registered_credentials[0].clone()
        } else {
            Vec::new()
        };

        if !p_assertion.is_null() {
            let ass = &*p_assertion;
            if ass.Credential.cbId > 0 && !ass.Credential.pbId.is_null() {
                let cid = std::slice::from_raw_parts(ass.Credential.pbId, ass.Credential.cbId as usize).to_vec();
                log::info!("assert_fido2_key_prompt: assertion returned credential_id len={}", cid.len());
                if registered_credentials.contains(&cid) {
                    matched_cid = cid;
                } else if registered_credentials.is_empty() {
                    // Для resident key: assertion возвращает cred_id напрямую
                    matched_cid = cid;
                }
            }
            WebAuthNFreeAssertion(p_assertion);
        }

        if matched_cid.is_empty() {
            return Err(VaultError::BadInput("FIDO2-ключ не вернул Credential ID".into()));
        }

        Ok(matched_cid)
    }
}

#[cfg(not(target_os = "windows"))]
pub fn register_fido2_key_prompt(_key_name: &str, _require_pin: bool) -> Result<Fido2Registration> {
    Err(VaultError::BadInput("FIDO2 поддерживается только на Windows 10/11".into()))
}

#[cfg(not(target_os = "windows"))]
pub fn assert_fido2_key_prompt(_registered_credentials: &[Vec<u8>], _require_pin: bool) -> Result<Vec<u8>> {
    Err(VaultError::BadInput("FIDO2 поддерживается только на Windows 10/11".into()))
}

// ============================================================================
// FFI-биндинги Windows WebAuthn API (`webauthn.dll`)
//
// AUDIT: все структуры соответствуют определениям из Windows SDK webauthn.h
// версии 10.0.26100.0. Версии struct (dwVersion) используются V1 если не
// указано иное.
// ============================================================================
#[cfg(target_os = "windows")]
#[allow(non_snake_case, non_upper_case_globals)]
mod win_webauthn {
    use std::ffi::c_void;

    pub const WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION: u32 = 1;
    pub const WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION: u32 = 1;
    pub const WEBAUTHN_CLIENT_DATA_CURRENT_VERSION: u32 = 1;

    pub const WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256: i32 = -7;
    pub const WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY: &str = "public-key";

    pub const WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM: u32 = 2;

    // webauthn.h:
    // #define WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY          0
    // #define WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED      1
    // #define WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED     2
    // #define WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED   3
    pub const WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED: u32 = 1;
    #[allow(dead_code)]
    pub const WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED: u32 = 2;
    pub const WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED: u32 = 3;

    // --- RP Entity Information ---
    #[repr(C)]
    pub struct WEBAUTHN_RP_ENTITY_INFORMATION {
        pub dwVersion: u32,
        pub pwszId: *const u16,
        pub pwszName: *const u16,
        pub pwszIcon: *const u16,
    }

    // --- User Entity Information ---
    #[repr(C)]
    pub struct WEBAUTHN_USER_ENTITY_INFORMATION {
        pub dwVersion: u32,
        pub cbId: u32,
        pub pbId: *const u8,
        pub pwszName: *const u16,
        pub pwszIcon: *const u16,
        pub pwszDisplayName: *const u16,
    }

    // --- COSE Credential Parameter ---
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

    // --- Client Data ---
    #[repr(C)]
    pub struct WEBAUTHN_CLIENT_DATA {
        pub dwVersion: u32,
        pub cbClientDataJSON: u32,
        pub pbClientDataJSON: *const u8,
        pub pwszHashAlgId: *const u16,
    }

    // --- Credential (used in allowCredentials and assertion response) ---
    // webauthn.h: _WEBAUTHN_CREDENTIAL (line 302)
    #[repr(C)]
    pub struct WEBAUTHN_CREDENTIAL {
        pub dwVersion: u32,
        pub cbId: u32,
        pub pbId: *const u8,
        pub pwszCredentialType: *const u16,
    }

    // --- Credentials List ---
    // webauthn.h: _WEBAUTHN_CREDENTIALS (line 317)
    #[repr(C)]
    pub struct WEBAUTHN_CREDENTIALS {
        pub cCredentials: u32,
        pub pCredentials: *const WEBAUTHN_CREDENTIAL,
    }

    // --- Extensions ---
    #[repr(C)]
    pub struct WEBAUTHN_EXTENSIONS {
        pub cExtensions: u32,
        pub pExtensions: *const c_void,
    }

    // --- MakeCredential Options (Version 1) ---
    // AUDIT: exact match to webauthn.h _WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS
    // Version 1 fields ONLY (lines 745-772).
    //
    // Layout (V1):
    //   dwVersion                           u32
    //   dwTimeoutMilliseconds               u32
    //   CredentialList                       WEBAUTHN_CREDENTIALS (8+8=16 на x64)
    //   Extensions                          WEBAUTHN_EXTENSIONS  (8+8=16 на x64)
    //   dwAuthenticatorAttachment           u32
    //   bRequireResidentKey                 BOOL (i32)  ← НЕ bRequireUserVerification!
    //   dwUserVerificationRequirement       u32
    //   dwAttestationConveyancePreference   u32
    //   dwFlags                             u32
    #[repr(C)]
    pub struct WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
        pub dwVersion: u32,
        pub dwTimeoutMilliseconds: u32,
        pub CredentialList: WEBAUTHN_CREDENTIALS,
        pub Extensions: WEBAUTHN_EXTENSIONS,
        pub dwAuthenticatorAttachment: u32,
        pub bRequireResidentKey: i32,               // BOOL: 1=resident key required
        pub dwUserVerificationRequirement: u32,     // 1=REQUIRED, 2=PREFERRED, 3=DISCOURAGED
        pub dwAttestationConveyancePreference: u32, // 0=NONE
        pub dwFlags: u32,                           // Reserved, 0
    }

    // --- GetAssertion Options (Version 1) ---
    // AUDIT: exact match to webauthn.h _WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
    // Version 1 fields ONLY (lines 892-913).
    //
    // Layout (V1):
    //   dwVersion                       u32
    //   dwTimeoutMilliseconds           u32
    //   CredentialList                   WEBAUTHN_CREDENTIALS (16 на x64)
    //   Extensions                      WEBAUTHN_EXTENSIONS  (16 на x64)
    //   dwAuthenticatorAttachment       u32
    //   dwUserVerificationRequirement   u32
    //   dwFlags                         u32
    #[repr(C)]
    pub struct WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
        pub dwVersion: u32,
        pub dwTimeoutMilliseconds: u32,
        pub CredentialList: WEBAUTHN_CREDENTIALS,
        pub Extensions: WEBAUTHN_EXTENSIONS,
        pub dwAuthenticatorAttachment: u32,
        pub dwUserVerificationRequirement: u32,
        pub dwFlags: u32,
    }

    // --- Credential Attestation (returned by MakeCredential) ---
    // AUDIT: exact match to webauthn.h _WEBAUTHN_CREDENTIAL_ATTESTATION (line 1140)
    #[repr(C)]
    pub struct WEBAUTHN_CREDENTIAL_ATTESTATION {
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

    // --- Assertion (returned by GetAssertion) ---
    // AUDIT: exact match to webauthn.h _WEBAUTHN_ASSERTION Version 1 (line 1214)
    #[repr(C)]
    pub struct WEBAUTHN_ASSERTION {
        pub dwVersion: u32,
        pub cbAuthenticatorData: u32,
        pub pbAuthenticatorData: *const u8,
        pub cbSignature: u32,
        pub pbSignature: *const u8,
        pub Credential: WEBAUTHN_CREDENTIAL,
        pub cbUserId: u32,
        pub pbUserId: *const u8,
    }

    // --- Win32 / WebAuthn API functions ---

    #[link(name = "user32")]
    extern "system" {
        pub fn GetForegroundWindow() -> *const c_void;
    }

    #[link(name = "webauthn")]
    extern "system" {
        pub fn WebAuthNGetApiVersionNumber() -> u32;

        pub fn WebAuthNAuthenticatorMakeCredential(
            hWnd: *const c_void,
            pRpInformation: *const WEBAUTHN_RP_ENTITY_INFORMATION,
            pUserInformation: *const WEBAUTHN_USER_ENTITY_INFORMATION,
            pPubKeyCredParams: *const WEBAUTHN_COSE_CREDENTIAL_PARAMETER_LIST,
            pClientData: *const WEBAUTHN_CLIENT_DATA,
            pOptions: *const WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
            ppCredentialAttestation: *mut *mut WEBAUTHN_CREDENTIAL_ATTESTATION,
        ) -> i32;

        pub fn WebAuthNFreeCredentialAttestation(
            pCredentialAttestation: *mut WEBAUTHN_CREDENTIAL_ATTESTATION,
        );

        // AUDIT: typed pointers instead of *const c_void
        pub fn WebAuthNAuthenticatorGetAssertion(
            hWnd: *const c_void,
            pwszRpId: *const u16,
            pClientData: *const WEBAUTHN_CLIENT_DATA,
            pOptions: *const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
            ppAssertion: *mut *mut WEBAUTHN_ASSERTION,
        ) -> i32;

        pub fn WebAuthNFreeAssertion(
            pAssertion: *mut WEBAUTHN_ASSERTION,
        );
    }
}
