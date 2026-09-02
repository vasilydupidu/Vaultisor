// FIDO2 / WebAuthn native Windows integration.
// Использует системную библиотеку `webauthn.dll` (Windows 10 1903+ / Windows 11).
//
// AUDIT VULN-01 FIX: KEK теперь выводится из PRF-output (hmac-secret) — аппаратно-
// привязанного секрета аутентификатора, а НЕ из публичного credential_id.
// Для работы PRF требуется API v6+ (Windows 11 21H2+) и поддержка hmac-secret
// в аутентификаторе (Рутокен MFA, YubiKey 5 — поддерживают).
//
// AUDIT: все FFI-структуры точно соответствуют определениям из Windows SDK
// webauthn.h (10.0.26100.0). Любые изменения должны сверяться с заголовком.

use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

pub struct Fido2Registration {
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    /// AAGUID аутентификатора (16 байт), извлечённый из authenticatorData.
    pub aaguid: [u8; 16],
    /// VULN-01 FIX: поддерживает ли аутентификатор PRF (hmac-secret).
    pub prf_supported: bool,
}

/// Результат FIDO2-assertion с PRF-output (VULN-01 FIX).
pub struct Fido2AssertionResult {
    pub credential_id: Vec<u8>,
    /// PRF-output (32 байта) — аппаратно-привязанный секрет.
    /// None если аутентификатор не поддерживает hmac-secret или API < v6.
    pub prf_output: Option<Zeroizing<Vec<u8>>>,
}

/// Определить имя модели ключа по AAGUID.
pub fn aaguid_model_name(aaguid: &[u8; 16]) -> &'static str {
    let hex = hex::encode(aaguid);
    match hex.as_str() {
        // --- Рутокен ---
        "3e22415d7fdf4ea48a0c dd60c4249b9" => "Рутокен MFA",
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

/// Стабильная 32-байтная соль для PRF/hmac-secret запросов.
/// Используется как CTAP2 hmac-secret salt (raw режим, флаг HMAC_SECRET_VALUES_FLAG).
/// Одинаковая соль при каждом assertion → детерминированный PRF-output → KEK.
const PRF_SALT: &[u8; 32] = b"vaultisor:fido2-prf-salt:v1\x00\x00\x00\x00\x00";

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
///   - `true`  → ПИН + Touch (resident key, CTAP2, UserVerification = REQUIRED)
///   - `false` → Touch-only (non-resident, U2F/CTAP1, никогда не спрашивает ПИН)
///
/// VULN-01 FIX: если API >= 6, устанавливает bEnablePrf = TRUE для hmac-secret.
#[cfg(target_os = "windows")]
pub fn register_fido2_key_prompt(key_name: &str, require_pin: bool) -> Result<Fido2Registration> {
    use std::ptr;
    use win_webauthn::*;

    if !is_fido2_supported() {
        return Err(VaultError::BadInput("FIDO2/WebAuthn API недоступен в данной версии ОС".into()));
    }

    unsafe {
        let api_version = WebAuthNGetApiVersionNumber();

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

        let cred_type: Vec<u16> = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY
            .encode_utf16().chain(std::iter::once(0)).collect();
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
        let challenge_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD, &challenge);
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

        let attachment = if require_pin {
            WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM
        } else {
            WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM_U2F_V2
        };

        let hwnd = GetForegroundWindow();
        let mut p_attestation: *mut WEBAUTHN_CREDENTIAL_ATTESTATION_V5 = ptr::null_mut();

        let hr;

        // VULN-01 FIX: V6 options с bEnablePrf = TRUE
        if api_version >= 6 {
            let options_v6 = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_V6 {
                dwVersion: 6,
                dwTimeoutMilliseconds: 60_000,
                CredentialList: WEBAUTHN_CREDENTIALS { cCredentials: 0, pCredentials: ptr::null() },
                Extensions: WEBAUTHN_EXTENSIONS { cExtensions: 0, pExtensions: ptr::null() },
                dwAuthenticatorAttachment: attachment,
                bRequireResidentKey: if require_pin { 1 } else { 0 },
                dwUserVerificationRequirement: if require_pin {
                    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
                } else {
                    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
                },
                dwAttestationConveyancePreference: 0,
                dwFlags: 0,
                pCancellationId: ptr::null(),
                pExcludeCredentialList: ptr::null(),
                dwEnterpriseAttestation: 0,
                dwLargeBlobSupport: 0,
                bPreferResidentKey: if require_pin { 1 } else { 0 },
                bBrowserInPrivateMode: 0,
                bEnablePrf: 1, // VULN-01 FIX
            };

            hr = WebAuthNAuthenticatorMakeCredential(
                hwnd, &rp_info, &user_info, &param_list, &client_data,
                &options_v6 as *const _ as *const WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_V1,
                &mut p_attestation as *mut *mut _ as *mut *mut WEBAUTHN_CREDENTIAL_ATTESTATION_V1,
            );
        } else {
            let options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_V1 {
                dwVersion: 1,
                dwTimeoutMilliseconds: 60_000,
                CredentialList: WEBAUTHN_CREDENTIALS { cCredentials: 0, pCredentials: ptr::null() },
                Extensions: WEBAUTHN_EXTENSIONS { cExtensions: 0, pExtensions: ptr::null() },
                dwAuthenticatorAttachment: attachment,
                bRequireResidentKey: if require_pin { 1 } else { 0 },
                dwUserVerificationRequirement: if require_pin {
                    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
                } else {
                    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
                },
                dwAttestationConveyancePreference: 0,
                dwFlags: 0,
            };

            hr = WebAuthNAuthenticatorMakeCredential(
                hwnd, &rp_info, &user_info, &param_list, &client_data,
                &options,
                &mut p_attestation as *mut *mut _ as *mut *mut WEBAUTHN_CREDENTIAL_ATTESTATION_V1,
            );
        }

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
        let mut prf_supported = false;

        if !p_attestation.is_null() {
            let att = &*p_attestation;

            if att.cbCredentialId > 0 && !att.pbCredentialId.is_null() {
                credential_id = std::slice::from_raw_parts(
                    att.pbCredentialId, att.cbCredentialId as usize).to_vec();
            }

            if att.cbAuthenticatorData >= 55 && !att.pbAuthenticatorData.is_null() {
                let auth_data = std::slice::from_raw_parts(
                    att.pbAuthenticatorData, att.cbAuthenticatorData as usize);
                if auth_data.len() >= 53 {
                    aaguid.copy_from_slice(&auth_data[37..53]);
                }
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
                public_key = std::slice::from_raw_parts(
                    att.pbAuthenticatorData, att.cbAuthenticatorData as usize).to_vec();
            }

            // VULN-01 FIX: bPrfEnabled из V5 ответа
            if att.dwVersion >= 5 {
                prf_supported = att.bPrfEnabled != 0;
                log::info!("register: bPrfEnabled={} (dwVersion={})", att.bPrfEnabled, att.dwVersion);
            }

            WebAuthNFreeCredentialAttestation(
                p_attestation as *mut WEBAUTHN_CREDENTIAL_ATTESTATION_V1);
        }

        if credential_id.is_empty() {
            return Err(VaultError::BadInput(
                "Не удалось получить Credential ID от FIDO2-ключа".into()));
        }

        let model = aaguid_model_name(&aaguid);
        log::info!("register_fido2_key_prompt: cred_id len={}, aaguid={}, model={}, \
            require_pin={}, prf_supported={}, attachment={}",
            credential_id.len(), hex::encode(&aaguid), model,
            require_pin, prf_supported, attachment);

        Ok(Fido2Registration { credential_id, public_key, aaguid, prf_supported })
    }
}

/// Аутентификация через FIDO2-ключ (assertion) с PRF-output.
///
/// VULN-01 FIX: при API >= 6 запрашивает hmac-secret с фиксированной солью.
/// Аутентификатор возвращает 32-байтный аппаратно-привязанный секрет.
pub fn assert_fido2_key_prompt(
    registered_credentials: &[Vec<u8>],
    require_pin: bool,
) -> Result<Fido2AssertionResult> {
    use std::ptr;
    use win_webauthn::*;

    if !is_fido2_supported() {
        return Err(VaultError::BadInput("FIDO2/WebAuthn API недоступен в данной версии ОС".into()));
    }

    unsafe {
        let api_version = WebAuthNGetApiVersionNumber();
        log::info!("assert_fido2_key_prompt: api_version={}, require_pin={}, cred_count={}",
            api_version, require_pin, registered_credentials.len());

        let rp_id: Vec<u16> = "vaultisor.app\0".encode_utf16().collect();

        let mut challenge = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut challenge);
        let challenge_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD, &challenge);
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

        let cred_type_str: Vec<u16> = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY
            .encode_utf16().chain(std::iter::once(0)).collect();

        let uv_requirement = if require_pin {
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
        } else {
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
        };

        let hwnd = GetForegroundWindow();
        let mut p_assertion: *mut WEBAUTHN_ASSERTION_V3 = ptr::null_mut();

        let hr;

        // VULN-01 FIX: V6 options с PRF salt
        if api_version >= 6 && !registered_credentials.is_empty() {
            let mut prf_salt_buf = *PRF_SALT;
            let mut hmac_salt = WEBAUTHN_HMAC_SECRET_SALT {
                cbFirst: 32,
                pbFirst: prf_salt_buf.as_mut_ptr(),
                cbSecond: 0,
                pbSecond: ptr::null_mut(),
            };

            let mut hmac_salt_values = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
                pGlobalHmacSalt: &mut hmac_salt,
                cCredWithHmacSecretSaltList: 0,
                pCredWithHmacSecretSaltList: ptr::null_mut(),
            };

            let allow_creds_ex: Vec<WEBAUTHN_CREDENTIAL_EX> = registered_credentials
                .iter()
                .map(|cid| WEBAUTHN_CREDENTIAL_EX {
                    dwVersion: 1,
                    cbId: cid.len() as u32,
                    pbId: cid.as_ptr(),
                    pwszCredentialType: cred_type_str.as_ptr(),
                    dwTransports: WEBAUTHN_CTAP_TRANSPORT_USB | WEBAUTHN_CTAP_TRANSPORT_NFC,
                })
                .collect();

            let allow_ptrs: Vec<*const WEBAUTHN_CREDENTIAL_EX> = allow_creds_ex
                .iter().map(|c| c as *const _).collect();

            let allow_list = WEBAUTHN_CREDENTIAL_LIST {
                cCredentials: allow_ptrs.len() as u32,
                ppCredentials: allow_ptrs.as_ptr(),
            };

            let options_v6 = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_V6 {
                dwVersion: 6,
                dwTimeoutMilliseconds: 60_000,
                CredentialList: WEBAUTHN_CREDENTIALS { cCredentials: 0, pCredentials: ptr::null() },
                Extensions: WEBAUTHN_EXTENSIONS { cExtensions: 0, pExtensions: ptr::null() },
                dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
                dwUserVerificationRequirement: uv_requirement,
                dwFlags: WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG,
                pwszU2fAppId: ptr::null(),
                pbU2fAppId: ptr::null_mut(),
                pCancellationId: ptr::null(),
                pAllowCredentialList: &allow_list,
                dwCredLargeBlobOperation: 0,
                cbCredLargeBlob: 0,
                pbCredLargeBlob: ptr::null_mut(),
                pHmacSecretSaltValues: &mut hmac_salt_values,
                bBrowserInPrivateMode: 0,
            };

            log::info!("assert: V6 options with PRF salt, {} credentials", allow_creds_ex.len());

            hr = WebAuthNAuthenticatorGetAssertion(
                hwnd, rp_id.as_ptr(), &client_data,
                &options_v6 as *const _ as *const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_V1,
                &mut p_assertion as *mut *mut _ as *mut *mut WEBAUTHN_ASSERTION_V1,
            );
        } else if api_version >= 4 && !registered_credentials.is_empty() {
            // V4 fallback (без PRF, с transport restriction)
            let allow_creds_ex: Vec<WEBAUTHN_CREDENTIAL_EX> = registered_credentials
                .iter()
                .map(|cid| WEBAUTHN_CREDENTIAL_EX {
                    dwVersion: 1,
                    cbId: cid.len() as u32,
                    pbId: cid.as_ptr(),
                    pwszCredentialType: cred_type_str.as_ptr(),
                    dwTransports: WEBAUTHN_CTAP_TRANSPORT_USB | WEBAUTHN_CTAP_TRANSPORT_NFC,
                })
                .collect();
            let allow_ptrs: Vec<*const WEBAUTHN_CREDENTIAL_EX> = allow_creds_ex
                .iter().map(|c| c as *const _).collect();
            let allow_list = WEBAUTHN_CREDENTIAL_LIST {
                cCredentials: allow_ptrs.len() as u32,
                ppCredentials: allow_ptrs.as_ptr(),
            };

            let options_v4 = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_V4 {
                dwVersion: 4,
                dwTimeoutMilliseconds: 60_000,
                CredentialList: WEBAUTHN_CREDENTIALS { cCredentials: 0, pCredentials: ptr::null() },
                Extensions: WEBAUTHN_EXTENSIONS { cExtensions: 0, pExtensions: ptr::null() },
                dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
                dwUserVerificationRequirement: uv_requirement,
                dwFlags: 0,
                pwszU2fAppId: ptr::null(),
                pbU2fAppId: ptr::null_mut(),
                pCancellationId: ptr::null(),
                pAllowCredentialList: &allow_list,
            };

            hr = WebAuthNAuthenticatorGetAssertion(
                hwnd, rp_id.as_ptr(), &client_data,
                &options_v4 as *const _ as *const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_V1,
                &mut p_assertion as *mut *mut _ as *mut *mut WEBAUTHN_ASSERTION_V1,
            );
        } else {
            // V1 fallback
            let allow_creds: Vec<WEBAUTHN_CREDENTIAL> = registered_credentials
                .iter()
                .map(|cid| WEBAUTHN_CREDENTIAL {
                    dwVersion: 1,
                    cbId: cid.len() as u32,
                    pbId: cid.as_ptr(),
                    pwszCredentialType: cred_type_str.as_ptr(),
                })
                .collect();

            let options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_V1 {
                dwVersion: 1,
                dwTimeoutMilliseconds: 60_000,
                CredentialList: if !allow_creds.is_empty() {
                    WEBAUTHN_CREDENTIALS {
                        cCredentials: allow_creds.len() as u32,
                        pCredentials: allow_creds.as_ptr(),
                    }
                } else {
                    WEBAUTHN_CREDENTIALS { cCredentials: 0, pCredentials: ptr::null() }
                },
                Extensions: WEBAUTHN_EXTENSIONS { cExtensions: 0, pExtensions: ptr::null() },
                dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
                dwUserVerificationRequirement: uv_requirement,
                dwFlags: 0,
            };

            hr = WebAuthNAuthenticatorGetAssertion(
                hwnd, rp_id.as_ptr(), &client_data,
                &options,
                &mut p_assertion as *mut *mut _ as *mut *mut WEBAUTHN_ASSERTION_V1,
            );
        }

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
        let mut prf_output: Option<Zeroizing<Vec<u8>>> = None;

        if !p_assertion.is_null() {
            let ass = &*p_assertion;
            if ass.Credential.cbId > 0 && !ass.Credential.pbId.is_null() {
                let cid = std::slice::from_raw_parts(
                    ass.Credential.pbId, ass.Credential.cbId as usize).to_vec();
                log::info!("assert: credential_id len={}", cid.len());
                if registered_credentials.contains(&cid) {
                    matched_cid = cid;
                } else if registered_credentials.is_empty() {
                    matched_cid = cid;
                }
            }

            // VULN-01 FIX: PRF-output из V3+ assertion
            if ass.dwVersion >= 3 && !ass.pHmacSecret.is_null() {
                let hmac_secret = &*ass.pHmacSecret;
                if hmac_secret.cbFirst >= 32 && !hmac_secret.pbFirst.is_null() {
                    let prf_bytes = std::slice::from_raw_parts(
                        hmac_secret.pbFirst, hmac_secret.cbFirst as usize);
                    let mut secret = vec![0u8; 32];
                    secret.copy_from_slice(&prf_bytes[..32]);
                    log::info!("assert: PRF output received ({} bytes)", hmac_secret.cbFirst);
                    prf_output = Some(Zeroizing::new(secret));
                } else {
                    log::warn!("assert: pHmacSecret present but cbFirst={}", hmac_secret.cbFirst);
                }
            } else {
                log::info!("assert: no PRF output (dwVersion={})", ass.dwVersion);
            }

            WebAuthNFreeAssertion(p_assertion as *mut WEBAUTHN_ASSERTION_V1);
        }

        if matched_cid.is_empty() {
            return Err(VaultError::BadInput("FIDO2-ключ не вернул Credential ID".into()));
        }

        Ok(Fido2AssertionResult { credential_id: matched_cid, prf_output })
    }
}

#[cfg(not(target_os = "windows"))]
pub fn register_fido2_key_prompt(_key_name: &str, _require_pin: bool) -> Result<Fido2Registration> {
    Err(VaultError::BadInput("FIDO2 поддерживается только на Windows 10/11".into()))
}

#[cfg(not(target_os = "windows"))]
pub fn assert_fido2_key_prompt(
    _registered_credentials: &[Vec<u8>],
    _require_pin: bool,
) -> Result<Fido2AssertionResult> {
    Err(VaultError::BadInput("FIDO2 поддерживается только на Windows 10/11".into()))
}

// ============================================================================
// FFI-биндинги Windows WebAuthn API (`webauthn.dll`)
//
// VULN-01 FIX: добавлены V5/V6 версии структур для PRF/hmac-secret.
// ============================================================================
#[cfg(target_os = "windows")]
#[allow(non_snake_case, non_upper_case_globals, dead_code)]
mod win_webauthn {
    use std::ffi::c_void;

    pub const WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION: u32 = 1;
    pub const WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION: u32 = 1;
    pub const WEBAUTHN_CLIENT_DATA_CURRENT_VERSION: u32 = 1;

    pub const WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256: i32 = -7;
    pub const WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY: &str = "public-key";

    pub const WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM: u32 = 2;
    pub const WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM_U2F_V2: u32 = 3;

    pub const WEBAUTHN_CTAP_TRANSPORT_USB: u32 = 0x00000001;
    pub const WEBAUTHN_CTAP_TRANSPORT_NFC: u32 = 0x00000002;

    pub const WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED: u32 = 1;
    pub const WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED: u32 = 2;
    pub const WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED: u32 = 3;

    /// VULN-01 FIX: raw HMAC-Secret salt mode flag.
    pub const WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG: u32 = 0x00100000;

    // --- Core structures ---

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

    // --- VULN-01 FIX: PRF/HMAC-Secret structures (webauthn.h L562-593) ---

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

    // --- MakeCredential Options ---

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

    /// V6: adds bEnablePrf (VULN-01 FIX)
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

    // --- GetAssertion Options ---

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

    #[repr(C)]
    pub struct WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_V4 {
        pub dwVersion: u32,
        pub dwTimeoutMilliseconds: u32,
        pub CredentialList: WEBAUTHN_CREDENTIALS,
        pub Extensions: WEBAUTHN_EXTENSIONS,
        pub dwAuthenticatorAttachment: u32,
        pub dwUserVerificationRequirement: u32,
        pub dwFlags: u32,
        pub pwszU2fAppId: *const u16,
        pub pbU2fAppId: *mut i32,
        pub pCancellationId: *const [u8; 16],
        pub pAllowCredentialList: *const WEBAUTHN_CREDENTIAL_LIST,
    }

    /// V6: adds pHmacSecretSaltValues (VULN-01 FIX)
    #[repr(C)]
    pub struct WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_V6 {
        pub dwVersion: u32,
        pub dwTimeoutMilliseconds: u32,
        pub CredentialList: WEBAUTHN_CREDENTIALS,
        pub Extensions: WEBAUTHN_EXTENSIONS,
        pub dwAuthenticatorAttachment: u32,
        pub dwUserVerificationRequirement: u32,
        pub dwFlags: u32,
        pub pwszU2fAppId: *const u16,
        pub pbU2fAppId: *mut i32,
        pub pCancellationId: *const [u8; 16],
        pub pAllowCredentialList: *const WEBAUTHN_CREDENTIAL_LIST,
        // V5
        pub dwCredLargeBlobOperation: u32,
        pub cbCredLargeBlob: u32,
        pub pbCredLargeBlob: *mut u8,
        // V6
        pub pHmacSecretSaltValues: *mut WEBAUTHN_HMAC_SECRET_SALT_VALUES,
        pub bBrowserInPrivateMode: i32,
    }

    // --- Attestation Response ---

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

    /// V5: adds bPrfEnabled (VULN-01 FIX)
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

    // --- Assertion Response ---

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

    /// V3: adds pHmacSecret (VULN-01 FIX)
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

    // --- API functions ---

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
            pOptions: *const WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_V1,
            ppCredentialAttestation: *mut *mut WEBAUTHN_CREDENTIAL_ATTESTATION_V1,
        ) -> i32;

        pub fn WebAuthNFreeCredentialAttestation(
            pCredentialAttestation: *mut WEBAUTHN_CREDENTIAL_ATTESTATION_V1,
        );

        pub fn WebAuthNAuthenticatorGetAssertion(
            hWnd: *const c_void,
            pwszRpId: *const u16,
            pClientData: *const WEBAUTHN_CLIENT_DATA,
            pOptions: *const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_V1,
            ppAssertion: *mut *mut WEBAUTHN_ASSERTION_V1,
        ) -> i32;

        pub fn WebAuthNFreeAssertion(
            pAssertion: *mut WEBAUTHN_ASSERTION_V1,
        );
    }
}
