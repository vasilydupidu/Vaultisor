// FIDO2 / WebAuthn native Windows integration.
// Использует системную библиотеку `webauthn.dll` (Windows 10 1903+ / Windows 11).
//
// KEK теперь выводится из PRF-output (hmac-secret) — аппаратно-
// привязанного секрета аутентификатора, а НЕ из публичного credential_id.
// Для работы PRF требуется API v6+ (Windows 11 21H2+) и поддержка hmac-secret
// в аутентификаторе (Рутокен MFA, YubiKey 5 — поддерживают).
//
// Все FFI-структуры точно соответствуют определениям из Windows SDK
// webauthn.h (10.0.26100.0). Любые изменения должны сверяться с заголовком.

use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

/// Сырой результат регистрации. Ничему из этого нельзя доверять до проверки
/// `auth::webauthn_rp::verify_registration`.
pub struct Fido2Registration {
    pub credential_id: Vec<u8>,
    /// authenticatorData с attested credential data (в нём COSE-ключ).
    pub authenticator_data: Vec<u8>,
    /// AAGUID аутентификатора (16 байт) — только для имени модели.
    pub aaguid: [u8; 16],
    /// Заявление Windows о поддержке PRF. Решает не оно, а настоящий assertion.
    pub prf_supported: bool,
}

/// Сырой результат assertion. PRF-выход используется только после проверки
/// подписи `auth::webauthn_rp::verify_assertion` сохранённым ключом.
pub struct Fido2AssertionResult {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    /// DER-подпись ES256 над authenticatorData ‖ SHA-256(clientDataJSON).
    pub signature: Vec<u8>,
    /// PRF-output (32 байта). None, если hmac-secret не вернулся.
    pub prf_output: Option<Zeroizing<Vec<u8>>>,
}

/// Модели, которых нет в FIDO MDS, но чей AAGUID снят с живого устройства.
///
/// Сюда попадает только то, что видно в логе привязки настоящего токена, —
/// никаких записей по памяти или из вторых рук: именно так прежняя таблица
/// подписала AAGUID Feitian iePass «Рутокен MFA». Сгенерированную таблицу
/// эти записи не трогают и при её пересборке не теряются.
const VERIFIED_OUTSIDE_MDS: &[(&str, &str)] = &[
    // Рутокен MFA: AAGUID из лога привязки 2026-09-19. В MDS не
    // зарегистрирован; hmac-secret поддерживает — PRF-секрет получен.
    ("aff32171f03fd048e5269324f49316a6", "Рутокен MFA"),
];

/// Название модели ключа по AAGUID, из FIDO Metadata Service.
///
/// Раньше таблица была написана вручную, и из её записей большинство
/// расходились с реестром: YubiKey 5 Series with NFC показывался как «FIPS» —
/// ложное утверждение о сертификации, — а AAGUID Feitian iePass был подписан
/// «Рутокен MFA». Теперь таблица генерируется из MDS скриптом
/// `scripts/gen_aaguid_table.py` и не правится руками.
///
/// Имя служит только подписью по умолчанию. Доверие ключу решается
/// криптографией — PRF и флагом UV в подписанных authenticator data, — а не
/// тем, как он себя называет.
pub fn aaguid_model_name(aaguid: &[u8; 16]) -> &'static str {
    let hex = hex::encode(aaguid);
    if let Some((_, name)) = VERIFIED_OUTSIDE_MDS.iter().find(|(key, _)| *key == hex) {
        return name;
    }
    super::aaguid_table::AAGUID_MODELS
        .binary_search_by(|(key, _)| (*key).cmp(hex.as_str()))
        .map(|index| super::aaguid_table::AAGUID_MODELS[index].1)
        .unwrap_or("FIDO2 Security Key")
}

/// Стабильная 32-байтная соль для PRF/hmac-secret запросов.
/// Используется как CTAP2 hmac-secret salt (raw режим, флаг HMAC_SECRET_VALUES_FLAG).
/// Одинаковая соль при каждом assertion → детерминированный PRF-output → KEK.
pub(crate) const PRF_SALT: &[u8; 32] = b"vaultisor:fido2-prf-salt:v1\x00\x00\x00\x00\x00";

/// Минимальная версия WebAuthn API: с неё Windows передаёт расширение
/// hmac-secret (PRF), без которого ключ хранилища нечем обернуть.
const MIN_API_VERSION: u32 = 6;

/// FIDO2 доступен, только если Windows умеет PRF: на старом API привязка
/// прошла бы диалоги и всё равно закончилась бы отказом.
#[cfg(target_os = "windows")]
pub fn is_fido2_supported() -> bool {
    unsafe { crate::windows_api::webauthn_ffi::WebAuthNGetApiVersionNumber() >= MIN_API_VERSION }
}

#[cfg(not(target_os = "windows"))]
pub fn is_fido2_supported() -> bool {
    false
}

/// Зарегистрировать FIDO2-ключ через Windows Security диалог.
///
/// `require_pin`:
///   - `true`  → ПИН + Touch (resident key, CTAP2, UserVerification = REQUIRED)
///   - `false` → Touch-only (non-resident, CTAP2, ПИН токена не требуется)
///
/// Если API >= 6, устанавливает bEnablePrf = TRUE для hmac-secret.
#[cfg(target_os = "windows")]
pub fn register_fido2_key_prompt(
    key_name: &str,
    require_pin: bool,
    client_data_json: &[u8],
) -> Result<Fido2Registration> {
    use crate::windows_api::webauthn_ffi::*;
    use std::ptr;

    if !is_fido2_supported() {
        return Err(VaultError::FidoFailed(
            "WebAuthn API недоступен в данной версии ОС".into(),
        ));
    }

    unsafe {
        let api_version = WebAuthNGetApiVersionNumber();
        if api_version < MIN_API_VERSION {
            return Err(VaultError::FidoFailed(
                "Windows не передаёт hmac-secret: FIDO2 требует WebAuthn API 6+ (Windows 11)"
                    .into(),
            ));
        }

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
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let cose_param = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: 1,
            pwszCredentialType: cred_type.as_ptr(),
            lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
        };
        let param_list = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_LIST {
            cCredentialParameters: 1,
            pCredentialParameters: &cose_param,
        };

        let client_json_bytes = client_data_json;

        let hash_alg: Vec<u16> = "SHA-256\0".encode_utf16().collect();
        let client_data = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: client_json_bytes.len() as u32,
            pbClientDataJSON: client_json_bytes.as_ptr(),
            pwszHashAlgId: hash_alg.as_ptr(),
        };

        // Оба режима — полноценный CTAP2. Раньше touch-only просил attachment
        // U2F_V2, то есть принудительный откат на CTAP1, где расширений нет
        // вовсе: hmac-secret там не мог появиться ни при каком токене, и
        // привязка touch-only ключа была обречена независимо от железа.
        // Разница между режимами — в резидентности и требовании UV, а не в
        // версии протокола.
        let attachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;

        log::info!(
            "register_fido2_key_prompt: api_version={}, require_pin={}, attachment={}, resident={}",
            api_version,
            require_pin,
            attachment,
            require_pin
        );

        let hwnd = windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow().0;
        let mut p_attestation: *mut WEBAUTHN_CREDENTIAL_ATTESTATION_V5 = ptr::null_mut();

        // V6 options с bEnablePrf = TRUE
        let hr = {
            let options_v6 = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_V6 {
                dwVersion: 6,
                dwTimeoutMilliseconds: 60_000,
                CredentialList: WEBAUTHN_CREDENTIALS {
                    cCredentials: 0,
                    pCredentials: ptr::null(),
                },
                Extensions: WEBAUTHN_EXTENSIONS {
                    cExtensions: 0,
                    pExtensions: ptr::null(),
                },
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
                bEnablePrf: 1,
            };

            WebAuthNAuthenticatorMakeCredential(
                hwnd,
                &rp_info,
                &user_info,
                &param_list,
                &client_data,
                &options_v6 as *const _ as *const WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_V1,
                &mut p_attestation as *mut *mut _ as *mut *mut WEBAUTHN_CREDENTIAL_ATTESTATION_V1,
            )
        };

        if hr != 0 || p_attestation.is_null() {
            let hr_u = hr as u32;
            let err_msg = match hr_u {
                // 0x80090030 — NTE_DEVICE_NOT_READY, это НЕ отмена
                // пользователем; раньше сообщение вводило в заблуждение.
                0x800704C7 => "Привязка FIDO2-ключа отменена пользователем".to_string(),
                0x80090030 => "FIDO2-ключ не готов: подключите токен и повторите".to_string(),
                0x800705B4 => {
                    "Превышено время ожидания подсоединения/касания FIDO2-ключа".to_string()
                }
                // CTAP2 без заданного на токене ПИН не создаёт credential:
                // hmac-secret и резидентные ключи опираются на pin/uv-протокол.
                // Windows отдаёт это как невнятное «не удалось прочесть ключ».
                0x8009_0026 | 0x8007_0057 | 0x8009_002D => {
                    format!("Токен отклонил создание ключа (код {hr:#X}). Чаще всего это значит, что на самом токене не задан ПИН: без него CTAP2 не может ни создать резидентный ключ, ни выдать hmac-secret. Задайте ПИН токена (Рутокен MFA Manager, YubiKey Manager) и повторите привязку.")
                }
                _ => format!("Ошибка FIDO2 (код {hr:#X})"),
            };
            // Без этой строки отказ Windows не оставлял в логе ничего:
            // «ключ не читается» выглядело одинаково при любой причине.
            log::warn!(
                "register_fido2_key_prompt: WebAuthn отказал, hr=0x{:08X} {}",
                hr as u32,
                crate::windows_api::key_credential::webauthn_error_name(hr)
            );
            return Err(VaultError::FidoFailed(err_msg));
        }

        let mut credential_id = Vec::new();
        let mut authenticator_data = Vec::new();
        let mut aaguid = [0u8; 16];
        let mut prf_supported = false;

        if !p_attestation.is_null() {
            // ОС может вернуть структуру ранней версии: общие поля читаются
            // через V1 (её префикс есть у любой версии), поля новых версий —
            // только после проверки `dwVersion`.
            let att = &*(p_attestation as *const WEBAUTHN_CREDENTIAL_ATTESTATION_V1);

            if att.cbCredentialId > 0 && !att.pbCredentialId.is_null() {
                credential_id =
                    std::slice::from_raw_parts(att.pbCredentialId, att.cbCredentialId as usize)
                        .to_vec();
            }

            if att.cbAuthenticatorData >= 55 && !att.pbAuthenticatorData.is_null() {
                let auth_data = std::slice::from_raw_parts(
                    att.pbAuthenticatorData,
                    att.cbAuthenticatorData as usize,
                );
                if auth_data.len() >= 53 {
                    aaguid.copy_from_slice(&auth_data[37..53]);
                }
                if credential_id.is_empty() {
                    let flags = auth_data[32];
                    if (flags & 0x40) != 0 && auth_data.len() >= 55 {
                        let cred_id_len =
                            ((auth_data[53] as usize) << 8) | (auth_data[54] as usize);
                        if auth_data.len() >= 55 + cred_id_len {
                            credential_id = auth_data[55..55 + cred_id_len].to_vec();
                        }
                    }
                }
            }

            if att.cbAuthenticatorData > 0 && !att.pbAuthenticatorData.is_null() {
                authenticator_data = std::slice::from_raw_parts(
                    att.pbAuthenticatorData,
                    att.cbAuthenticatorData as usize,
                )
                .to_vec();
            }

            // `bPrfEnabled` из ответа V5
            if att.dwVersion >= 5 {
                let prf_enabled = (*p_attestation).bPrfEnabled;
                prf_supported = prf_enabled != 0;
                log::info!(
                    "register: bPrfEnabled={} (dwVersion={})",
                    prf_enabled,
                    att.dwVersion
                );
            }

            WebAuthNFreeCredentialAttestation(
                p_attestation as *mut WEBAUTHN_CREDENTIAL_ATTESTATION_V1,
            );
        }

        if credential_id.is_empty() {
            return Err(VaultError::FidoFailed(
                "Не удалось получить Credential ID от FIDO2-ключа".into(),
            ));
        }

        let model = aaguid_model_name(&aaguid);
        log::info!(
            "register_fido2_key_prompt: cred_id len={}, aaguid={}, model={}, \
            require_pin={}, prf_supported={}, attachment={}",
            credential_id.len(),
            hex::encode(aaguid),
            model,
            require_pin,
            prf_supported,
            attachment
        );

        Ok(Fido2Registration {
            credential_id,
            authenticator_data,
            aaguid,
            prf_supported,
        })
    }
}

/// Аутентификация через FIDO2-ключ (assertion) с PRF-output.
///
/// При API >= 6 запрашивает hmac-secret с фиксированной солью.
/// Аутентификатор возвращает 32-байтный аппаратно-привязанный секрет.
pub fn assert_fido2_key_prompt(
    registered_credentials: &[Vec<u8>],
    require_pin: bool,
    client_data_json: &[u8],
) -> Result<Fido2AssertionResult> {
    use crate::windows_api::webauthn_ffi::*;
    use std::ptr;

    if !is_fido2_supported() {
        return Err(VaultError::FidoFailed(
            "WebAuthn API недоступен в данной версии ОС".into(),
        ));
    }

    unsafe {
        let api_version = WebAuthNGetApiVersionNumber();
        if api_version < MIN_API_VERSION {
            return Err(VaultError::FidoFailed(
                "Windows не передаёт hmac-secret: FIDO2 требует WebAuthn API 6+ (Windows 11)"
                    .into(),
            ));
        }
        log::info!(
            "assert_fido2_key_prompt: api_version={}, require_pin={}, cred_count={}",
            api_version,
            require_pin,
            registered_credentials.len()
        );

        // Экран Windows «Ключ безопасности / iPhone, iPad или Android» перед
        // входом приложение убрать не может — проверено на железе:
        //   * подсказку «ключ только USB/NFC» (dwTransports в списке
        //     разрешённых) Windows на этом экране не учитывает, хотя поле
        //     доходит на своём смещении — см. тест разметки;
        //   * attachment ANY вместо CROSS_PLATFORM выбор тоже не убирает.
        // Это интерфейс самой Windows. Пользователю сначала нужно выбрать
        // «Ключ безопасности» и только потом коснуться токена: касание до
        // выбора отменяет диалог (0x800704C7 NotAllowedError).
        let attachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;

        let rp_id: Vec<u16> = "vaultisor.app\0".encode_utf16().collect();

        let client_json_bytes = client_data_json;

        let hash_alg: Vec<u16> = "SHA-256\0".encode_utf16().collect();
        let client_data = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: client_json_bytes.len() as u32,
            pbClientDataJSON: client_json_bytes.as_ptr(),
            pwszHashAlgId: hash_alg.as_ptr(),
        };

        let cred_type_str: Vec<u16> = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // REQUIRED заставило бы Touch-only ключ спрашивать ПИН, которого у него
        // может не быть; DISCOURAGED, наоборот, позволил бы ПИН+Touch ключу
        // ответить одним касанием. Итоговое требование проверяется по флагу UV
        // уже после ответа — там известно, какой именно ключ откликнулся.
        let uv_requirement = if require_pin {
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
        } else {
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED
        };

        let hwnd = windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow().0;
        let mut p_assertion: *mut WEBAUTHN_ASSERTION_V3 = ptr::null_mut();

        // V6 options с PRF salt
        let hr = {
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

            let allow_ptrs: Vec<*const WEBAUTHN_CREDENTIAL_EX> =
                allow_creds_ex.iter().map(|c| c as *const _).collect();

            let allow_list = WEBAUTHN_CREDENTIAL_LIST {
                cCredentials: allow_ptrs.len() as u32,
                ppCredentials: allow_ptrs.as_ptr(),
            };

            let options_v6 = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_V6 {
                dwVersion: 6,
                dwTimeoutMilliseconds: 60_000,
                CredentialList: WEBAUTHN_CREDENTIALS {
                    cCredentials: 0,
                    pCredentials: ptr::null(),
                },
                Extensions: WEBAUTHN_EXTENSIONS {
                    cExtensions: 0,
                    pExtensions: ptr::null(),
                },
                dwAuthenticatorAttachment: attachment,
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

            log::info!(
                "assert: V6 options with PRF salt, {} credentials",
                allow_creds_ex.len()
            );

            WebAuthNAuthenticatorGetAssertion(
                hwnd,
                rp_id.as_ptr(),
                &client_data,
                &options_v6 as *const _ as *const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_V1,
                &mut p_assertion as *mut *mut _ as *mut *mut WEBAUTHN_ASSERTION_V1,
            )
        };

        if hr != 0 || p_assertion.is_null() {
            let hr_u = hr as u32;
            let err_msg = match hr_u {
                0x800704C7 => "Проверка FIDO2-ключа отменена пользователем".to_string(),
                0x80090030 => "FIDO2-ключ не готов: подключите токен и повторите".to_string(),
                0x800705B4 => {
                    "Превышено время ожидания подсоединения/касания FIDO2-ключа".to_string()
                }
                _ => format!("Ошибка FIDO2 (код {hr:#X})"),
            };
            // Без этой строки отказ Windows не оставлял в логе ничего:
            // «ключ не читается» выглядело одинаково при любой причине.
            log::warn!(
                "assert_fido2_key_prompt: WebAuthn отказал, hr=0x{:08X} {}",
                hr as u32,
                crate::windows_api::key_credential::webauthn_error_name(hr)
            );
            return Err(VaultError::FidoFailed(err_msg));
        }

        // Раньше по умолчанию подставлялся ПЕРВЫЙ зарегистрированный
        // ключ, поэтому ответ неизвестного аутентификатора молча выдавался за
        // него. Теперь принимается только credential id из списка разрешённых.
        let mut matched_cid: Option<Vec<u8>> = None;
        let mut prf_output: Option<Zeroizing<Vec<u8>>> = None;
        let mut authenticator_data = Vec::new();
        let mut signature = Vec::new();

        if !p_assertion.is_null() {
            // Как и при регистрации: общие поля — через V1, `pHmacSecret` —
            // только при `dwVersion >= 3`.
            let ass = &*(p_assertion as *const WEBAUTHN_ASSERTION_V1);
            if ass.cbAuthenticatorData > 32 && !ass.pbAuthenticatorData.is_null() {
                authenticator_data = std::slice::from_raw_parts(
                    ass.pbAuthenticatorData,
                    ass.cbAuthenticatorData as usize,
                )
                .to_vec();
                // В лог: флаги видны до проверки подписи, чтобы на железе было
                // понятно, почему вход прошёл или не прошёл.
                log::info!(
                    "assert: authenticator flags=0x{:02X}",
                    authenticator_data[32]
                );
            }
            if ass.cbSignature > 0 && !ass.pbSignature.is_null() {
                signature =
                    std::slice::from_raw_parts(ass.pbSignature, ass.cbSignature as usize).to_vec();
            }
            if ass.Credential.cbId > 0 && !ass.Credential.pbId.is_null() {
                let cid =
                    std::slice::from_raw_parts(ass.Credential.pbId, ass.Credential.cbId as usize)
                        .to_vec();
                log::info!("assert: credential_id len={}", cid.len());
                if registered_credentials.contains(&cid) {
                    matched_cid = Some(cid);
                } else {
                    log::warn!("assert: authenticator returned an unregistered credential id");
                }
            }

            // PRF-output из V3+ assertion
            let p_hmac_secret = if ass.dwVersion >= 3 {
                (*p_assertion).pHmacSecret
            } else {
                ptr::null()
            };
            if !p_hmac_secret.is_null() {
                let hmac_secret = &*p_hmac_secret;
                if hmac_secret.cbFirst >= 32 && !hmac_secret.pbFirst.is_null() {
                    let prf_bytes = std::slice::from_raw_parts(
                        hmac_secret.pbFirst,
                        hmac_secret.cbFirst as usize,
                    );
                    let mut secret = vec![0u8; 32];
                    secret.copy_from_slice(&prf_bytes[..32]);
                    log::info!(
                        "assert: PRF output received ({} bytes)",
                        hmac_secret.cbFirst
                    );
                    prf_output = Some(Zeroizing::new(secret));
                } else {
                    log::warn!(
                        "assert: pHmacSecret present but cbFirst={}",
                        hmac_secret.cbFirst
                    );
                }
            } else {
                log::info!("assert: no PRF output (dwVersion={})", ass.dwVersion);
            }

            WebAuthNFreeAssertion(p_assertion as *mut WEBAUTHN_ASSERTION_V1);
        }

        let credential_id = matched_cid.ok_or_else(|| {
            VaultError::FidoFailed("FIDO2-ключ не вернул известный Credential ID".into())
        })?;

        Ok(Fido2AssertionResult {
            credential_id,
            authenticator_data,
            signature,
            prf_output,
        })
    }
}

#[cfg(not(target_os = "windows"))]
pub fn register_fido2_key_prompt(
    _key_name: &str,
    _require_pin: bool,
    _client_data_json: &[u8],
) -> Result<Fido2Registration> {
    Err(VaultError::FidoFailed(
        "FIDO2 поддерживается только на Windows 10/11".into(),
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn assert_fido2_key_prompt(
    _registered_credentials: &[Vec<u8>],
    _require_pin: bool,
    _client_data_json: &[u8],
) -> Result<Fido2AssertionResult> {
    Err(VaultError::FidoFailed(
        "FIDO2 поддерживается только на Windows 10/11".into(),
    ))
}

#[cfg(test)]
mod aaguid_tests {
    use super::aaguid_model_name;
    use crate::auth::aaguid_table::AAGUID_MODELS;

    fn aaguid(hex_str: &str) -> [u8; 16] {
        let bytes = hex::decode(hex_str).unwrap();
        bytes.try_into().unwrap()
    }

    /// Поиск двоичный: при несортированной таблице он молча промахивается и
    /// выдаёт имя по умолчанию для известного ключа. Генератор сортирует,
    /// но ручная правка файла сломала бы это незаметно.
    #[test]
    fn table_is_sorted_and_unique() {
        for pair in AAGUID_MODELS.windows(2) {
            assert!(
                pair[0].0 < pair[1].0,
                "не отсортировано или дубль: {:?}",
                pair
            );
        }
    }

    #[test]
    fn every_key_is_32_lowercase_hex() {
        for (key, _) in AAGUID_MODELS {
            assert_eq!(key.len(), 32, "{key}");
            assert!(
                key.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                "{key}"
            );
        }
    }

    /// Регрессия прежней ручной таблицы: YubiKey 5 Series with NFC
    /// показывался как «FIPS». Для ключа безопасности это ложное утверждение
    /// о сертификации.
    #[test]
    fn non_fips_yubikey_is_not_labelled_fips() {
        let name = aaguid_model_name(&aaguid("2fc0579f811347eab116bb5a8db9202a"));
        assert_eq!(name, "YubiKey 5 Series with NFC");
        assert!(!name.contains("FIPS"));
    }

    /// Регрессия: этот AAGUID принадлежит Feitian iePass, а подписан был
    /// «Рутокен MFA». Если настоящий Рутокен отдаёт именно его, лог привязки
    /// это покажет — но утверждать это без проверки нельзя.
    #[test]
    fn feitian_aaguid_is_not_claimed_as_rutoken() {
        let name = aaguid_model_name(&aaguid("3e22415d7fdf4ea48a0cdd60c4249b9d"));
        assert!(name.contains("Feitian"), "{name}");
    }

    /// Рутокен MFA в MDS нет; его AAGUID снят с живого токена.
    #[test]
    fn rutoken_mfa_is_named_from_verified_hardware() {
        let name = aaguid_model_name(&aaguid("aff32171f03fd048e5269324f49316a6"));
        assert_eq!(name, "Рутокен MFA");
    }

    /// Проверенные вручную записи не должны дублировать реестр: иначе ручная
    /// запись молча перекроет официальное имя.
    #[test]
    fn verified_entries_are_not_in_mds() {
        for (key, _) in super::VERIFIED_OUTSIDE_MDS {
            assert!(
                AAGUID_MODELS
                    .binary_search_by(|(k, _)| (*k).cmp(key))
                    .is_err(),
                "{key} уже есть в MDS — ручная запись не нужна"
            );
        }
    }

    #[test]
    fn unknown_aaguid_falls_back_to_generic_name() {
        assert_eq!(aaguid_model_name(&[0u8; 16]), "FIDO2 Security Key");
    }
}
