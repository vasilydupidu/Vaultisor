//! Windows Hello credential for the unpackaged Win32 build.
//!
//! Native WebAuthn asks the Windows platform authenticator to verify the user
//! as part of a credential assertion. Vaultisor verifies that assertion with
//! the MAC-protected public key before opening a session.

use base64::Engine;
use subtle::ConstantTimeEq;

use crate::auth::webauthn_rp::{self, Ceremony, ClientData, RP_ID};
use crate::error::{Result, VaultError};
use crate::windows_api::webauthn_ffi as webauthn;

const PREFIX: &str = "webauthn-platform-v1:";

#[derive(Debug, Clone)]
pub struct CreatedCredential {
    /// Versioned opaque credential id. It is public and authenticated by the
    /// metadata MAC.
    pub name: String,
    /// Uncompressed SEC1 P-256 public key: 0x04 || X || Y.
    pub public_key: Vec<u8>,
}

pub fn is_supported() -> bool {
    unsafe {
        if webauthn::WebAuthNGetApiVersionNumber() < 1 {
            return false;
        }
        let mut available = 0;
        webauthn::WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(&mut available) == 0
            && available != 0
    }
}

/// Завести платформенный credential и тут же доказать, что им можно войти.
///
/// Регистрация и вход — разные церемонии WebAuthn, и успешная регистрация
/// НЕ означает, что assertion потом пройдёт. Поэтому здесь два запроса Hello
/// подряд, и это осознанно: если проверочный assertion не прошёл, credential
/// удаляется и наружу уходит ошибка — лучше не включить Hello, чем закрыть
/// пользователю доступ к данным.
pub fn create(hwnd_raw: isize, user_handle: &[u8; 16]) -> Result<CreatedCredential> {
    let created = create_blocking(hwnd_raw, user_handle)?;
    match verify(hwnd_raw, &created.name, &created.public_key) {
        Ok(()) => Ok(created),
        Err(error) => {
            log::warn!("Hello enrollment rolled back: proof assertion failed ({error})");
            if let Err(cleanup) = delete(&created.name) {
                log::warn!("stale Hello credential left in Windows passkey store: {cleanup}");
            }
            Err(error)
        }
    }
}

pub fn delete(name: &str) -> Result<()> {
    let credential_id = decode_name(name)?;
    let Some(delete_platform_credential) = webauthn::delete_platform_credential_fn() else {
        // Функция появилась только в WebAuthn API v4 (Windows 11 22H2).
        // На более старых системах удалять нечего — platform credential там не
        // создаётся; сообщаем честно, вместо того чтобы падать при запуске.
        log::warn!("WebAuthNDeletePlatformCredential unavailable on this Windows build");
        return Err(VaultError::HelloUnavailable);
    };
    // SAFETY: resolved from the already loaded webauthn.dll; the buffer stays
    // alive for the duration of the call.
    let status =
        unsafe { delete_platform_credential(credential_id.len() as u32, credential_id.as_ptr()) };
    // Отсутствующий ключ — не ошибка: очистка после сбоя повторяется
    // безопасно, а пользователь мог удалить ключ в Параметрах сам.
    if status == 0 || status as u32 == NTE_NOT_FOUND {
        Ok(())
    } else {
        Err(map_hresult(status))
    }
}

const NTE_NOT_FOUND: u32 = 0x8009_0011;

/// Имена платформенных credential'ов Vaultisor с данным user.id.
///
/// user.id выбирает Vaultisor и записывает в журнал операций до создания
/// ключа: идентификатор credential'а выдаёт аутентификатор, и узнать его до
/// создания нельзя. По user.id журнал находит ключ, созданный перед сбоем.
pub fn find_by_user(user_handle: &[u8; 16]) -> Result<Vec<String>> {
    Ok(list_credentials()?
        .into_iter()
        .filter(|(_, user)| user.as_slice() == user_handle)
        .map(|(id, _)| encode_name(&id))
        .collect())
}

/// Есть ли credential с этим именем в хранилище ключей Windows.
pub fn exists(name: &str) -> Result<bool> {
    let wanted = decode_name(name)?;
    Ok(list_credentials()?.iter().any(|(id, _)| *id == wanted))
}

/// Все платформенные credential'ы RP Vaultisor: (credential id, user.id).
fn list_credentials() -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let Some((get_list, free_list)) = webauthn::platform_credential_list_fns() else {
        return Err(VaultError::HelloUnavailable);
    };
    let rp_id = wide(RP_ID);
    let options = webauthn::WEBAUTHN_GET_CREDENTIALS_OPTIONS {
        dwVersion: webauthn::WEBAUTHN_GET_CREDENTIALS_OPTIONS_VERSION_1,
        pwszRpId: rp_id.as_ptr(),
        bBrowserInPrivateMode: 0,
    };
    let mut list = std::ptr::null_mut();
    // SAFETY: options и rp_id живут до конца вызова; список освобождается
    // парной функцией ниже на любом пути.
    let status = unsafe { get_list(&options, &mut list) };
    if status as u32 == NTE_NOT_FOUND {
        return Ok(Vec::new());
    }
    if status != 0 || list.is_null() {
        return Err(map_hresult(status));
    }
    let collected = (|| {
        // SAFETY: list возвращён ОС и валиден до free_list; каждый элемент и
        // его вложенные указатели проверяются на NULL перед чтением.
        unsafe {
            let list = &*list;
            let mut out = Vec::with_capacity(list.cCredentialDetails as usize);
            for index in 0..list.cCredentialDetails as usize {
                let details = *list.ppCredentialDetails.add(index);
                if details.is_null() {
                    continue;
                }
                let details = &*details;
                let id = checked_slice(details.pbCredentialID, details.cbCredentialID)?.to_vec();
                let user = if details.pUserInformation.is_null() {
                    Vec::new()
                } else {
                    let user = &*details.pUserInformation;
                    checked_slice(user.pbId, user.cbId)?.to_vec()
                };
                out.push((id, user));
            }
            Ok(out)
        }
    })();
    // SAFETY: освобождаем ровно то, что вернула get_list.
    unsafe { free_list(list) };
    collected
}

fn encode_name(credential_id: &[u8]) -> String {
    format!(
        "{PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential_id)
    )
}

fn decode_name(name: &str) -> Result<Vec<u8>> {
    let encoded = name
        .strip_prefix(PREFIX)
        .ok_or(VaultError::CorruptedWrapper)?;
    let id = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| VaultError::CorruptedWrapper)?;
    if id.is_empty() {
        return Err(VaultError::CorruptedWrapper);
    }
    Ok(id)
}

fn create_blocking(hwnd_raw: isize, user_handle: &[u8; 16]) -> Result<CreatedCredential> {
    use std::ptr;
    if !is_supported() {
        return Err(VaultError::HelloUnavailable);
    }
    unsafe {
        let rp_id = wide(RP_ID);
        let rp_name = wide("Vaultisor");
        let rp = webauthn::WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: 1,
            pwszId: rp_id.as_ptr(),
            pwszName: rp_name.as_ptr(),
            pwszIcon: ptr::null(),
        };
        let user_id = *user_handle;
        let user_name = wide("Vaultisor Windows Hello");
        let display_name = wide("Vaultisor additional verification");
        let user = webauthn::WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: 1,
            cbId: user_id.len() as u32,
            pbId: user_id.as_ptr(),
            pwszName: user_name.as_ptr(),
            pwszIcon: ptr::null(),
            pwszDisplayName: display_name.as_ptr(),
        };
        let kind = wide("public-key");
        let parameter = webauthn::WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: 1,
            pwszCredentialType: kind.as_ptr(),
            lAlg: -7,
        };
        let parameters = webauthn::WEBAUTHN_COSE_CREDENTIAL_PARAMETER_LIST {
            cCredentialParameters: 1,
            pCredentialParameters: &parameter,
        };
        let client_data = ClientData::new(Ceremony::Create);
        let hash_name = wide("SHA-256");
        let client = webauthn::WEBAUTHN_CLIENT_DATA {
            dwVersion: 1,
            cbClientDataJSON: client_data.json.len() as u32,
            pbClientDataJSON: client_data.json.as_ptr(),
            pwszHashAlgId: hash_name.as_ptr(),
        };
        let options = webauthn::WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_V1 {
            dwVersion: 1,
            dwTimeoutMilliseconds: 60_000,
            CredentialList: webauthn::empty_credentials(),
            Extensions: webauthn::empty_extensions(),
            dwAuthenticatorAttachment: webauthn::WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
            // Ключ НЕ discoverable, и это осознанно: Vaultisor сам хранит его
            // идентификатор, «обнаруживать» ключ незачем. Discoverable-ключ
            // ломал вход в паре со списком разрешённых и заставлял Windows
            // показывать выбор из нескольких passkey одного и того же RP.
            //
            // ВАЖНО: на скрытие ключа из «Параметры → Учётные записи → Ключи
            // доступа» это НЕ влияет. Платформенный аутентификатор Windows
            // Hello держит у себя все свои credential'ы независимо от этого
            // флага (в отличие от аппаратных токенов, где не-discoverable ключ
            // заворачивается внутрь credential id). Пользователь видит запись
            // и может её удалить — после чего вход в хранилище возможен только
            // через восстановление по долям Шамира. Это компенсируется
            // предупреждением в интерфейсе и внятной ошибкой при входе.
            bRequireResidentKey: 0,
            dwUserVerificationRequirement:
                webauthn::WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            dwAttestationConveyancePreference: 0,
            dwFlags: 0,
        };
        let mut attestation = ptr::null_mut();
        let status = webauthn::WebAuthNAuthenticatorMakeCredential(
            hwnd_raw as *mut _,
            &rp,
            &user,
            &parameters,
            &client,
            &options,
            &mut attestation,
        );
        if status != 0 || attestation.is_null() {
            return Err(map_hresult(status));
        }
        let result = (|| {
            let response = &*attestation;
            let credential_id = checked_slice(response.pbCredentialId, response.cbCredentialId)?;
            let auth_data =
                checked_slice(response.pbAuthenticatorData, response.cbAuthenticatorData)?;
            // Регистрация проверяется как у RP: наш RP ID, UP и UV, credential
            // id в attested data совпадает с возвращённым, ключ — ES256.
            let (public_key, _) = webauthn_rp::verify_registration(auth_data, credential_id, true)
                .map_err(|_| VaultError::HelloFailed)?;
            Ok(CreatedCredential {
                name: encode_name(credential_id),
                public_key,
            })
        })();
        webauthn::WebAuthNFreeCredentialAttestation(attestation);
        result
    }
}

pub fn verify(hwnd_raw: isize, name: &str, public_key: &[u8]) -> Result<()> {
    use std::ptr;
    if !is_supported() {
        return Err(VaultError::HelloUnavailable);
    }
    if public_key.len() != 65 || public_key[0] != 4 {
        return Err(VaultError::CorruptedWrapper);
    }
    let credential_id = decode_name(name)?;
    unsafe {
        let rp_id = wide(RP_ID);
        let kind = wide("public-key");
        let client_data = ClientData::new(Ceremony::Get);
        let hash_name = wide("SHA-256");
        let client = webauthn::WEBAUTHN_CLIENT_DATA {
            dwVersion: 1,
            cbClientDataJSON: client_data.json.len() as u32,
            pbClientDataJSON: client_data.json.as_ptr(),
            pwszHashAlgId: hash_name.as_ptr(),
        };
        // Ключ не-discoverable, поэтому адресуем его списком разрешённых —
        // это единственный способ им воспользоваться и штатное назначение
        // поля. Сломанным был не список сам по себе, а его сочетание с
        // discoverable-ключом: Windows отвечала на такую пару ERROR_CANCELLED
        // и диалогом «при входе с ключом доступа возникла ошибка».
        //
        // Список из одного элемента означает, что выбор ключа пользователю
        // не показывается: Windows сразу запрашивает Hello.
        let credential = webauthn::WEBAUTHN_CREDENTIAL {
            dwVersion: 1,
            cbId: credential_id.len() as u32,
            pbId: credential_id.as_ptr(),
            pwszCredentialType: kind.as_ptr(),
        };
        let options = webauthn::WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_V1 {
            dwVersion: 1,
            dwTimeoutMilliseconds: 60_000,
            CredentialList: webauthn::WEBAUTHN_CREDENTIALS {
                cCredentials: 1,
                pCredentials: &credential,
            },
            Extensions: webauthn::empty_extensions(),
            dwAuthenticatorAttachment: webauthn::WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
            dwUserVerificationRequirement:
                webauthn::WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            dwFlags: 0,
        };
        let mut assertion = ptr::null_mut();
        let status = webauthn::WebAuthNAuthenticatorGetAssertion(
            hwnd_raw as *mut _,
            rp_id.as_ptr(),
            &client,
            &options,
            &mut assertion,
        );
        if status != 0 || assertion.is_null() {
            return Err(map_hresult(status));
        }
        let result = (|| {
            let response = &*assertion;
            let returned_id = checked_slice(response.Credential.pbId, response.Credential.cbId)?;
            if !bool::from(returned_id.ct_eq(credential_id.as_slice())) {
                return Err(VaultError::HelloFailed);
            }
            let auth_data =
                checked_slice(response.pbAuthenticatorData, response.cbAuthenticatorData)?;
            let signature = checked_slice(response.pbSignature, response.cbSignature)?;
            webauthn_rp::verify_assertion(public_key, auth_data, &client_data.json, signature, true)
                .map(|_| ())
                .map_err(|_| VaultError::HelloFailed)
        })();
        webauthn::WebAuthNFreeAssertion(assertion);
        result
    }
}

unsafe fn checked_slice<'a>(pointer: *const u8, len: u32) -> Result<&'a [u8]> {
    if len == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() {
        return Err(VaultError::HelloFailed);
    }
    Ok(std::slice::from_raw_parts(pointer, len as usize))
}

/// Имя ошибки WebAuthn по HRESULT (`NotAllowedError`, `InvalidStateError`, …).
///
/// Общая для обоих биндингов WebAuthn: это просто поиск строки в webauthn.dll,
/// разметка структур на него не влияет.
pub(crate) fn webauthn_error_name(status: i32) -> String {
    // SAFETY: API возвращает указатель на статическую строку внутри webauthn.dll
    // либо NULL для неизвестного кода.
    let pointer = unsafe { webauthn::WebAuthNGetErrorName(status) };
    if pointer.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: строка завершается нулём; ограничиваем длину на случай мусора.
    unsafe {
        while len < 128 && *pointer.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(pointer, len))
    }
}

fn map_hresult(status: i32) -> VaultError {
    let name = webauthn_error_name(status);
    let code = format!("0x{:08X}", status as u32);
    let detail = if name.is_empty() {
        code.clone()
    } else {
        format!("{code} {name}")
    };
    log::warn!("WebAuthn ceremony failed: {detail}");
    match status as u32 {
        0x8007_04C7 | 0x8009_0036 => VaultError::HelloCancelled,
        0x8007_05B4 | 0x8009_000B | 0x8009_002E => VaultError::HelloUnavailable,
        _ => VaultError::HelloOsError(detail),
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hresults_are_typed() {
        assert!(matches!(
            map_hresult(0x8007_04C7u32 as i32),
            VaultError::HelloCancelled
        ));
        // Неизвестный код не должен теряться: он обязан доехать до пользователя
        // в тексте ошибки, иначе диалог Windows «Произошла ошибка» ничем не
        // отличается от любого другого сбоя.
        let VaultError::HelloOsError(detail) = map_hresult(-1) else {
            panic!("unknown HRESULT must carry a diagnostic");
        };
        assert!(detail.contains("0xFFFFFFFF"), "detail was {detail}");
    }

    #[test]
    #[ignore = "requires interactive Windows Hello enrollment"]
    fn hardware_create_assert_reopen() {
        assert!(is_supported());
        let hwnd = unsafe { GetConsoleWindow() } as isize;
        assert_ne!(hwnd, 0, "hardware test needs a console window");
        let created =
            create_blocking(hwnd, &[7u8; 16]).expect("platform credential enrollment must succeed");
        verify(hwnd, &created.name, &created.public_key)
            .expect("platform assertion signature must verify");
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetConsoleWindow() -> *mut std::ffi::c_void;
    }
}
