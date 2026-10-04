//! Проверка разметки FFI-структур WebAuthn против `webauthn.h`.
//!
//! Компилятор разметку C-структур не проверяет: переставленное поле или
//! забытый `DWORD` заставят Windows читать мусор по нашему указателю, а сбой
//! проявится как «не работает у некоторых пользователей». Оба дефекта, которые
//! ловились руками, — passkey вместо не-discoverable ключа и touch-only через
//! CTAP1 — были ошибками в параметрах WebAuthn.
//!
//! Раньше биндингов было два, и тест сверял их между собой. Теперь биндинг
//! один (`webauthn_ffi`), поэтому проверяется главное — совпадение с SDK для
//! x86_64: `DWORD` 4 байта, указатель 8 с выравниванием 8, поэтому после
//! нечётного числа `DWORD` компилятор вставляет дополнение.
//!
//! Если Microsoft изменит структуру, тест упадёт — и это правильно: менять
//! разметку вслепую нельзя.

#![cfg(test)]

use std::mem::{offset_of, size_of};

use crate::windows_api::webauthn_ffi::*;

#[test]
fn entity_and_list_structs_match_the_sdk() {
    assert_eq!(size_of::<WEBAUTHN_RP_ENTITY_INFORMATION>(), 32);
    assert_eq!(size_of::<WEBAUTHN_USER_ENTITY_INFORMATION>(), 40);
    assert_eq!(size_of::<WEBAUTHN_COSE_CREDENTIAL_PARAMETER>(), 24);
    assert_eq!(size_of::<WEBAUTHN_COSE_CREDENTIAL_PARAMETER_LIST>(), 16);
    assert_eq!(size_of::<WEBAUTHN_CLIENT_DATA>(), 24);
    assert_eq!(size_of::<WEBAUTHN_EXTENSIONS>(), 16);

    assert_eq!(size_of::<WEBAUTHN_CREDENTIAL>(), 24);
    assert_eq!(offset_of!(WEBAUTHN_CREDENTIAL, cbId), 4);
    assert_eq!(offset_of!(WEBAUTHN_CREDENTIAL, pbId), 8);
    assert_eq!(offset_of!(WEBAUTHN_CREDENTIAL, pwszCredentialType), 16);
    assert_eq!(size_of::<WEBAUTHN_CREDENTIALS>(), 16);

    // Подсказка транспорта: именно ею мы говорим Windows «ключ только USB/NFC».
    assert_eq!(size_of::<WEBAUTHN_CREDENTIAL_EX>(), 32);
    assert_eq!(offset_of!(WEBAUTHN_CREDENTIAL_EX, dwTransports), 24);
    assert_eq!(size_of::<WEBAUTHN_CREDENTIAL_LIST>(), 16);
    assert_eq!(offset_of!(WEBAUTHN_CREDENTIAL_LIST, ppCredentials), 8);
}

/// Соль и ответ hmac-secret: от этих смещений зависит, из чего будет выведен
/// ключ шифрования мастер-ключа FIDO2.
#[test]
fn hmac_secret_structs_match_the_sdk() {
    assert_eq!(size_of::<WEBAUTHN_HMAC_SECRET_SALT>(), 32);
    assert_eq!(offset_of!(WEBAUTHN_HMAC_SECRET_SALT, pbFirst), 8);
    assert_eq!(offset_of!(WEBAUTHN_HMAC_SECRET_SALT, cbSecond), 16);
    assert_eq!(offset_of!(WEBAUTHN_HMAC_SECRET_SALT, pbSecond), 24);

    assert_eq!(size_of::<WEBAUTHN_HMAC_SECRET_SALT_VALUES>(), 24);
    assert_eq!(
        offset_of!(
            WEBAUTHN_HMAC_SECRET_SALT_VALUES,
            cCredWithHmacSecretSaltList
        ),
        8
    );
    assert_eq!(
        offset_of!(
            WEBAUTHN_HMAC_SECRET_SALT_VALUES,
            pCredWithHmacSecretSaltList
        ),
        16
    );
}

#[test]
fn make_credential_options_match_the_sdk() {
    type V1 = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_V1;
    assert_eq!(size_of::<V1>(), 64);
    assert_eq!(offset_of!(V1, CredentialList), 8);
    assert_eq!(offset_of!(V1, Extensions), 24);
    assert_eq!(offset_of!(V1, dwAuthenticatorAttachment), 40);
    assert_eq!(offset_of!(V1, bRequireResidentKey), 44);
    assert_eq!(offset_of!(V1, dwUserVerificationRequirement), 48);

    // V6 должен начинаться точно как V1: Windows читает его по указателю на V1.
    type V6 = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_V6;
    assert_eq!(size_of::<V6>(), 104);
    assert_eq!(offset_of!(V6, dwAuthenticatorAttachment), 40);
    assert_eq!(offset_of!(V6, bRequireResidentKey), 44);
    assert_eq!(offset_of!(V6, dwFlags), 56);
    assert_eq!(offset_of!(V6, pCancellationId), 64);
    assert_eq!(offset_of!(V6, pExcludeCredentialList), 72);
    assert_eq!(offset_of!(V6, bPreferResidentKey), 88);
    assert_eq!(offset_of!(V6, bEnablePrf), 96);
}

#[test]
fn get_assertion_options_match_the_sdk() {
    type V1 = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_V1;
    assert_eq!(size_of::<V1>(), 56);
    assert_eq!(offset_of!(V1, CredentialList), 8);
    assert_eq!(offset_of!(V1, Extensions), 24);
    assert_eq!(offset_of!(V1, dwAuthenticatorAttachment), 40);
    assert_eq!(offset_of!(V1, dwUserVerificationRequirement), 44);

    type V4 = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_V4;
    assert_eq!(size_of::<V4>(), 88);
    assert_eq!(offset_of!(V4, pAllowCredentialList), 80);

    type V6 = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_V6;
    assert_eq!(size_of::<V6>(), 120);
    assert_eq!(offset_of!(V6, dwFlags), 48);
    assert_eq!(offset_of!(V6, pwszU2fAppId), 56);
    assert_eq!(offset_of!(V6, pAllowCredentialList), 80);
    assert_eq!(offset_of!(V6, pHmacSecretSaltValues), 104);
    assert_eq!(offset_of!(V6, bBrowserInPrivateMode), 112);
}

/// Перечисление платформенных credential'ов: по нему журнал операций находит
/// ключ Hello, созданный перед сбоем, по заранее выбранному user.id.
#[test]
fn credential_list_structs_match_the_sdk() {
    assert_eq!(size_of::<WEBAUTHN_GET_CREDENTIALS_OPTIONS>(), 24);
    assert_eq!(offset_of!(WEBAUTHN_GET_CREDENTIALS_OPTIONS, pwszRpId), 8);
    assert_eq!(
        offset_of!(WEBAUTHN_GET_CREDENTIALS_OPTIONS, bBrowserInPrivateMode),
        16
    );

    assert_eq!(size_of::<WEBAUTHN_CREDENTIAL_DETAILS>(), 40);
    assert_eq!(offset_of!(WEBAUTHN_CREDENTIAL_DETAILS, cbCredentialID), 4);
    assert_eq!(offset_of!(WEBAUTHN_CREDENTIAL_DETAILS, pbCredentialID), 8);
    assert_eq!(offset_of!(WEBAUTHN_CREDENTIAL_DETAILS, pRpInformation), 16);
    assert_eq!(
        offset_of!(WEBAUTHN_CREDENTIAL_DETAILS, pUserInformation),
        24
    );
    assert_eq!(offset_of!(WEBAUTHN_CREDENTIAL_DETAILS, bRemovable), 32);

    assert_eq!(size_of::<WEBAUTHN_CREDENTIAL_DETAILS_LIST>(), 16);
    assert_eq!(
        offset_of!(WEBAUTHN_CREDENTIAL_DETAILS_LIST, ppCredentialDetails),
        8
    );
}

/// Ответы аутентификатора: отсюда читаются credential id, флаги, подпись,
/// признак PRF и сам PRF-секрет.
#[test]
fn response_structs_match_the_sdk() {
    type Att1 = WEBAUTHN_CREDENTIAL_ATTESTATION_V1;
    assert_eq!(size_of::<Att1>(), 96);
    assert_eq!(offset_of!(Att1, pwszFormatType), 8);
    assert_eq!(offset_of!(Att1, cbAuthenticatorData), 16);
    assert_eq!(offset_of!(Att1, pbAuthenticatorData), 24);
    assert_eq!(offset_of!(Att1, cbCredentialId), 80);
    assert_eq!(offset_of!(Att1, pbCredentialId), 88);

    type Att5 = WEBAUTHN_CREDENTIAL_ATTESTATION_V5;
    assert_eq!(offset_of!(Att5, pbCredentialId), 88);
    assert_eq!(offset_of!(Att5, Extensions), 96);
    assert_eq!(offset_of!(Att5, dwUsedTransport), 112);
    assert_eq!(offset_of!(Att5, bPrfEnabled), 128);

    type As1 = WEBAUTHN_ASSERTION_V1;
    assert_eq!(size_of::<As1>(), 72);
    assert_eq!(offset_of!(As1, cbAuthenticatorData), 4);
    assert_eq!(offset_of!(As1, pbAuthenticatorData), 8);
    assert_eq!(offset_of!(As1, cbSignature), 16);
    assert_eq!(offset_of!(As1, pbSignature), 24);
    assert_eq!(offset_of!(As1, Credential), 32);

    type As3 = WEBAUTHN_ASSERTION_V3;
    assert_eq!(offset_of!(As3, Credential), 32);
    assert_eq!(offset_of!(As3, Extensions), 72);
    assert_eq!(offset_of!(As3, pbCredLargeBlob), 96);
    assert_eq!(offset_of!(As3, pHmacSecret), 112);
}
