// DPAPI — Data Protection API.
//
// CryptProtectData оборачивает данные в blob, расшифровать который
// можно только в той же учётной записи Windows на том же устройстве
// (если флаг CRYPTPROTECT_LOCAL_MACHINE НЕ установлен — это наш дефолт).
//
// Это даёт привязку к (user, device): при копировании БД на другую машину
// или другому пользователю blob не расшифровывается → master-key недоступен.
//
// Дополнительный entropy (опционально) — ещё один секрет, без которого
// расшифровка невозможна. Мы используем его как "vaultisor:dpapi:v1".

use windows::core::PWSTR;
use windows::Win32::Foundation::LocalFree;
use windows::Win32::Foundation::HLOCAL;
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
};

use crate::error::{Result, VaultError};

// Принятый остаток (задокументировано намеренно):
// ENTROPY — константа в бинарнике, а не секрет. DPAPI(CurrentUser) — это ACL
// уровня ОС, а не криптография: код в той же сессии Windows может вызвать
// CryptProtect/UnprotectData с этой же entropy. Поэтому same-user malware
// теоретически может подделать meta-MAC (сбросить счётчик попыток PIN).
//
// Почему НЕ «усилено» domain-separation'ом: разные namespace НЕ мешают
// same-user коду (константы известны из бинарника) — находку это не закрывает,
// зато рассинхрон namespace protect/unprotect сломал бы unlock/recovery.
// Почему НЕ TPM-binding: integrity_key снимается ДО загрузки device_secret
// (иначе циклическая зависимость), а сам TPM-ключ silent-signable (H3) →
// бонус нулевой при усложнении критического пути.
//
// Практический эффект находки МАЛ: реальный тормоз перебора PIN — Argon2id
// (512 МБ) + device_secret в TPM, а не счётчик попыток. ЕДИНСТВЕННЫЙ полноценный
// фикс — TPM NV monotonic counter (аппаратный, не откатываемый same-user кодом) —
// вынесен как отдельная будущая фича.
const ENTROPY: &[u8] = b"vaultisor:dpapi:v1";

/// Длина для `CRYPT_INTEGER_BLOB`: поле 32-битное, и усечение `as u32`
/// передало бы DPAPI укороченный буфер вместо отказа.
fn blob_len(len: usize) -> Result<u32> {
    u32::try_from(len).map_err(|_| {
        log::warn!("DPAPI: buffer of {len} bytes does not fit CRYPT_INTEGER_BLOB");
        VaultError::DpapiFailure
    })
}

/// Проверка доступности DPAPI: пробуем round-trip короткой строки.
pub fn is_available() -> bool {
    let probe = b"\x01\x02\x03\x04";
    match protect(probe) {
        Ok(blob) => unprotect(&blob).map(|p| *p == probe[..]).unwrap_or(false),
        Err(_) => false,
    }
}

/// Защитить blob с привязкой к user+device (CurrentUser scope) с дефолтной entropy.
pub fn protect(plaintext: &[u8]) -> Result<Vec<u8>> {
    protect_with_entropy(plaintext, ENTROPY)
}

/// Защитить blob с привязкой к user+device (CurrentUser scope) и заданной entropy.
pub fn protect_with_entropy(plaintext: &[u8], entropy_bytes: &[u8]) -> Result<Vec<u8>> {
    // SAFETY:
    // - Pointers in CRYPT_INTEGER_BLOB input point to valid slice memory for the duration of the FFI call.
    // - entropy pointer points to valid slice memory.
    // - output.pbData is allocated by the OS and we correctly free it using LocalFree after use.
    unsafe {
        let input = CRYPT_INTEGER_BLOB {
            cbData: blob_len(plaintext.len())?,
            pbData: plaintext.as_ptr() as *mut u8,
        };
        let entropy = CRYPT_INTEGER_BLOB {
            cbData: blob_len(entropy_bytes.len())?,
            pbData: entropy_bytes.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();

        // Флаги:
        //  0 = CurrentUser (привязка user+device).
        //  CRYPTPROTECT_UI_FORBIDDEN = не показывать UI (нужно для backend).
        const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

        let description: PWSTR = PWSTR::null();
        CryptProtectData(
            &input,
            description,
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|error| {
            // Код ошибки больше не проглатывается — без него
            // невозможно отличить «чужая учётная запись» от «повреждён blob».
            log::warn!("CryptProtectData failed: {error}");
            VaultError::DpapiFailure
        })?;

        // Скопировать в Vec и освободить системный buffer.
        // from_raw_parts требует non-null даже при нулевой длине.
        let result = if output.pbData.is_null() || output.cbData == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec()
        };
        if !output.pbData.is_null() {
            let _ = LocalFree(Some(HLOCAL(output.pbData as *mut _)));
        }
        Ok(result)
    }
}

/// Снять защиту (только в той же учётной записи на том же устройстве) с дефолтной entropy.
pub fn unprotect(blob: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    unprotect_with_entropy(blob, ENTROPY)
}

/// Снять защиту с заданной entropy.
pub fn unprotect_with_entropy(
    blob: &[u8],
    entropy_bytes: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    // SAFETY:
    // - Pointers in CRYPT_INTEGER_BLOB input point to valid slice memory for the duration of the FFI call.
    // - entropy pointer points to valid slice memory.
    // - output.pbData and description are allocated by the OS and we free them with LocalFree.
    // - Plaintext is safely zeroized before freeing.
    unsafe {
        let input = CRYPT_INTEGER_BLOB {
            cbData: blob_len(blob.len())?,
            pbData: blob.as_ptr() as *mut u8,
        };
        let entropy = CRYPT_INTEGER_BLOB {
            cbData: blob_len(entropy_bytes.len())?,
            pbData: entropy_bytes.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        let mut description: PWSTR = PWSTR::null();

        const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

        CryptUnprotectData(
            &input,
            Some(&mut description as *mut _),
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|error| {
            log::warn!("CryptUnprotectData failed: {error}");
            VaultError::DpapiFailure
        })?;

        let result = if output.pbData.is_null() || output.cbData == 0 {
            Vec::new()
        } else {
            let slice = std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize);
            let copied = slice.to_vec();
            // Открытый текст в буфере ОС затирается до освобождения; `zeroize`
            // пишет через volatile и не выбрасывается как мёртвая запись.
            zeroize::Zeroize::zeroize(slice);
            copied
        };
        if !output.pbData.is_null() {
            let _ = LocalFree(Some(HLOCAL(output.pbData as *mut _)));
        }
        if !description.is_null() {
            let _ = LocalFree(Some(HLOCAL(description.0 as *mut _)));
        }
        Ok(zeroize::Zeroizing::new(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Локальный тест требует Windows; запускайте только на Windows-машине.
    #[test]
    #[cfg(windows)]
    fn dpapi_roundtrip() {
        let secret = b"vaultisor-dpapi-test-secret";
        let blob = protect(secret).expect("DPAPI protect недоступен в этой сессии Windows");
        assert_ne!(blob.as_slice(), secret); // действительно зашифровано
        let restored = unprotect(&blob).expect("unprotect must succeed when protect succeeded");
        assert_eq!(restored.as_slice(), secret);
    }

    #[test]
    fn oversized_buffers_are_refused_not_truncated() {
        assert_eq!(blob_len(0).unwrap(), 0);
        assert_eq!(blob_len(u32::MAX as usize).unwrap(), u32::MAX);
        #[cfg(target_pointer_width = "64")]
        assert!(blob_len(u32::MAX as usize + 1).is_err());
    }

    #[test]
    #[cfg(windows)]
    fn dpapi_custom_entropy_roundtrip() {
        let secret = b"vaultisor-dpapi-custom-entropy-secret";
        let entropy = b"custom:entropy:test:123";
        let blob = protect_with_entropy(secret, entropy)
            .expect("DPAPI protect недоступен в этой сессии Windows");
        assert_ne!(blob.as_slice(), secret);
        let restored =
            unprotect_with_entropy(&blob, entropy).expect("unprotect_with_entropy must succeed");
        assert_eq!(restored.as_slice(), secret);

        // Wrong entropy must fail to unprotect
        let wrong_entropy = b"wrong:entropy:456";
        assert!(unprotect_with_entropy(&blob, wrong_entropy).is_err());
    }
}
