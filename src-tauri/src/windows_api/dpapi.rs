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

// AUDIT M6/L3 — принятый остаток (задокументировано намеренно):
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

/// Проверка доступности DPAPI: пробуем round-trip короткой строки.
pub fn is_available() -> bool {
    let probe = b"\x01\x02\x03\x04";
    match protect(probe) {
        Ok(blob) => unprotect(&blob).map(|p| *p == probe[..]).unwrap_or(false),
        Err(_) => false,
    }
}

/// Защитить blob с привязкой к user+device (CurrentUser scope).
pub fn protect(plaintext: &[u8]) -> Result<Vec<u8>> {
    // SAFETY:
    // - Pointers in CRYPT_INTEGER_BLOB input point to valid slice memory for the duration of the FFI call.
    // - ENTROPY pointer also points to valid static memory.
    // - output.pbData is allocated by the OS and we correctly free it using LocalFree after use.
    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: plaintext.len() as u32,
            pbData: plaintext.as_ptr() as *mut u8,
        };
        let mut entropy = CRYPT_INTEGER_BLOB {
            cbData: ENTROPY.len() as u32,
            pbData: ENTROPY.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();

        // Флаги:
        //  0 = CurrentUser (привязка user+device).
        //  CRYPTPROTECT_UI_FORBIDDEN = не показывать UI (нужно для backend).
        const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

        let description: PWSTR = PWSTR::null();
        CryptProtectData(
            &mut input,
            description,
            Some(&mut entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|e| VaultError::System(format!("CryptProtectData: {e}")))?;

        // Скопировать в Vec и освободить системный buffer.
        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        let result = slice.to_vec();
        let _ = LocalFree(Some(HLOCAL(output.pbData as *mut _)));
        Ok(result)
    }
}

/// Снять защиту (только в той же учётной записи на том же устройстве).
pub fn unprotect(blob: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    // SAFETY:
    // - Pointers in CRYPT_INTEGER_BLOB input point to valid slice memory for the duration of the FFI call.
    // - ENTROPY pointer also points to valid static memory.
    // - output.pbData and description are allocated by the OS and we free them with LocalFree.
    // - Plaintext is safely zeroized before freeing.
    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: blob.len() as u32,
            pbData: blob.as_ptr() as *mut u8,
        };
        let mut entropy = CRYPT_INTEGER_BLOB {
            cbData: ENTROPY.len() as u32,
            pbData: ENTROPY.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        let mut description: PWSTR = PWSTR::null();

        const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

        CryptUnprotectData(
            &mut input,
            Some(&mut description as *mut _),
            Some(&mut entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|e| VaultError::System(format!("CryptUnprotectData: {e}")))?;

        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        let result = slice.to_vec();
        // HIGH-02: scrub the system-allocated plaintext buffer before freeing.
        std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
        let _ = LocalFree(Some(HLOCAL(output.pbData as *mut _)));
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
        if let Ok(blob) = protect(secret) {
            assert_ne!(blob.as_slice(), secret); // действительно зашифровано
            let restored = unprotect(&blob).expect("unprotect must succeed when protect succeeded");
            assert_eq!(restored.as_slice(), secret);
        }
    }
}
