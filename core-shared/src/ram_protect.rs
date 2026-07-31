// Внутрипамятийная защита RAM.
//
// Использует Windows API `CryptProtectMemory` для шифрования блоков
// памяти на уровне операционной системы, защищая их от дамперов памяти и стилеров.
// Блоки должны быть кратны 16 байтам.
// На не-Windows платформах и в WASM работает как обычный zeroized буфер.

use zeroize::Zeroize;

#[cfg(windows)]
use windows::Win32::Security::Cryptography::{
    CryptProtectMemory, CryptUnprotectMemory, CRYPTPROTECTMEMORY_SAME_PROCESS,
};

#[derive(Clone)]
pub struct EncryptedMemoryBuffer<const N: usize> {
    data: [u8; N],
    /// L-07: удалось ли реально зашифровать буфер через CryptProtectMemory.
    /// Если нет (API вернул ошибку / не-Windows) — `data` хранит plaintext, и
    /// расшифровывать его в with_decrypted НЕЛЬЗЯ (иначе CryptUnprotectMemory
    /// испортит открытые байты). Флаг синхронизирует protect/unprotect.
    #[cfg_attr(not(windows), allow(dead_code))]
    protected: bool,
}

impl<const N: usize> EncryptedMemoryBuffer<N> {
    /// Создать защищенный буфер из переданных открытых байтов.
    /// Исходный plaintext зачищается.
    pub fn new(mut plaintext: [u8; N]) -> Self {
        assert_eq!(N % 16, 0, "Buffer size must be a multiple of 16 bytes for CryptProtectMemory");
        let mut data = plaintext;
        plaintext.zeroize();

        #[cfg(windows)]
        let protected = unsafe {
            CryptProtectMemory(
                data.as_mut_ptr() as *mut _,
                N as u32,
                CRYPTPROTECTMEMORY_SAME_PROCESS,
            )
            .is_ok()
        };
        #[cfg(not(windows))]
        let protected = false;

        Self { data, protected }
    }

    /// Выполнить замыкание с временным расшифрованным значением в RAM.
    /// По окончании замыкания временный расшифрованный буфер немедленно зачищается.
    pub fn with_decrypted<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8; N]) -> R,
    {
        let mut decrypted = self.data;

        #[cfg(windows)]
        {
            if self.protected {
                unsafe {
                    let _ = CryptUnprotectMemory(
                        decrypted.as_mut_ptr() as *mut _,
                        N as u32,
                        CRYPTPROTECTMEMORY_SAME_PROCESS,
                    );
                }
            }
        }

        let res = f(&decrypted);
        decrypted.zeroize();
        res
    }
}

impl<const N: usize> Zeroize for EncryptedMemoryBuffer<N> {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl<const N: usize> Drop for EncryptedMemoryBuffer<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ram_protect_roundtrip() {
        let key = [0xAAu8; 32];
        let protected = EncryptedMemoryBuffer::new(key);
        protected.with_decrypted(|dec| {
            assert_eq!(dec, &[0xAAu8; 32]);
        });
    }
}
