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
    /// Удалось ли реально зашифровать буфер через CryptProtectMemory.
    /// Если нет (API вернул ошибку / не-Windows) — `data` хранит plaintext, и
    /// расшифровывать его в with_decrypted НЕЛЬЗЯ (иначе CryptUnprotectMemory
    /// испортит открытые байты). Флаг синхронизирует protect/unprotect.
    #[cfg_attr(not(windows), allow(dead_code))]
    protected: bool,
}

impl<const N: usize> EncryptedMemoryBuffer<N> {
    /// Создать защищенный буфер из переданных открытых байтов.
    ///
    /// Массив передаётся по изменяемой ссылке, а не по значению: `[u8; N]` —
    /// `Copy`, и передача по значению оставляла бы на стеке вызывающего
    /// незатертую копию. Здесь байты копируются в буфер, а массив вызывающего
    /// зачищается.
    ///
    /// Если `CryptProtectMemory` вернул ошибку (или платформа не Windows),
    /// буфер продолжает хранить ключ открытым текстом. Это не скрывается:
    /// состояние видно через [`Self::is_protected`], и вызывающий код обязан
    /// его проверить и сообщить.
    pub fn new(plaintext: &mut [u8; N]) -> Self {
        assert_eq!(
            N % 16,
            0,
            "Buffer size must be a multiple of 16 bytes for CryptProtectMemory"
        );
        #[cfg_attr(not(windows), allow(unused_mut))]
        let mut buf = Self {
            data: *plaintext,
            protected: false,
        };
        plaintext.zeroize();

        #[cfg(windows)]
        {
            buf.protected = unsafe {
                CryptProtectMemory(
                    buf.data.as_mut_ptr() as *mut _,
                    N as u32,
                    CRYPTPROTECTMEMORY_SAME_PROCESS,
                )
                .is_ok()
            };
        }

        buf
    }

    /// Зашифрован ли буфер средствами ОС. `false` — ключ лежит в памяти
    /// открытым текстом (ошибка `CryptProtectMemory` либо не-Windows).
    pub fn is_protected(&self) -> bool {
        self.protected
    }

    /// Выполнить замыкание с временным расшифрованным значением в RAM.
    /// По окончании замыкания временный расшифрованный буфер немедленно зачищается.
    /// Если расшифровка CryptUnprotectMemory завершилась с ошибкой, буфер зачищается,
    /// а функция аварийно завершает работу, предотвращая исполнение над шифротекстом.
    pub fn with_decrypted<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8; N]) -> R,
    {
        let mut decrypted = self.data;

        #[cfg(windows)]
        {
            if self.protected {
                let status = unsafe {
                    CryptUnprotectMemory(
                        decrypted.as_mut_ptr() as *mut _,
                        N as u32,
                        CRYPTPROTECTMEMORY_SAME_PROCESS,
                    )
                };
                if let Err(e) = status {
                    decrypted.zeroize();
                    panic!("CryptUnprotectMemory failed: {e:?}");
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
        let mut key = [0xAAu8; 32];
        let protected = EncryptedMemoryBuffer::new(&mut key);
        protected.with_decrypted(|dec| {
            assert_eq!(dec, &[0xAAu8; 32]);
        });
    }

    /// Массив вызывающего зачищается: незатертой копии ключа на его стеке нет.
    #[test]
    fn constructor_wipes_the_callers_array() {
        let mut key = [0x5Cu8; 32];
        let _buf = EncryptedMemoryBuffer::new(&mut key);
        assert_eq!(key, [0u8; 32]);
    }

    /// На Windows защита должна реально включаться, и в этом случае в буфере
    /// лежит не открытый текст.
    #[cfg(windows)]
    #[test]
    fn windows_buffer_is_protected_and_not_plaintext() {
        let mut key = [0x77u8; 32];
        let buf = EncryptedMemoryBuffer::new(&mut key);
        assert!(buf.is_protected());
        assert_ne!(buf.data, [0x77u8; 32], "в буфере остался открытый текст");
        buf.with_decrypted(|dec| assert_eq!(dec, &[0x77u8; 32]));
    }

    /// Без защиты ОС флаг честно сообщает об открытом хранении.
    #[cfg(not(windows))]
    #[test]
    fn non_windows_buffer_reports_unprotected() {
        let mut key = [0x77u8; 32];
        let buf = EncryptedMemoryBuffer::new(&mut key);
        assert!(!buf.is_protected());
    }
}
