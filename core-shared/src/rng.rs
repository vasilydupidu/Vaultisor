// Источник криптоэнтропии.
//
// На Windows OsRng использует BCryptGenRandom, а в Web Assembly
// используется Web Cryptography API (через getrandom с js-фичей).

use rand::RngCore;

/// Заполнить буфер случайными байтами из OS RNG.
pub fn fill(buf: &mut [u8]) {
    rand::rngs::OsRng.fill_bytes(buf);
}

/// Сгенерировать массив фиксированной длины.
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    fill(&mut buf);
    buf
}

/// Сгенерировать Vec<u8> произвольной длины.
pub fn random_vec(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    fill(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_is_not_constant() {
        let a: [u8; 32] = random_array();
        let b: [u8; 32] = random_array();
        assert_ne!(
            a, b,
            "OS RNG не должен возвращать одинаковые значения подряд"
        );
    }

    #[test]
    fn random_fills_full_length() {
        let v = random_vec(64);
        assert_eq!(v.len(), 64);
        assert!(v.iter().any(|&b| b != 0));
    }
}
