// Shamir Secret Sharing над GF(2^8) (поле AES, неприводимый многочлен 0x11b).

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::rng;
use crate::error::{CoreError, Result};

/// Одна доля: индекс (1..=255) + Y-значения для каждого байта секрета.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct Share {
    pub x: u8,
    pub y: Vec<u8>,
}

/// Разбить секрет на `n` долей с порогом `threshold`.
pub fn split_secret(secret: &[u8], threshold: u8, n: u8) -> Result<Vec<Share>> {
    // AUDIT L2: threshold < 2 — foot-gun: при threshold=1 каждая доля РАВНА
    // секрету (цикл коэффициентов пуст), т.е. любая одна доля раскрывает master.
    // Запрещаем на границе API. (Целостность реконструкции проверяется отдельно
    // в recovery через records_key_opens — H5.)
    if threshold < 2 || n == 0 {
        return Err(CoreError::Crypto("shamir: threshold must be >= 2, n > 0".into()));
    }
    if threshold > n {
        return Err(CoreError::Crypto("shamir: threshold > n".into()));
    }
    if secret.is_empty() {
        return Err(CoreError::Crypto("shamir: empty secret".into()));
    }
    if n > 254 {
        return Err(CoreError::Crypto("shamir: n > 254".into()));
    }

    let mut shares: Vec<Share> = (1..=n)
        .map(|i| Share {
            x: i,
            y: Vec::with_capacity(secret.len()),
        })
        .collect();

    for &byte in secret {
        let mut coeffs = vec![byte];
        for _ in 1..threshold {
            let r: [u8; 1] = rng::random_array();
            coeffs.push(r[0]);
        }
        for share in shares.iter_mut() {
            let y = eval_poly(&coeffs, share.x);
            share.y.push(y);
        }
        coeffs.zeroize();
    }

    Ok(shares)
}

/// Восстановить секрет из любых >= threshold долей.
pub fn combine_shares(shares: &[Share], threshold: u8) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    if shares.is_empty() {
        return Err(CoreError::Crypto("shamir: no shares".into()));
    }
    if (shares.len() as u8) < threshold {
        return Err(CoreError::Crypto(format!(
            "shamir: need at least {} shares, got {}",
            threshold,
            shares.len()
        )));
    }
    let len = shares[0].y.len();
    if len == 0 {
        return Err(CoreError::Crypto("shamir: empty share".into()));
    }
    for s in shares {
        if s.y.len() != len {
            return Err(CoreError::Crypto("shamir: share length mismatch".into()));
        }
        if s.x == 0 {
            return Err(CoreError::Crypto("shamir: x=0 forbidden".into()));
        }
    }
    let mut xs: Vec<u8> = shares.iter().map(|s| s.x).collect();
    xs.sort_unstable();
    xs.dedup();
    if xs.len() != shares.len() {
        return Err(CoreError::Crypto("shamir: duplicate x".into()));
    }

    let mut out = zeroize::Zeroizing::new(vec![0u8; len]);
    for byte_idx in 0..len {
        let mut points: Vec<(u8, u8)> = shares.iter().map(|s| (s.x, s.y[byte_idx])).collect();
        out[byte_idx] = lagrange_interpolate_at_zero(&points);
        for p in points.iter_mut() {
            *p = (0, 0);
        }
    }
    Ok(out)
}

fn eval_poly(coeffs: &[u8], x: u8) -> u8 {
    let mut acc: u8 = 0;
    for &c in coeffs.iter().rev() {
        acc = gf_add(gf_mul(acc, x), c);
    }
    acc
}

fn lagrange_interpolate_at_zero(points: &[(u8, u8)]) -> u8 {
    let mut result: u8 = 0;
    for (i, &(xi, yi)) in points.iter().enumerate() {
        let mut num: u8 = 1;
        let mut den: u8 = 1;
        for (j, &(xj, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            num = gf_mul(num, xj);
            den = gf_mul(den, gf_add(xi, xj));
        }
        let li0 = gf_mul(num, gf_inv(den));
        result = gf_add(result, gf_mul(yi, li0));
    }
    result
}

#[inline]
fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

#[inline]
fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let log_a = LOG_TABLE[a as usize] as u16;
    let log_b = LOG_TABLE[b as usize] as u16;
    EXP_TABLE[((log_a + log_b) % 255) as usize]
}

#[inline]
fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        debug_assert!(false, "gf_inv(0) should never be called");
        return 0;
    }
    let log_a = LOG_TABLE[a as usize] as u16;
    EXP_TABLE[((255 - log_a) % 255) as usize]
}

static LOG_TABLE: once_cell::sync::Lazy<[u8; 256]> = once_cell::sync::Lazy::new(|| {
    let mut log = [0u8; 256];
    let exp = &*EXP_TABLE;
    for i in 1..255usize {
        log[exp[i] as usize] = i as u8;
    }
    log
});

static EXP_TABLE: once_cell::sync::Lazy<[u8; 256]> = once_cell::sync::Lazy::new(|| {
    let mut exp = [0u8; 256];
    let mut x: u16 = 1;
    for i in 0..255usize {
        exp[i] = x as u8;
        let mut next = x ^ (x << 1);
        if next & 0x100 != 0 {
            next ^= 0x11b;
        }
        x = next & 0xff;
    }
    exp[255] = exp[0];
    exp
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf_basic_identities() {
        assert_eq!(gf_mul(0, 5), 0);
        assert_eq!(gf_mul(5, 0), 0);
        assert_eq!(gf_mul(1, 7), 7);
        assert_eq!(gf_mul(7, 1), 7);
        for a in 1u8..=255u8 {
            let inv = gf_inv(a);
            assert_eq!(gf_mul(a, inv), 1);
        }
    }

    #[test]
    fn split_and_combine_2_of_3_all_pairs() {
        let secret = b"my-32-byte-master-key-aaaaaaaa!!";
        let shares = split_secret(secret, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);

        // All 3 pairs of 2-of-3 must reconstruct the exact secret
        let pairs = [
            (0, 1),
            (0, 2),
            (1, 2),
        ];

        for (i, j) in pairs {
            let recovered = combine_shares(&[shares[i].clone(), shares[j].clone()], 2).unwrap();
            assert_eq!(recovered.as_slice(), secret, "Failed on pair ({i}, {j})");
        }
    }

    #[test]
    fn split_and_combine_3_of_5_all_triplets() {
        let secret = b"32-byte-secret-for-3-of-5-test!!";
        let shares = split_secret(secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        // Test all 10 combinations of 3 shares out of 5
        for i in 0..5 {
            for j in (i + 1)..5 {
                for k in (j + 1)..5 {
                    let subset = vec![shares[i].clone(), shares[j].clone(), shares[k].clone()];
                    let recovered = combine_shares(&subset, 3).unwrap();
                    assert_eq!(recovered.as_slice(), secret, "Failed on triplet ({i}, {j}, {k})");
                }
            }
        }
    }

    #[test]
    fn shamir_insufficient_shares_error() {
        let secret = b"secret-bytes-1234";
        let shares = split_secret(secret, 3, 5).unwrap();
        // 2 shares when threshold is 3 must return error
        let err = combine_shares(&[shares[0].clone(), shares[1].clone()], 3);
        assert!(err.is_err());
    }

    #[test]
    fn shamir_duplicate_x_rejected() {
        let secret = b"secret-bytes-1234";
        let shares = split_secret(secret, 2, 3).unwrap();
        let mut dup_shares = vec![shares[0].clone(), shares[0].clone()];
        dup_shares[1].x = shares[0].x;
        assert!(combine_shares(&dup_shares, 2).is_err());
    }

    #[test]
    fn shamir_invalid_parameters_rejected() {
        let secret = b"valid-secret";
        assert!(split_secret(secret, 1, 3).is_err(), "threshold < 2 must be rejected");
        assert!(split_secret(secret, 4, 3).is_err(), "threshold > n must be rejected");
        assert!(split_secret(secret, 2, 0).is_err(), "n = 0 must be rejected");
        assert!(split_secret(b"", 2, 3).is_err(), "empty secret must be rejected");
    }

    #[test]
    fn shamir_corrupted_shares_fail_or_differ() {
        let secret = b"sensitive-vault-master-key-32b!!";
        let mut shares = split_secret(secret, 2, 3).unwrap();
        // Corrupt one byte of share 0
        shares[0].y[0] ^= 0xFF;
        let recovered = combine_shares(&[shares[0].clone(), shares[1].clone()], 2).unwrap();
        assert_ne!(recovered.as_slice(), secret, "Corrupted share must not recover original secret");
    }
}
