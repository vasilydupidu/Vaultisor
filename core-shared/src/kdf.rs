// KDF: Argon2id для PIN/passphrase, HKDF-SHA256 для производных ключей.

use argon2::{Algorithm, Argon2, Params, Version};
use once_cell::sync::Lazy;
use sha2::Sha256;
use std::sync::Mutex;
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

/// Дефолтные параметры Argon2id для PIN.
pub const ARGON2_M_COST: u32 = 512 * 1024; // 512 МБ
pub const ARGON2_T_COST: u32 = 6;
/// Четыре дорожки считаются параллельно: на четырёх и более ядрах ввод PIN
/// занимает меньше секунды. Стоимость перебора задают память и число проходов.
pub const ARGON2_P_COST: u32 = 4;
pub const ARGON2_OUT_LEN: usize = 32;

// Argon2 uses a deliberately large memory cost.  Serialize all memory-hard
// operations so an untrusted webview cannot fan out N concurrent 512 MiB
// allocations and exhaust the process or host.
static ARGON2_SINGLE_FLIGHT: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

fn acquire_argon2_slot() -> Result<std::sync::MutexGuard<'static, ()>> {
    ARGON2_SINGLE_FLIGHT
        .lock()
        .map_err(|_| CoreError::Internal("argon2 concurrency guard poisoned".into()))
}

/// Параметры Argon2id, под которыми обёрнут конкретный мастер-ключ.
///
/// Параметры сохранялись в метаданные хранилища, но деривация
/// всегда шла по константам сборки. Любое их изменение в будущем сделало бы
/// существующие хранилища неоткрываемыми. Теперь распаковка использует именно
/// те параметры, под которыми ключ был запечатан.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost: ARGON2_M_COST,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
        }
    }
}

/// Границы параметров, которые принимаются из метаданных хранилища.
///
/// Метаданные могут прийти из недоверенного файла (импорт копии). Без границ
/// `t_cost = u32::MAX` занимал бы глобальный слот Argon2 на годы (все
/// разблокировки висели бы до перезапуска), а `m_cost` в терабайтах завершал
/// бы процесс при выделении памяти. Нижняя граница — стоимость, дешевле которой продукт
/// ничего не запечатывает (тестовые параметры); выше верхней — не бывает.
pub const ARGON2_M_COST_MIN: u32 = 8 * 1024;
pub const ARGON2_M_COST_MAX: u32 = 2 * 1024 * 1024; // 2 ГиБ
pub const ARGON2_T_COST_MAX: u32 = 16;
pub const ARGON2_P_COST_MAX: u32 = 8;

impl Argon2Params {
    /// Параметры, прочитанные из файла. Значения вне допустимого диапазона
    /// отвергаются до какой-либо деривации.
    pub fn from_stored(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Self> {
        let valid = (ARGON2_M_COST_MIN..=ARGON2_M_COST_MAX).contains(&m_cost)
            && (1..=ARGON2_T_COST_MAX).contains(&t_cost)
            && (1..=ARGON2_P_COST_MAX).contains(&p_cost);
        if !valid {
            return Err(CoreError::BadInput(format!(
                "argon2 params out of range: m={m_cost} t={t_cost} p={p_cost}"
            )));
        }
        Ok(Self {
            m_cost,
            t_cost,
            p_cost,
        })
    }

    fn build(&self) -> Result<Params> {
        Params::new(self.m_cost, self.t_cost, self.p_cost, Some(ARGON2_OUT_LEN))
            .map_err(|e| CoreError::Crypto(format!("argon2 params: {e}")))
    }
}

/// Произвести 32-байтовый ключ-шифрования-ключа (KEK) из passphrase + salt
/// с явно заданными параметрами Argon2id.
pub fn argon2id_derive_key_with(
    passphrase: &[u8],
    salt: &[u8],
    params: Argon2Params,
) -> Result<Zeroizing<[u8; 32]>> {
    let _slot = acquire_argon2_slot()?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.build()?);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase, salt, out.as_mut_slice())
        .map_err(|e| CoreError::Crypto(format!("argon2 derive: {e}")))?;
    Ok(out)
}

/// Произвести KEK из passphrase + salt на параметрах текущей сборки.
pub fn argon2id_derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    argon2id_derive_key_with(passphrase, salt, Argon2Params::default())
}

/// HKDF-SHA256 (extract-then-expand) — audited RustCrypto implementation.
pub fn hkdf_derive(
    secret: &[u8],
    salt: &[u8],
    info: &[u8],
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    use hkdf::Hkdf;

    let hk = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut out = vec![0u8; out_len];
    hk.expand(info, &mut out)
        .map_err(|_| CoreError::Crypto("hkdf expand: output too long".into()))?;
    Ok(Zeroizing::new(out))
}

/// Произвести KEK из PIN + device_secret через Argon2id с явными параметрами.
pub fn argon2id_derive_key_v2_with(
    pin: &[u8],
    device_secret: &[u8; 32],
    salt: &[u8],
    params: Argon2Params,
) -> Result<Zeroizing<[u8; 32]>> {
    let mut combined = Zeroizing::new(Vec::with_capacity(pin.len() + 32));
    combined.extend_from_slice(pin);
    combined.extend_from_slice(device_secret);
    argon2id_derive_key_with(&combined, salt, params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_params_are_honoured_and_differ_from_defaults() {
        // Ключ, запечатанный под одними параметрами, обязан открываться
        // именно ими и не совпадать с результатом на других параметрах.
        let weak = Argon2Params {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        };
        let salt = b"0123456789abcdef";
        let a = argon2id_derive_key_with(b"pin", salt, weak).unwrap();
        let b = argon2id_derive_key_with(b"pin", salt, weak).unwrap();
        assert_eq!(a.as_slice(), b.as_slice(), "деривация детерминирована");

        let other = Argon2Params {
            m_cost: 16 * 1024,
            t_cost: 1,
            p_cost: 1,
        };
        let c = argon2id_derive_key_with(b"pin", salt, other).unwrap();
        assert_ne!(
            a.as_slice(),
            c.as_slice(),
            "другие параметры обязаны давать другой ключ"
        );
    }

    /// Параметры из файла вне диапазона отвергаются, а не заменяются: ни
    /// нулей-«умолчаний», ни многочасовой деривации по подложенному заголовку.
    #[test]
    fn stored_params_outside_the_safe_range_are_rejected() {
        let defaults = Argon2Params::default();
        assert_eq!(
            Argon2Params::from_stored(defaults.m_cost, defaults.t_cost, defaults.p_cost).unwrap(),
            defaults
        );
        for (m, t, p) in [
            (0, 0, 0),
            (ARGON2_M_COST_MIN - 1, 1, 1),
            (ARGON2_M_COST_MAX + 1, 1, 1),
            (u32::MAX, 1, 1),
            (ARGON2_M_COST_MIN, 0, 1),
            (ARGON2_M_COST_MIN, ARGON2_T_COST_MAX + 1, 1),
            (ARGON2_M_COST_MIN, u32::MAX, 1),
            (ARGON2_M_COST_MIN, 1, 0),
            (ARGON2_M_COST_MIN, 1, ARGON2_P_COST_MAX + 1),
        ] {
            assert!(
                Argon2Params::from_stored(m, t, p).is_err(),
                "m={m} t={t} p={p} должны быть отвергнуты"
            );
        }
    }

    /// Рабочие параметры сборки обязаны укладываться в принимаемый диапазон,
    /// иначе собственное хранилище не открылось бы.
    #[test]
    fn production_defaults_are_within_the_accepted_range() {
        let d = Argon2Params::default();
        assert!(Argon2Params::from_stored(d.m_cost, d.t_cost, d.p_cost).is_ok());
    }

    #[test]
    fn invalid_params_are_rejected_not_silently_replaced() {
        let broken = Argon2Params {
            m_cost: 1,
            t_cost: 0,
            p_cost: 0,
        };
        assert!(argon2id_derive_key_with(b"pin", b"0123456789abcdef", broken).is_err());
    }

    #[test]
    fn argon2_derive_deterministic_with_same_salt() {
        // Дешёвые параметры: проверяется детерминизм, а не стоимость.
        let params = Argon2Params {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        };
        let salt = b"0123456789abcdef";
        let a = argon2id_derive_key_with(b"pin", salt, params).unwrap();
        let b = argon2id_derive_key_with(b"pin", salt, params).unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn production_defaults_stay_memory_hard() {
        // Защита от случайного ослабления констант при рефакторинге.
        let defaults = Argon2Params::default();
        assert!(
            defaults.m_cost >= 256 * 1024,
            "Argon2 memory cost downgraded"
        );
        assert!(defaults.t_cost >= 3, "Argon2 time cost downgraded");
        assert!(defaults.p_cost >= 1);
    }

    #[test]
    fn hkdf_basic() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let out = hkdf_derive(&ikm, &salt, &info, 42).unwrap();
        let expected = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();
        assert_eq!(*out, expected);
    }
}
