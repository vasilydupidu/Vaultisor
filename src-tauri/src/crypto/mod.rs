// Криптографическое ядро Vaultisor.
//
// Принципы:
//  - Все примитивы поверх отлаженных реализаций RustCrypto.
//  - Никакой ручной реализации AES/SHA — только проверенные крейты.
//  - Свой код только там, где либо нет зрелого крейта (Shamir GF(256)),
//    либо нужен очень тонкий wrapper (RNG, нормализация ошибок).
//  - Все секретные буферы зачищаются Zeroize.
//
// Слои (от низа к верху):
//   rng            — единый источник энтропии (OsRng + ChaCha20Rng resp).
//   aead           — AES-256-GCM шифрование/дешифрование.
//   kdf            — Argon2id для PIN, HKDF для derived keys.
//   shamir         — Shamir Secret Sharing на GF(256) (части B и C).
//   device_secret  — TPM-привязанный 256-bit device secret (KEK через HKDF).
//   master         — операции с мастер-ключом (генерация, обёртка PIN+DPAPI+DS).

pub use core_shared::aead;
pub use core_shared::kdf;
pub use core_shared::rng;
pub use core_shared::shamir;
pub mod device_secret;
pub mod fido;
pub mod master;

// Реэкспорты для удобства использования.
pub use aead::{decrypt, encrypt, EncryptedBlob};
pub use kdf::{hkdf_derive, Argon2Params};
pub use master::{generate_master_key, MASTER_KEY_LEN};
pub use shamir::{combine_shares, split_secret, Share};

/// Параметры Argon2id для новых обёрток мастер-ключа и защищённых бэкапов.
///
/// Рабочие значения (512 МиБ, t=6) делают одну деривацию многосекундной. Тесты
/// сценариев прогоняют создание, смену PIN и восстановление сотни раз — с
/// каждым отказом на каждом шаге, — поэтому в тестовой сборке стоимость
/// снижена. Криптографическая логика от стоимости не зависит, а сами рабочие
/// значения закреплены тестом `production_defaults_stay_memory_hard`.
pub fn new_wrap_params() -> Argon2Params {
    #[cfg(test)]
    {
        Argon2Params {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }
    #[cfg(not(test))]
    {
        Argon2Params::default()
    }
}
