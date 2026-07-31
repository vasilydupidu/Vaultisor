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
//   shamir         — Shamir Secret Sharing 2-of-3 на GF(256).
//   device_secret  — TPM-привязанный 256-bit device secret (KEK через HKDF).
//   pq_kem         — пост-квантовый KEM (ML-KEM-768, FIPS 203).
//   master         — операции с мастер-ключом (генерация, обёртка PIN+DPAPI+DS).

pub use core_shared::aead;
pub use core_shared::kdf;
pub use core_shared::pq_kem;
pub use core_shared::rng;
pub use core_shared::shamir;
pub mod device_secret;
pub mod master;

// Реэкспорты для удобства использования.
pub use aead::{decrypt, encrypt, EncryptedBlob};
pub use kdf::{argon2id_hash, argon2id_verify, hkdf_derive};
pub use master::{generate_master_key, MASTER_KEY_LEN};
pub use shamir::{combine_shares, split_secret, Share};
