// Пост-квантовый KEM: ML-KEM-768 (FIPS 203).

use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

/// Сгенерировать пару ключей ML-KEM-768.
pub fn keygen() -> (Vec<u8>, Vec<u8>) {
    let (dk, ek) = MlKem768::generate(&mut OsRng);
    let ek_bytes = ek.as_bytes().to_vec();
    let dk_bytes = dk.as_bytes().to_vec();
    (ek_bytes, dk_bytes)
}

/// Инкапсулировать общий секрет с помощью публичного ek.
pub fn encapsulate(ek_bytes: &[u8]) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>)> {
    let ek_encoded = ml_kem::Encoded::<
        ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>,
    >::try_from(ek_bytes)
    .map_err(|_| CoreError::Crypto("ml-kem: invalid encapsulation key length".into()))?;
    let ek = ml_kem::kem::EncapsulationKey::<ml_kem::MlKem768Params>::from_bytes(&ek_encoded);

    let (ct, shared) = ek
        .encapsulate(&mut OsRng)
        .map_err(|_| CoreError::Crypto("ml-kem: encapsulation failed".into()))?;

    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(shared.as_slice());

    let ct_bytes = ct.to_vec();
    Ok((secret, ct_bytes))
}

/// Декапсулировать общий секрет с помощью секретного dk и ciphertext.
pub fn decapsulate(dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let dk_encoded = ml_kem::Encoded::<
        ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>,
    >::try_from(dk_bytes)
    .map_err(|_| CoreError::Crypto("ml-kem: invalid decapsulation key length".into()))?;
    let dk = ml_kem::kem::DecapsulationKey::<ml_kem::MlKem768Params>::from_bytes(&dk_encoded);

    let ct = ml_kem::Ciphertext::<MlKem768>::try_from(ct_bytes)
        .map_err(|_| CoreError::Crypto("ml-kem: invalid ciphertext length".into()))?;

    let shared = dk
        .decapsulate(&ct)
        .map_err(|_| CoreError::Crypto("ml-kem: decapsulation failed".into()))?;

    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(shared.as_slice());
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_produces_non_empty_keys() {
        let (ek, dk) = keygen();
        assert!(!ek.is_empty());
        assert!(!dk.is_empty());
        assert_eq!(ek.len(), 1184);
        assert_eq!(dk.len(), 2400);
    }

    #[test]
    fn encapsulate_decapsulate_roundtrip() {
        let (ek, dk) = keygen();
        let (secret_enc, ct) = encapsulate(&ek).unwrap();
        let secret_dec = decapsulate(&dk, &ct).unwrap();
        assert_eq!(secret_enc.as_slice(), secret_dec.as_slice());
    }
}
