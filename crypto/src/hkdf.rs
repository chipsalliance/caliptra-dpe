// Licensed under the Apache-2.0 license

use crate::{ecdsa::EcdsaAlgorithm, CryptoError, Digest, SignatureAlgorithm};
use hkdf::Hkdf;
use sha2::{Sha256, Sha384};

#[cfg(feature = "ml-dsa")]
use crate::MldsaAlgorithm;

impl From<hkdf::InvalidLength> for CryptoError {
    fn from(_: hkdf::InvalidLength) -> Self {
        CryptoError::HashError(0)
    }
}

pub fn hkdf_derive_cdi(
    algs: SignatureAlgorithm,
    measurement: &Digest,
    info: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match algs {
        SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
            let hk = Hkdf::<Sha256>::new(Some(info), measurement.bytes());
            let mut cdi = [0u8; EcdsaAlgorithm::Bit256.curve_size()];
            hk.expand(measurement.bytes(), &mut cdi)?;

            Ok(cdi.to_vec())
        }
        SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
            let hk = Hkdf::<Sha384>::new(Some(info), measurement.bytes());
            let mut cdi = [0u8; EcdsaAlgorithm::Bit384.curve_size()];
            hk.expand(measurement.bytes(), &mut cdi)?;

            Ok(cdi.to_vec())
        }
        #[cfg(feature = "ml-dsa")]
        SignatureAlgorithm::MlDsa(MldsaAlgorithm::KL87) => {
            // This block assumes that the size of `xi` is the same as `SHA256`.
            const _: () = assert!(MldsaAlgorithm::KL87.xi_size() == 256 / 8);

            let hk = Hkdf::<Sha256>::new(Some(info), measurement.bytes());
            let mut cdi = [0u8; MldsaAlgorithm::KL87.xi_size()];
            hk.expand(measurement.bytes(), &mut cdi)?;

            Ok(cdi.to_vec())
        }
    }
}

pub fn hkdf_get_priv_key(
    algs: SignatureAlgorithm,
    cdi: &[u8],
    label: &[u8],
    info: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match algs {
        SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
            let hk = Hkdf::<Sha256>::new(Some(info), cdi);
            let mut priv_key = [0u8; EcdsaAlgorithm::Bit256.curve_size()];
            hk.expand(label, &mut priv_key)?;

            Ok(priv_key.into())
        }
        SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
            let hk = Hkdf::<Sha384>::new(Some(info), cdi);
            let mut priv_key = [0u8; EcdsaAlgorithm::Bit384.curve_size()];
            hk.expand(label, &mut priv_key)?;

            Ok(priv_key.into())
        }
        #[cfg(feature = "ml-dsa")]
        SignatureAlgorithm::MlDsa(MldsaAlgorithm::KL87) => {
            let hk = Hkdf::<Sha256>::new(Some(info), cdi);
            let mut priv_key = [0u8; MldsaAlgorithm::KL87.xi_size()];
            hk.expand(label, &mut priv_key)?;

            Ok(priv_key.into())
        }
    }
}
