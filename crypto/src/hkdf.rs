// Licensed under the Apache-2.0 license

use crate::{AlgLen, CryptoBuf, CryptoError, Digest};
use hkdf::Hkdf;
use sha2::{Sha256, Sha384};

impl From<hkdf::InvalidLength> for CryptoError {
    fn from(_: hkdf::InvalidLength) -> Self {
        CryptoError::HashError(0)
    }
}

pub fn hkdf_derive_cdi(
    algs: AlgLen,
    measurement: &Digest,
    info: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match algs {
        AlgLen::Bit256 => {
            let hk = Hkdf::<Sha256>::new(Some(info), measurement.bytes());
            let mut cdi = [0u8; AlgLen::Bit256.size()];
            hk.expand(measurement.bytes(), &mut cdi)?;

            Ok(cdi.to_vec())
        }
        AlgLen::Bit384 => {
            let hk = Hkdf::<Sha384>::new(Some(info), measurement.bytes());
            let mut cdi = [0u8; AlgLen::Bit384.size()];
            hk.expand(measurement.bytes(), &mut cdi)?;

            Ok(cdi.to_vec())
        }
    }
}

pub fn hkdf_get_priv_key(
    algs: AlgLen,
    cdi: &[u8],
    label: &[u8],
    info: &[u8],
) -> Result<CryptoBuf, CryptoError> {
    match algs {
        AlgLen::Bit256 => {
            let hk = Hkdf::<Sha256>::new(Some(info), cdi);
            let mut priv_key = [0u8; AlgLen::Bit256.size()];
            hk.expand(label, &mut priv_key)?;

            Ok(CryptoBuf::new(&priv_key).unwrap())
        }
        AlgLen::Bit384 => {
            let hk = Hkdf::<Sha384>::new(Some(info), cdi);
            let mut priv_key = [0u8; AlgLen::Bit384.size()];
            hk.expand(label, &mut priv_key)?;

            Ok(CryptoBuf::new(&priv_key).unwrap())
        }
    }
}
