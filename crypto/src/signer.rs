// Licensed under the Apache-2.0 license

use crate::{AlgLen, CryptoError};

/// An ECDSA signature
pub struct EcdsaSig {
    pub r: CryptoBuf,
    pub s: CryptoBuf,
}

impl EcdsaSig {
    pub fn default(alg: AlgLen) -> EcdsaSig {
        EcdsaSig {
            r: CryptoBuf::default(alg),
            s: CryptoBuf::default(alg),
        }
    }
}

/// An ECDSA public key
pub struct EcdsaPub {
    pub x: CryptoBuf,
    pub y: CryptoBuf,
}

impl EcdsaPub {
    pub fn default(alg: AlgLen) -> EcdsaPub {
        EcdsaPub {
            x: CryptoBuf::default(alg),
            y: CryptoBuf::default(alg),
        }
    }
}

pub type EcdsaPriv = CryptoBuf;

/// An HMAC Signature
pub type HmacSig = CryptoBuf;

/// An HMAC Key
pub type HmacKey = CryptoBuf;

/// A common base struct that can be used for all digests, signatures, and keys.
#[derive(Debug, PartialEq)]
pub struct CryptoBuf {
    pub(crate) bytes: [u8; Self::MAX_SIZE],
    pub(crate) len: usize,
}

impl CryptoBuf {
    pub const MAX_SIZE: usize = AlgLen::MAX_ALG_LEN_BYTES;

    pub fn new(bytes: &[u8], alg: AlgLen) -> Result<CryptoBuf, CryptoError> {
        if bytes.len() < alg.size() {
            return Err(CryptoError::Size);
        }

        let mut copied_bytes = [0; Self::MAX_SIZE];
        copied_bytes[..alg.size()].copy_from_slice(&bytes[..alg.size()]);
        Ok(CryptoBuf {
            bytes: copied_bytes,
            len: alg.size(),
        })
    }

    pub fn default(alg: AlgLen) -> CryptoBuf {
        CryptoBuf {
            bytes: [0; Self::MAX_SIZE],
            len: alg.size(),
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        false
    }
}

impl AsRef<[u8]> for CryptoBuf {
    fn as_ref(&self) -> &[u8] {
        self.bytes()
    }
}
