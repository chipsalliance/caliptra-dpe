// Licensed under the Apache-2.0 license

use crate::{AlgLen, CryptoError};
use arrayvec::ArrayVec;

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

/// An HMAC Signature
pub type HmacSig = CryptoBuf;

/// A common base struct that can be used for all digests, signatures, and keys.
pub struct CryptoBuf(ArrayVec<u8, { Self::MAX_SIZE }>);

impl CryptoBuf {
    pub const MAX_SIZE: usize = AlgLen::MAX_ALG_LEN_BYTES;

    pub fn new(bytes: &[u8], algs: AlgLen) -> Result<CryptoBuf, CryptoError> {
        let mut vec = ArrayVec::new();
        vec.try_extend_from_slice(bytes)
            .map_err(|_| CryptoError::Size)?;
        unsafe { vec.set_len(algs.size()) };
        Ok(CryptoBuf(vec))
    }

    pub fn default(algs: AlgLen) -> CryptoBuf {
        let mut vec = ArrayVec::new();
        for _ in 0..algs.size() {
            vec.push(0);
        }
        unsafe { vec.set_len(algs.size()) };
        CryptoBuf(vec)
    }

    pub fn bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.len() == 0
    }

    pub fn write_hex_str(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        let src = self.bytes();
        if dest.len() != src.len() * 2 {
            return Err(CryptoError::Size);
        }

        let mut curr_idx = 0;
        const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
        for &b in src {
            let h1 = (b >> 4) as usize;
            let h2 = (b & 0xF) as usize;
            if h1 >= HEX_CHARS.len() || h2 >= HEX_CHARS.len() || curr_idx + 1 >= dest.len() {
                return Err(CryptoError::CryptoLibError);
            }
            dest[curr_idx] = HEX_CHARS[h1];
            dest[curr_idx + 1] = HEX_CHARS[h2];
            curr_idx += 2;
        }

        Ok(())
    }
}
