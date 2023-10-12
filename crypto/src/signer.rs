// Licensed under the Apache-2.0 license

use crate::{AlgLen, CryptoError};
use arrayvec::ArrayVec;

/// An ECDSA signature
pub struct EcdsaSig {
    pub r: CryptoBuf,
    pub s: CryptoBuf,
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
#[derive(Debug, PartialEq, Eq)]
pub struct CryptoBuf(ArrayVec<u8, { Self::MAX_SIZE }>);

impl CryptoBuf {
    pub const MAX_SIZE: usize = AlgLen::MAX_ALG_LEN_BYTES;

    pub fn new(bytes: &[u8]) -> Result<CryptoBuf, CryptoError> {
        let mut vec = ArrayVec::new();
        vec.try_extend_from_slice(bytes)
            .map_err(|_| CryptoError::Size)?;
        Ok(CryptoBuf(vec))
    }

    pub fn default(algs: AlgLen) -> CryptoBuf {
        let mut vec = ArrayVec::new();
        for _ in 0..algs.size() {
            vec.push(0);
        }
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
        const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";
        for &b in src {
            let h1 = (b >> 4) as usize;
            let h2 = (b & 0xF) as usize;
            if h1 >= HEX_CHARS.len()
                || h2 >= HEX_CHARS.len()
                || curr_idx >= dest.len()
                || curr_idx + 1 >= dest.len()
            {
                return Err(CryptoError::CryptoLibError);
            }
            dest[curr_idx] = HEX_CHARS[h1];
            dest[curr_idx + 1] = HEX_CHARS[h2];
            curr_idx += 2;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_buf_init() {
        let arr = &[1u8; CryptoBuf::MAX_SIZE + 1];

        // array length must not exceed MAX_SIZE
        assert_eq!(CryptoBuf::new(arr), Err(CryptoError::Size));

        let arr = &[1u8; AlgLen::Bit256.size()];
        // test new
        match CryptoBuf::new(arr) {
            Ok(buf) => {
                assert_eq!(arr, buf.bytes());
                assert_eq!(buf.len(), AlgLen::Bit256.size());
            }
            Err(_) => panic!("CryptoBuf::new failed"),
        };

        // test default
        let default_buf = CryptoBuf::default(AlgLen::Bit384);
        assert_eq!(default_buf.bytes(), [0; AlgLen::Bit384.size()]);
    }
}
