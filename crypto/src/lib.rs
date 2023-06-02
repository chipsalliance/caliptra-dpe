/*++
Licensed under the Apache-2.0 license.
Abstract:
    Generic trait definition of Cryptographic functions.
--*/
#![cfg_attr(not(any(feature = "openssl", test)), no_std)]

#[cfg(feature = "openssl")]
pub use crate::openssl::*;
pub use signer::*;

#[cfg(feature = "openssl")]
pub mod openssl;

mod signer;
use core::fmt::{Error, Write};

#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(strum_macros::EnumIter))]
pub enum AlgLen {
    Bit256,
    Bit384,
    // NOTE: If a larger length is added, MUST update AlgLen::MAX_ALG_LEN
}

impl AlgLen {
    const MAX_ALG_LEN: Self = Self::Bit384;
    pub(crate) const MAX_ALG_LEN_BYTES: usize = Self::MAX_ALG_LEN.size();
    pub const fn size(self) -> usize {
        match self {
            AlgLen::Bit256 => 256 / 8,
            AlgLen::Bit384 => 384 / 8,
        }
    }
}

#[derive(Debug)]
pub enum CryptoError {
    AbstractionLayer,
    CryptoLibError,
    Size,
    NotImplemented,
}

pub trait Hasher: Sized {
    /// Adds a chunk to the running hash.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Value to add to hash.
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError>;

    /// Finish a running hash operation and return the result.
    ///
    /// Once this function has been called, the object can no longer be used and
    /// a new one must be created to hash more data.
    fn finish(self) -> Result<Digest, CryptoError>;
}

pub type Digest = CryptoBuf;

pub trait Crypto {
    type Cdi;
    type Hasher: Hasher;
    type PrivKey;

    /// Fills the buffer with random values.
    ///
    /// # Arguments
    ///
    /// * `dst` - The buffer to be filled.
    fn rand_bytes(dst: &mut [u8]) -> Result<(), CryptoError>;

    /// Cryptographically hashes the given buffer.
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithm to use.
    /// * `bytes` - Value to be hashed.
    fn hash(algs: AlgLen, bytes: &[u8]) -> Result<Digest, CryptoError> {
        let mut hasher = Self::hash_initialize(algs)?;
        hasher.update(bytes)?;
        hasher.finish()
    }

    /// Compute the serial number of an ECDSA public key by computing the hash
    /// over the point in uncompressed format.
    ///
    /// This function outputs the serial number as a hex string
    ///
    /// # Arguments
    ///
    /// * `algs` - Length of algorithm to use.
    /// * `pub_key` - EC public key
    /// * `serial` - Output buffer to write serial number
    fn get_pubkey_serial(
        algs: AlgLen,
        pub_key: &EcdsaPub,
        serial: &mut [u8],
    ) -> Result<(), CryptoError> {
        if serial.len() < algs.size() * 2 {
            return Err(CryptoError::CryptoLibError);
        }

        let mut hasher = Self::hash_initialize(algs)?;
        hasher.update(&[0x4u8])?;
        hasher.update(pub_key.x.bytes())?;
        hasher.update(pub_key.y.bytes())?;
        let digest = hasher.finish()?;

        let mut w = BufWriter {
            buf: serial,
            offset: 0,
        };
        w.write_hex_str(digest.bytes())
    }

    /// Initialize a running hash. Returns an object that will be able to complete the rest.
    ///
    /// Used for hashing multiple buffers that may not be in consecutive memory.
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithm to use.
    fn hash_initialize(algs: AlgLen) -> Result<Self::Hasher, CryptoError>;

    /// Derive a CDI based on the current base CDI and measurements as well as an optional random seed value.
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `measurement` - A digest of the measurements which should be used for CDI derivation
    /// * `info` - Caller-supplied info string to use in CDI derivation
    /// * `rand_seed` - Caller-supplied optional random seed to use in CDI derivation
    fn derive_cdi(
        algs: AlgLen,
        measurement: &Digest,
        info: &[u8],
        rand_seed: Option<&[u8]>,
    ) -> Result<Self::Cdi, CryptoError>;

    /// Derives a private key using a cryptographically secure KDF
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `cdi` - Caller-supplied private key to use in public key derivation
    /// * `label` - Caller-supplied label to use in asymmetric key derivation
    /// * `info` - Caller-supplied info string to use in asymmetric key derivation
    ///
    fn derive_private_key(
        algs: AlgLen,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<Self::PrivKey, CryptoError>;

    /// Derives and returns an ECDSA public key using the caller-supplied private key
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `priv_key` - Caller-supplied private key to use in public key derivation
    /// Returns a derived public key
    fn derive_ecdsa_pub(algs: AlgLen, priv_key: &Self::PrivKey) -> Result<EcdsaPub, CryptoError>;

    /// Sign `digest` with the platform Alias Key
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `digest` - Digest of data to be signed.
    fn ecdsa_sign_with_alias(algs: AlgLen, digest: &Digest) -> Result<EcdsaSig, CryptoError>;

    /// Sign `digest` with a derived key-pair from the CDI and caller-supplied private key
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `digest` - Digest of data to be signed.
    /// * `priv_key` - Caller-supplied private key to use in public key derivation
    fn ecdsa_sign_with_derived(
        algs: AlgLen,
        digest: &Digest,
        priv_key: &Self::PrivKey,
    ) -> Result<EcdsaSig, CryptoError>;

    /// Compute the serial number string for the alias public key
    ///
    /// # Arguments
    ///
    /// * `algs` - Length of algorithm to use.
    /// * `serial` - Output buffer to write serial number
    fn get_ecdsa_alias_serial(algs: AlgLen, serial: &mut [u8]) -> Result<(), CryptoError>;

    /// Sign `digest` with a derived HMAC key from the CDI.
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `cdi` - CDI from which to derive the signing key
    /// * `label` - Caller-supplied label to use in symmetric key derivation
    /// * `info` - Caller-supplied info string to use in symmetric key derivation
    /// * `digest` - Digest of data to be signed.
    fn hmac_sign_with_derived(
        algs: AlgLen,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
        digest: &Digest,
    ) -> Result<HmacSig, CryptoError>;
}

/// Writer for a static buffer
struct BufWriter<'a> {
    buf: &'a mut [u8],
    offset: usize,
}

impl Write for BufWriter<'_> {
    fn write_str(&mut self, s: &str) -> Result<(), Error> {
        if s.len() > self.buf.len().saturating_sub(self.offset) {
            return Err(Error::default());
        }

        self.buf[self.offset..self.offset + s.len()].copy_from_slice(s.as_bytes());
        self.offset += s.len();

        Ok(())
    }
}

impl BufWriter<'_> {
    fn write_hex_str(&mut self, src: &[u8]) -> Result<(), CryptoError> {
        for &b in src {
            write!(self, "{b:02x}").map_err(|_| CryptoError::CryptoLibError)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    #[test]
    fn test_max_alg_len_size() {
        let max_len = AlgLen::iter().map(|x| x.size()).max().unwrap();
        assert_eq!(AlgLen::MAX_ALG_LEN_BYTES, max_len);
    }
}
