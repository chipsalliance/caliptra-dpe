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
    HashError,
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
    type Hasher<'c>: Hasher
    where
        Self: 'c;
    type PrivKey;

    /// Fills the buffer with random values.
    ///
    /// # Arguments
    ///
    /// * `dst` - The buffer to be filled.
    fn rand_bytes(&mut self, dst: &mut [u8]) -> Result<(), CryptoError>;

    /// Cryptographically hashes the given buffer.
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithm to use.
    /// * `bytes` - Value to be hashed.
    fn hash(&mut self, algs: AlgLen, bytes: &[u8]) -> Result<Digest, CryptoError> {
        let mut hasher = self.hash_initialize(algs)?;
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
        &mut self,
        algs: AlgLen,
        pub_key: &EcdsaPub,
        serial: &mut [u8],
    ) -> Result<(), CryptoError> {
        if serial.len() < algs.size() * 2 {
            return Err(CryptoError::Size);
        }

        let mut hasher = self.hash_initialize(algs)?;
        hasher.update(&[0x4u8])?;
        hasher.update(pub_key.x.bytes())?;
        hasher.update(pub_key.y.bytes())?;
        let digest = hasher.finish()?;

        CryptoBuf::write_hex_str(&digest, serial)
    }

    /// Initialize a running hash. Returns an object that will be able to complete the rest.
    ///
    /// Used for hashing multiple buffers that may not be in consecutive memory.
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithm to use.
    fn hash_initialize(&mut self, algs: AlgLen) -> Result<Self::Hasher<'_>, CryptoError>;

    /// Derive a CDI based on the current base CDI and measurements
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `measurement` - A digest of the measurements which should be used for CDI derivation
    /// * `info` - Caller-supplied info string to use in CDI derivation
    fn derive_cdi(
        &mut self,
        algs: AlgLen,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<Self::Cdi, CryptoError>;

    /// Derives a key pair using a cryptographically secure KDF
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `cdi` - Caller-supplied private key to use in public key derivation
    /// * `label` - Caller-supplied label to use in asymmetric key derivation
    /// * `info` - Caller-supplied info string to use in asymmetric key derivation
    ///
    fn derive_key_pair(
        &mut self,
        algs: AlgLen,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, EcdsaPub), CryptoError>;

    /// Sign `digest` with the platform Alias Key
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `digest` - Digest of data to be signed.
    fn ecdsa_sign_with_alias(
        &mut self,
        algs: AlgLen,
        digest: &Digest,
    ) -> Result<EcdsaSig, CryptoError>;

    /// Sign `digest` with a derived key-pair from the CDI and caller-supplied private key
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `digest` - Digest of data to be signed.
    /// * `priv_key` - Caller-supplied private key to use in public key derivation
    /// * `pub_key` - The public key corresponding to `priv_key`. An implementation may
    ///    optionally use pub_key to validate any generated signatures.
    fn ecdsa_sign_with_derived(
        &mut self,
        algs: AlgLen,
        digest: &Digest,
        priv_key: &Self::PrivKey,
        pub_key: EcdsaPub,
    ) -> Result<EcdsaSig, CryptoError>;

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
        &mut self,
        algs: AlgLen,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
        digest: &Digest,
    ) -> Result<HmacSig, CryptoError>;
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
