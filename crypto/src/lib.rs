/*++
Licensed under the Apache-2.0 license.
Abstract:
    Generic trait definition of Cryptographic functions.
--*/

#[cfg(feature = "openssl")]
pub use crate::openssl::*;

#[cfg(feature = "openssl")]
pub mod openssl;

#[derive(Debug, Clone, Copy)]
pub enum AlgLen {
    Bit256,
    Bit384,
}

impl AlgLen {
    pub const fn size(self) -> usize {
        match self {
            AlgLen::Bit256 => 256 / 8,
            AlgLen::Bit384 => 384 / 8,
        }
    }
}

pub enum CryptoError {
    AbstractionLayer,
    CryptoLibError,
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
    ///
    /// # Arguments
    ///
    /// * `digest` - Where the computed digest should be written.
    fn finish(self, digest: &mut [u8]) -> Result<(), CryptoError>;
}

pub trait Crypto {
    type Cdi;
    type Hasher: Hasher;

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
    /// * `digest` - Where the computed digest should be written.
    fn hash(algs: AlgLen, bytes: &[u8], digest: &mut [u8]) -> Result<(), CryptoError> {
        let mut hasher = Self::hash_initialize(algs)?;
        hasher.update(bytes)?;
        hasher.finish(digest)
    }

    /// Initialize a running hash. Returns an object that will be able to complete the rest.
    ///
    /// Used for hashing multiple buffers that may not be in consecutive memory.
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithm to use.
    fn hash_initialize(algs: AlgLen) -> Result<Self::Hasher, CryptoError>;

    /// Derive a CDI based on the current base CDI and measurements.
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `measurement_digest` - A digest of the measurements which should be
    ///   used for CDI derivation
    /// * `info` - Caller-supplied info string to use in CDI derivation
    fn derive_cdi(
        algs: AlgLen,
        measurement_digest: &[u8],
        info: &[u8],
    ) -> Result<Self::Cdi, CryptoError>;

    /// Derives an ECDSA keypair from `cdi` and returns the public key
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `cdi` - CDI from which to derive the signing key
    /// * `label` - Caller-supplied label to use in asymmetric key derivation
    /// * `info` - Caller-supplied info string to use in asymmetric key derivation
    /// * `pub_x` - Destination for public key's X component.
    /// * `pub_y` - Destination for public key's Y component.
    ///
    /// Returns a derived public key
    fn derive_ecdsa_pub(
        algs: AlgLen,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
        pub_x: &mut [u8],
        pub_y: &mut [u8],
    ) -> Result<(), CryptoError>;

    /// Sign `digest` with the platform Alias Key
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `digest` - Digest of data to be signed.
    /// * `sig_r` - Destination for signature's R component.
    /// * `sig_s` - Destination for signature's S component.
    fn ecdsa_sign_with_alias(
        algs: AlgLen,
        digest: &[u8],
        sig_r: &mut [u8],
        sig_s: &mut [u8],
    ) -> Result<(), CryptoError>;
}
