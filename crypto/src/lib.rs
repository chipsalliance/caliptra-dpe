/*++
Licensed under the Apache-2.0 license.
Abstract:
    Generic trait definition of Cryptographic functions.
--*/
#![cfg_attr(not(any(feature = "rustcrypto", test)), no_std)]

use ecdsa::EcdsaSignature;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[cfg(feature = "rustcrypto")]
pub use crate::rustcrypto::*;

#[cfg(feature = "rustcrypto")]
pub mod rustcrypto;

#[cfg(feature = "deterministic_rand")]
pub use rand::*;

#[cfg(feature = "rustcrypto")]
mod hkdf;

// TODO(clundin): Put this behind a feature flag?
pub mod ecdsa;

pub const MAX_EXPORTED_CDI_SIZE: usize = 32;
pub type ExportedCdiHandle = [u8; MAX_EXPORTED_CDI_SIZE];

pub trait SignatureType {
    const SIGNATURE_ALGORITHM: SignatureAlgorithm;

    fn signature_algorithm(&self) -> SignatureAlgorithm {
        Self::SIGNATURE_ALGORITHM
    }
}

pub trait DigestType {
    const DIGEST_ALGORITHM: DigestAlgorithm;

    fn digest_algorithm(&self) -> DigestAlgorithm {
        Self::DIGEST_ALGORITHM
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg(feature = "ml-dsa")]
pub enum MldsaAlgorithm {
    KL87,
}

#[cfg(all(test, feature = "ml-dsa"))]
impl Default for MldsaAlgorithm {
    fn default() -> Self {
        Self::KL87
    }
}

#[cfg(feature = "ml-dsa")]
impl MldsaAlgorithm {
    const fn xi_size(self) -> usize {
        match self {
            MldsaAlgorithm::KL87 => 32,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
}

impl DigestAlgorithm {
    pub const fn size(&self) -> usize {
        match self {
            DigestAlgorithm::Sha256 => 32,
            DigestAlgorithm::Sha384 => 48,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SignatureAlgorithm {
    Ecdsa(ecdsa::EcdsaAlgorithm),
    #[cfg(feature = "ml-dsa")]
    MlDsa(MldsaAlgorithm),
}

impl SignatureAlgorithm {
    pub const fn signature_size(self) -> usize {
        match self {
            SignatureAlgorithm::Ecdsa(ec) => ec.curve_size() * 2,
            #[cfg(feature = "ml-dsa")]
            SignatureAlgorithm::MlDsa(MldsaAlgorithm::KL87) => 4627,
        }
    }
    pub const fn public_key_size(self) -> usize {
        match self {
            SignatureAlgorithm::Ecdsa(ec) => ec.curve_size(),
            #[cfg(feature = "ml-dsa")]
            SignatureAlgorithm::MlDsa(MldsaAlgorithm::KL87) => 2592,
        }
    }
    pub const fn private_key_size(self) -> usize {
        match self {
            SignatureAlgorithm::Ecdsa(ec) => ec.curve_size(),
            #[cfg(feature = "ml-dsa")]
            SignatureAlgorithm::MlDsa(MldsaAlgorithm::KL87) => 4896,
        }
    }
}

// For errors which come from lower layers, include the error code returned
// from platform libraries.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
pub enum CryptoError {
    AbstractionLayer(u32) = 0x1,
    CryptoLibError(u32) = 0x2,
    Size = 0x3,
    NotImplemented = 0x4,
    HashError(u32) = 0x5,
    InvalidExportedCdiHandle = 0x6,
    ExportedCdiHandleDuplicateCdi = 0x7,
    ExportedCdiHandleLimitExceeded = 0x8,
}

impl CryptoError {
    pub fn discriminant(&self) -> u16 {
        // SAFETY: Because `Self` is marked `repr(u16)`, its layout is a `repr(C)` `union`
        // between `repr(C)` structs, each of which has the `u16` discriminant as its first
        // field, so we can read the discriminant without offsetting the pointer.
        unsafe { *<*const _>::from(self).cast::<u16>() }
    }

    pub fn get_error_detail(&self) -> Option<u32> {
        match self {
            CryptoError::AbstractionLayer(code)
            | CryptoError::CryptoLibError(code)
            | CryptoError::HashError(code) => Some(*code),
            CryptoError::Size
            | CryptoError::InvalidExportedCdiHandle
            | CryptoError::ExportedCdiHandleLimitExceeded
            | CryptoError::ExportedCdiHandleDuplicateCdi
            | CryptoError::NotImplemented => None,
        }
    }
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

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Sha256(pub [u8; DigestAlgorithm::Sha256.size()]);

impl DigestType for Sha256 {
    const DIGEST_ALGORITHM: DigestAlgorithm = DigestAlgorithm::Sha256;
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Sha384(pub [u8; DigestAlgorithm::Sha384.size()]);

impl DigestType for Sha384 {
    const DIGEST_ALGORITHM: DigestAlgorithm = DigestAlgorithm::Sha384;
}

pub enum Digest {
    Sha256(Sha256),
    Sha384(Sha384),
    // TODO(clundin): Add a variant for External Mu
    //ExternalMu(),
}

impl Digest {
    pub fn size(&self) -> usize {
        match self {
            Digest::Sha256(dig) => dig.0.len(),
            Digest::Sha384(dig) => dig.0.len(),
        }
    }
    pub fn bytes(&self) -> &[u8] {
        match self {
            Digest::Sha256(dig) => dig.0.as_slice(),
            Digest::Sha384(dig) => dig.0.as_slice(),
        }
    }
}

#[derive(Clone)]
pub enum ExportedPubKey {
    Ecdsa(ecdsa::EcdsaPubKey),
}

pub enum Signature {
    Ecdsa(EcdsaSignature),
}

pub trait CryptoEngine: Crypto + SignatureType + DigestType {}

pub trait Crypto {
    type Cdi;
    type Hasher<'c>: Hasher
    where
        Self: 'c;
    type PrivKey;
    type PubKey;

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
    fn hash(&mut self, bytes: &[u8]) -> Result<Digest, CryptoError> {
        let mut hasher = self.hash_initialize()?;
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
        pub_key: &ExportedPubKey,
        serial: &mut [u8],
    ) -> Result<(), CryptoError>;

    /// Initialize a running hash. Returns an object that will be able to complete the rest.
    ///
    /// Used for hashing multiple buffers that may not be in consecutive memory.
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithm to use.
    fn hash_initialize(&mut self) -> Result<Self::Hasher<'_>, CryptoError>;

    /// Derive a CDI based on the current base CDI and measurements
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `measurement` - A digest of the measurements which should be used for CDI derivation
    /// * `info` - Caller-supplied info string to use in CDI derivation
    fn derive_cdi(&mut self, measurement: &Digest, info: &[u8]) -> Result<Self::Cdi, CryptoError>;

    /// Derive a CDI for an exported private key based on the current base CDI and measurements
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `measurement` - A digest of the measurements which should be used for CDI derivation
    /// * `info` - Caller-supplied info string to use in CDI derivation
    fn derive_exported_cdi(
        &mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<ExportedCdiHandle, CryptoError>;

    /// CFI wrapper around derive_cdi
    ///
    /// To implement this function, you need to add the
    /// cfi_impl_fn proc_macro to derive_cdi.
    #[cfg(not(feature = "no-cfi"))]
    fn __cfi_derive_cdi(
        &mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<Self::Cdi, CryptoError>;

    /// CFI wrapper around derive_cdi_exported
    ///
    /// To implement this function, you need to add the
    /// cfi_impl_fn proc_macro to derive_exported_cdi.
    #[cfg(not(feature = "no-cfi"))]
    fn __cfi_derive_exported_cdi(
        &mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<ExportedCdiHandle, CryptoError>;

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
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, Self::PubKey), CryptoError>;

    /// Derives an exported key pair using a cryptographically secure KDF
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `exported_handle` - The handle associated with an existing CDI. Created by
    ///   `derive_cdi_exported`
    /// * `label` - Caller-supplied label to use in asymmetric key derivation
    /// * `info` - Caller-supplied info string to use in asymmetric key derivation
    ///
    fn derive_key_pair_exported(
        &mut self,
        exported_handle: &ExportedCdiHandle,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, Self::PubKey), CryptoError>;

    /// CFI wrapper around derive_key_pair
    ///
    /// To implement this function, you need to add the
    /// cfi_impl_fn proc_macro to derive_key_pair.
    #[cfg(not(feature = "no-cfi"))]
    fn __cfi_derive_key_pair(
        &mut self,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, Self::PubKey), CryptoError>;

    /// CFI wrapper around derive_key_pair_exported
    ///
    /// To implement this function, you need to add the
    /// cfi_impl_fn proc_macro to derive_key_pair.
    #[cfg(not(feature = "no-cfi"))]
    fn __cfi_derive_key_pair_exported(
        &mut self,
        exported_handle: &ExportedCdiHandle,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, Self::PubKey), CryptoError>;

    /// Sign `digest` with the platform Alias Key
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `digest` - Digest of data to be signed.
    fn sign_with_alias(&mut self, digest: &Digest) -> Result<Signature, CryptoError>;

    /// Sign `digest` with a derived key-pair from the CDI and caller-supplied private key
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `digest` - Digest of data to be signed.
    /// * `priv_key` - Caller-supplied private key to use in public key derivation
    /// * `pub_key` - The public key corresponding to `priv_key`. An implementation may
    ///    optionally use pub_key to validate any generated signatures.
    fn sign_with_derived(
        &mut self,
        digest: &Digest,
        priv_key: &Self::PrivKey,
        pub_key: &Self::PubKey,
    ) -> Result<Signature, CryptoError>;

    /// Converts the internel `PubKey` into a `ExportedPubKey`.
    ///
    /// # Arguments
    ///
    /// * `pub_key` - The public key previously created in a derivation.
    fn export_public_key(&self, pub_key: &Self::PubKey) -> Result<ExportedPubKey, CryptoError>;
}
