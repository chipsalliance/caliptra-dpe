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

pub mod ecdsa;

#[cfg(feature = "ml-dsa")]
pub mod ml_dsa;

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
pub enum SignDataAlgorithm {
    Sha256,
    Sha384,
    Mu,
}

impl SignDataAlgorithm {
    pub const fn size(&self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Mu => 64,
        }
    }
}

pub trait SignDataType {
    const SIGN_DATA_ALGORITHM: SignDataAlgorithm;

    fn digest_algorithm(&self) -> SignDataAlgorithm {
        Self::SIGN_DATA_ALGORITHM
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
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SignatureAlgorithm {
    Ecdsa(ecdsa::EcdsaAlgorithm),
    #[cfg(feature = "ml-dsa")]
    MlDsa(ml_dsa::MldsaAlgorithm),
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
    MismatchedAlgorithm = 0x9,
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
            | CryptoError::MismatchedAlgorithm
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

impl SignDataType for Sha256 {
    const SIGN_DATA_ALGORITHM: SignDataAlgorithm = SignDataAlgorithm::Sha256;
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Sha384(pub [u8; DigestAlgorithm::Sha384.size()]);

impl DigestType for Sha384 {
    const DIGEST_ALGORITHM: DigestAlgorithm = DigestAlgorithm::Sha384;
}

impl SignDataType for Sha384 {
    const SIGN_DATA_ALGORITHM: SignDataAlgorithm = SignDataAlgorithm::Sha384;
}

pub enum Digest {
    Sha256(Sha256),
    Sha384(Sha384),
}

impl Digest {
    pub fn size(&self) -> usize {
        match self {
            Self::Sha256(dig) => dig.0.len(),
            Self::Sha384(dig) => dig.0.len(),
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Sha256(dig) => dig.0.as_slice(),
            Self::Sha384(dig) => dig.0.as_slice(),
        }
    }
    pub fn write_hex_str(&self, dst: &mut [u8]) -> Result<(), CryptoError> {
        if dst.len() < self.size() * 2 {
            return Err(CryptoError::Size);
        }

        let src = self.as_slice();
        let mut curr_idx = 0;
        const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";
        for &b in src {
            let h1 = (b >> 4) as usize;
            let h2 = (b & 0xF) as usize;
            if h1 >= HEX_CHARS.len() || h2 >= HEX_CHARS.len() || curr_idx + 1 >= dst.len() {
                return Err(CryptoError::CryptoLibError(0));
            }
            dst[curr_idx] = HEX_CHARS[h1];
            dst[curr_idx + 1] = HEX_CHARS[h2];
            curr_idx += 2;
        }
        Ok(())
    }
}

impl From<Sha256> for Digest {
    fn from(digest: Sha256) -> Self {
        Digest::Sha256(digest)
    }
}

impl From<Sha384> for Digest {
    fn from(digest: Sha384) -> Self {
        Digest::Sha384(digest)
    }
}

impl From<[u8; 32]> for Digest {
    fn from(digest: [u8; 32]) -> Self {
        Digest::Sha256(Sha256(digest))
    }
}

impl From<[u8; 48]> for Digest {
    fn from(digest: [u8; 48]) -> Self {
        Digest::Sha384(Sha384(digest))
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Mu(pub [u8; 64]);

impl SignDataType for Mu {
    const SIGN_DATA_ALGORITHM: SignDataAlgorithm = SignDataAlgorithm::Mu;
}

impl From<[u8; 64]> for Mu {
    fn from(mu: [u8; 64]) -> Self {
        Mu(mu)
    }
}

pub enum PrecomputedSignData {
    Digest(Digest),
    Mu(Mu),
}

impl PrecomputedSignData {
    pub fn size(&self) -> usize {
        match self {
            Self::Digest(dig) => dig.size(),
            Self::Mu(mu) => mu.0.len(),
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Digest(dig) => dig.as_slice(),
            Self::Mu(mu) => mu.0.as_slice(),
        }
    }
}

impl From<Digest> for PrecomputedSignData {
    fn from(digest: Digest) -> Self {
        PrecomputedSignData::Digest(digest)
    }
}

impl From<Mu> for PrecomputedSignData {
    fn from(mu: Mu) -> Self {
        PrecomputedSignData::Mu(mu)
    }
}

pub enum SignData<'a> {
    Digest(Digest),
    Mu(Mu),
    Raw(&'a [u8]),
}

impl SignData<'_> {
    pub fn size(&self) -> usize {
        match self {
            Self::Digest(dig) => dig.size(),
            Self::Mu(mu) => mu.0.len(),
            Self::Raw(raw) => raw.len(),
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Digest(dig) => dig.as_slice(),
            Self::Mu(mu) => mu.0.as_slice(),
            Self::Raw(raw) => raw,
        }
    }
}

impl From<Digest> for SignData<'_> {
    fn from(digest: Digest) -> Self {
        SignData::Digest(digest)
    }
}

impl From<Mu> for SignData<'_> {
    fn from(mu: Mu) -> Self {
        SignData::Mu(mu)
    }
}

impl From<PrecomputedSignData> for SignData<'_> {
    fn from(precalc: PrecomputedSignData) -> Self {
        match precalc {
            PrecomputedSignData::Digest(dig) => SignData::Digest(dig),
            PrecomputedSignData::Mu(mu) => SignData::Mu(mu),
        }
    }
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum PubKey {
    Ecdsa(ecdsa::EcdsaPubKey),
    #[cfg(feature = "ml-dsa")]
    MlDsa(ml_dsa::MldsaPublicKey),
}

impl From<ecdsa::EcdsaPubKey> for PubKey {
    fn from(pub_key: ecdsa::EcdsaPubKey) -> Self {
        PubKey::Ecdsa(pub_key)
    }
}

impl From<ecdsa::curve_256::EcdsaPub256> for PubKey {
    fn from(pub_key: ecdsa::curve_256::EcdsaPub256) -> Self {
        PubKey::Ecdsa(pub_key.into())
    }
}

impl From<ecdsa::curve_384::EcdsaPub384> for PubKey {
    fn from(pub_key: ecdsa::curve_384::EcdsaPub384) -> Self {
        PubKey::Ecdsa(pub_key.into())
    }
}

#[cfg(feature = "ml-dsa")]
impl From<ml_dsa::MldsaPublicKey> for PubKey {
    fn from(pub_key: ml_dsa::MldsaPublicKey) -> Self {
        PubKey::MlDsa(pub_key)
    }
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Signature {
    Ecdsa(EcdsaSignature),
    #[cfg(feature = "ml-dsa")]
    MlDsa(ml_dsa::MldsaSignature),
}

impl From<ecdsa::EcdsaSignature> for Signature {
    fn from(sig: ecdsa::EcdsaSignature) -> Self {
        Signature::Ecdsa(sig)
    }
}

impl From<ecdsa::curve_256::EcdsaSignature256> for Signature {
    fn from(sig: ecdsa::curve_256::EcdsaSignature256) -> Self {
        Signature::Ecdsa(sig.into())
    }
}

impl From<ecdsa::curve_384::EcdsaSignature384> for Signature {
    fn from(sig: ecdsa::curve_384::EcdsaSignature384) -> Self {
        Signature::Ecdsa(sig.into())
    }
}

#[cfg(feature = "ml-dsa")]
impl From<ml_dsa::MldsaSignature> for Signature {
    fn from(sig: ml_dsa::MldsaSignature) -> Self {
        Signature::MlDsa(sig)
    }
}

pub trait CryptoSuite: Crypto + SignatureType + DigestType {
    /// Compute the serial number of an ECDSA public key by computing the hash
    /// over the point in uncompressed format.
    ///
    /// This function outputs the serial number as a hex string
    ///
    /// # Arguments
    ///
    /// * `pub_key` - EC public key
    /// * `serial` - Output buffer to write serial number
    fn get_pubkey_serial(
        &mut self,
        pub_key: &PubKey,
        serial: &mut [u8],
    ) -> Result<(), CryptoError> {
        if serial.len() < self.digest_algorithm().size() * 2 {
            return Err(CryptoError::Size);
        }

        let signature_alg = self.signature_algorithm();
        let mut hasher = self.hash_initialize()?;
        match (signature_alg, pub_key) {
            (SignatureAlgorithm::Ecdsa(_), PubKey::Ecdsa(pub_key)) => {
                let (x, y) = pub_key.as_slice();
                hasher.update(&[0x4u8])?;
                hasher.update(x)?;
                hasher.update(y)?;
            }
            #[cfg(feature = "ml-dsa")]
            (SignatureAlgorithm::MlDsa(_), PubKey::MlDsa(pub_key)) => {
                hasher.update(pub_key.as_bytes())?;
            }
            // This can be reached when the "ml-dsa" feature is enabled.
            #[allow(unreachable_patterns)]
            _ => Err(CryptoError::MismatchedAlgorithm)?,
        }

        let digest = hasher.finish()?;
        digest.write_hex_str(serial)
    }
}

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
    /// * `bytes` - Value to be hashed.
    fn hash(&mut self, bytes: &[u8]) -> Result<Digest, CryptoError> {
        let mut hasher = self.hash_initialize()?;
        hasher.update(bytes)?;
        hasher.finish()
    }

    /// Compute the information needed to sign data
    ///
    /// This is pre-hashing for classic signing algorithms, but this allows for computing external
    /// mu for ML-DSA.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw bytes to be signed
    fn precompute_sign_data(&mut self, bytes: &[u8]) -> Result<PrecomputedSignData, CryptoError>;

    /// Initialize a running hash. Returns an object that will be able to complete the rest.
    ///
    /// Used for hashing multiple buffers that may not be in consecutive memory.
    fn hash_initialize(&mut self) -> Result<Self::Hasher<'_>, CryptoError>;

    /// Derive a CDI based on the current base CDI and measurements
    ///
    /// # Arguments
    ///
    /// * `measurement` - A digest of the measurements which should be used for CDI derivation
    /// * `info` - Caller-supplied info string to use in CDI derivation
    fn derive_cdi(&mut self, measurement: &Digest, info: &[u8]) -> Result<Self::Cdi, CryptoError>;

    /// Derive a CDI for an exported private key based on the current base CDI and measurements
    ///
    /// # Arguments
    ///
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
    /// * `cdi` - Caller-supplied private key to use in public key derivation
    /// * `label` - Caller-supplied label to use in asymmetric key derivation
    /// * `info` - Caller-supplied info string to use in asymmetric key derivation
    fn derive_key_pair(
        &mut self,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, PubKey), CryptoError>;

    /// Derives an exported key pair using a cryptographically secure KDF
    ///
    /// # Arguments
    ///
    /// * `exported_handle` - The handle associated with an existing CDI. Created by
    ///   `derive_cdi_exported`
    /// * `label` - Caller-supplied label to use in asymmetric key derivation
    /// * `info` - Caller-supplied info string to use in asymmetric key derivation
    fn derive_key_pair_exported(
        &mut self,
        exported_handle: &ExportedCdiHandle,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, PubKey), CryptoError>;

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
    ) -> Result<(Self::PrivKey, PubKey), CryptoError>;

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
    ) -> Result<(Self::PrivKey, PubKey), CryptoError>;

    /// Sign `digest` with the platform Alias Key
    ///
    /// # Arguments
    ///
    /// * `data` - Data to be signed.
    fn sign_with_alias(&mut self, data: &SignData) -> Result<Signature, CryptoError>;

    /// Sign `digest` with a derived key-pair from the CDI and caller-supplied private key
    ///
    /// # Arguments
    ///
    /// * `data` - Data to be signed.
    /// * `priv_key` - Caller-supplied private key to use in public key derivation
    /// * `pub_key` - The public key corresponding to `priv_key`. An implementation may
    ///    optionally use pub_key to validate any generated signatures.
    fn sign_with_derived(
        &mut self,
        data: &SignData,
        priv_key: &Self::PrivKey,
        pub_key: &PubKey,
    ) -> Result<Signature, CryptoError>;
}
