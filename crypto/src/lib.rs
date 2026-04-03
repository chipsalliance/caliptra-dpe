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

#[cfg(feature = "dummy")]
pub mod dummy;

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
    fn signature_algorithm(&self) -> SignatureAlgorithm;
}

pub trait DigestType {
    fn digest_algorithm(&self) -> DigestAlgorithm;
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
    fn sign_data_algorithm(&self) -> SignDataAlgorithm;
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
    Mldsa(ml_dsa::MldsaAlgorithm),
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

pub trait Hasher {
    /// Initialize a running hash operation.
    fn initialize(&mut self) -> Result<(), CryptoError>;

    /// Adds a chunk to the running hash.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Value to add to hash.
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError>;

    /// Finish a running hash operation and return the result.
    ///
    /// Once this function has been called, the object can no longer be used
    /// until it is re-initialized.
    fn finish(&mut self) -> Result<Digest, CryptoError>;
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Clone)]
#[repr(C)]
pub struct Sha256(pub [u8; DigestAlgorithm::Sha256.size()]);

impl DigestType for Sha256 {
    fn digest_algorithm(&self) -> DigestAlgorithm {
        DigestAlgorithm::Sha256
    }
}

impl SignDataType for Sha256 {
    fn sign_data_algorithm(&self) -> SignDataAlgorithm {
        SignDataAlgorithm::Sha256
    }
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Clone)]
#[repr(C)]
pub struct Sha384(pub [u8; DigestAlgorithm::Sha384.size()]);

impl DigestType for Sha384 {
    fn digest_algorithm(&self) -> DigestAlgorithm {
        DigestAlgorithm::Sha384
    }
}

impl SignDataType for Sha384 {
    fn sign_data_algorithm(&self) -> SignDataAlgorithm {
        SignDataAlgorithm::Sha384
    }
}

#[derive(Debug, Clone)]
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

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Clone)]
#[repr(C)]
pub struct Mu(pub [u8; 64]);

impl SignDataType for Mu {
    fn sign_data_algorithm(&self) -> SignDataAlgorithm {
        SignDataAlgorithm::Mu
    }
}

impl From<[u8; 64]> for Mu {
    fn from(mu: [u8; 64]) -> Self {
        Mu(mu)
    }
}

#[derive(Debug, Clone)]
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

#[derive(Debug)]
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
    Mldsa(ml_dsa::MldsaPublicKey),
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
        PubKey::Mldsa(pub_key)
    }
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Signature {
    Ecdsa(EcdsaSignature),
    #[cfg(feature = "ml-dsa")]
    Mldsa(ml_dsa::MldsaSignature),
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
        Signature::Mldsa(sig)
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
        let digest = match (signature_alg, pub_key) {
            (SignatureAlgorithm::Ecdsa(_), PubKey::Ecdsa(pub_key)) => {
                let (x, y) = pub_key.as_slice();
                self.hash_all(&[&[0x4u8], &x, &y])?
            }
            #[cfg(feature = "ml-dsa")]
            (SignatureAlgorithm::Mldsa(_), PubKey::Mldsa(pub_key)) => {
                self.hash(pub_key.as_bytes())?
            }
            // This can be reached when the "ml-dsa" feature is enabled.
            #[allow(unreachable_patterns)]
            _ => Err(CryptoError::MismatchedAlgorithm)?,
        };
        digest.write_hex_str(serial)
    }
}

pub trait Signer {
    /// Sign `data` with the derived private key
    fn sign(&mut self, data: &SignData) -> Result<Signature, CryptoError>;

    /// Get the public key associated with the derived key-pair
    fn public_key(&mut self) -> Result<PubKey, CryptoError>;
}

pub trait CdiManager {
    /// Derives a key pair using a cryptographically secure KDF
    ///
    /// # Arguments
    ///
    /// * `label` - Caller-supplied label to use in asymmetric key derivation
    /// * `info` - Caller-supplied info string to use in asymmetric key derivation
    fn derive_key_pair(
        &mut self,
        label: &[u8],
        info: &[u8],
    ) -> Result<&mut dyn Signer, CryptoError>;

    /// CFI wrapper around derive_key_pair
    ///
    /// To implement this function, you need to add the
    /// cfi_impl_fn proc_macro to derive_key_pair.
    #[cfg(feature = "cfi")]
    fn __cfi_derive_key_pair(
        &mut self,
        label: &[u8],
        info: &[u8],
    ) -> Result<&mut dyn Signer, CryptoError>;

    /// Sign `data` with a derived key-pair from the CDI
    ///
    /// # Arguments
    ///
    /// * `label` - Caller-supplied label to use in asymmetric key derivation
    /// * `info` - Caller-supplied info string to use in asymmetric key derivation
    /// * `data` - Data to be signed.
    fn sign_with_derived(
        &mut self,
        label: &[u8],
        info: &[u8],
        data: &SignData,
    ) -> Result<Signature, CryptoError> {
        self.derive_key_pair(label, info)?.sign(data)
    }

    /// Get the public key of a derived key-pair from the CDI
    ///
    /// # Arguments
    ///
    /// * `label` - Caller-supplied label to use in asymmetric key derivation
    /// * `info` - Caller-supplied info string to use in asymmetric key derivation
    fn derive_pub_key(&mut self, label: &[u8], info: &[u8]) -> Result<PubKey, CryptoError> {
        self.derive_key_pair(label, info)?.public_key()
    }

    /// This should only be used in testing
    fn as_slice(&self) -> &[u8];
}

pub trait Crypto {
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
        self.hash_all(&[&bytes])
    }

    /// Returns an object that will be able to perform hash operations.
    ///
    /// Used for hashing multiple buffers that may not be in consecutive memory.
    fn hasher(&mut self) -> Result<&mut dyn Hasher, CryptoError>;

    /// Cryptographically hashes the given buffers as a running hash.
    ///
    /// # Arguments
    ///
    /// * `vals` - Values to be hashed.
    fn hash_all(&mut self, vals: &[&dyn AsRef<[u8]>]) -> Result<Digest, CryptoError> {
        self.with_hasher(&|hasher| {
            for chunk in vals {
                hasher.update(chunk.as_ref())?;
            }
            Ok(())
        })
    }

    /// Initialize a running hash and call a closure with it.
    ///
    /// # Arguments
    ///
    /// * `f` - Closure to call with the hasher.
    fn with_hasher(
        &mut self,
        f: &dyn Fn(&mut dyn Hasher) -> Result<(), CryptoError>,
    ) -> Result<Digest, CryptoError> {
        let hasher = self.hasher()?;
        hasher.initialize()?;
        f(hasher)?;
        hasher.finish()
    }

    /// Derive a CDI based on the current base CDI and measurements
    ///
    /// # Arguments
    ///
    /// * `measurement` - A digest of the measurements which should be used for CDI derivation
    /// * `info` - Caller-supplied info string to use in CDI derivation
    fn derive_cdi(
        &mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<&mut dyn CdiManager, CryptoError>;

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
    #[cfg(feature = "cfi")]
    fn __cfi_derive_cdi<'a>(
        &'a mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<&'a mut dyn CdiManager, CryptoError>;

    /// Derive a CDI for an exported private key based on the current base CDI and measurements
    ///
    /// # Arguments
    ///
    /// * `measurement` - A digest of the measurements which should be used for CDI derivation
    /// * `info` - Caller-supplied info string to use in CDI derivation
    #[cfg(feature = "cfi")]
    fn __cfi_derive_exported_cdi(
        &mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<ExportedCdiHandle, CryptoError>;

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
    ) -> Result<&mut dyn Signer, CryptoError>;

    /// CFI wrapper around derive_key_pair_exported
    ///
    /// To implement this function, you need to add the
    /// cfi_impl_fn proc_macro to derive_key_pair.
    #[cfg(feature = "cfi")]
    fn __cfi_derive_key_pair_exported(
        &mut self,
        exported_handle: &ExportedCdiHandle,
        label: &[u8],
        info: &[u8],
    ) -> Result<&mut dyn Signer, CryptoError>;

    /// Sign `digest` with the platform Alias Key
    ///
    /// # Arguments
    ///
    /// * `data` - Data to be signed.
    fn sign_with_alias(&mut self, data: &SignData) -> Result<Signature, CryptoError>;

    /// Sign `data` with a key derived from the current CDI and measurements.
    ///
    /// # Arguments
    ///
    /// * `measurement` - A digest of the measurements which should be used for CDI derivation.
    /// * `info` - Caller-supplied info string to use in CDI derivation.
    /// * `label` - Caller-supplied label to use in key derivation.
    /// * `derived_info` - Caller-supplied info string to use in key derivation.
    /// * `data` - Data to be signed.
    fn sign_with_derived(
        &mut self,
        measurement: &Digest,
        info: &[u8],
        label: &[u8],
        derived_info: &[u8],
        data: &SignData,
    ) -> Result<Signature, CryptoError> {
        self.derive_cdi(measurement, info)?
            .sign_with_derived(label, derived_info, data)
    }

    /// Derive the public key for a key derived from the current CDI and measurements.
    ///
    /// # Arguments
    ///
    /// * `measurement` - A digest of the measurements which should be used for CDI derivation.
    /// * `info` - Caller-supplied info string to use in CDI derivation.
    /// * `label` - Caller-supplied label to use in key derivation.
    /// * `derived_info` - Caller-supplied info string to use in key derivation.
    fn derive_pub_key(
        &mut self,
        measurement: &Digest,
        info: &[u8],
        label: &[u8],
        derived_info: &[u8],
    ) -> Result<PubKey, CryptoError> {
        self.derive_cdi(measurement, info)?
            .derive_pub_key(label, derived_info)
    }
}
