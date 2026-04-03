// Licensed under the Apache-2.0 license

use crate::{
    CryptoError, CryptoSuite, DigestAlgorithm, DigestType, Hasher, SignatureAlgorithm,
    SignatureType,
};

use super::Crypto;

pub struct DummyCrypto;
impl DummyCrypto {
    pub fn new() -> DummyCrypto {
        DummyCrypto
    }
}
impl Default for DummyCrypto {
    fn default() -> Self {
        Self::new()
    }
}

impl Crypto for DummyCrypto {
    type Cdi = ();

    type Hasher<'c>
        = DummyHasher
    where
        Self: 'c;

    type PrivKey = ();

    fn rand_bytes(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        let _ = dst;
        Err(CryptoError::NotImplemented)
    }

    fn hash_initialize(&mut self) -> Result<Self::Hasher<'_>, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn derive_cdi(
        &mut self,
        measurement: &crate::Digest,
        info: &[u8],
    ) -> Result<Self::Cdi, CryptoError> {
        let _ = info;
        let _ = measurement;
        Err(CryptoError::NotImplemented)
    }

    fn derive_exported_cdi(
        &mut self,
        measurement: &crate::Digest,
        info: &[u8],
    ) -> Result<crate::ExportedCdiHandle, CryptoError> {
        let _ = info;
        let _ = measurement;
        Err(CryptoError::NotImplemented)
    }

    #[cfg(feature = "cfi")]
    fn __cfi_derive_cdi(
        &mut self,
        measurement: &crate::Digest,
        info: &[u8],
    ) -> Result<Self::Cdi, CryptoError> {
        let _ = info;
        let _ = measurement;
        Err(CryptoError::NotImplemented)
    }

    #[cfg(feature = "cfi")]
    fn __cfi_derive_exported_cdi(
        &mut self,
        measurement: &crate::Digest,
        info: &[u8],
    ) -> Result<crate::ExportedCdiHandle, CryptoError> {
        let _ = info;
        let _ = measurement;
        Err(CryptoError::NotImplemented)
    }

    fn derive_key_pair(
        &mut self,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, crate::PubKey), CryptoError> {
        let _ = info;
        let _ = label;
        let _ = cdi;
        Err(CryptoError::NotImplemented)
    }

    fn derive_key_pair_exported(
        &mut self,
        exported_handle: &crate::ExportedCdiHandle,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, crate::PubKey), CryptoError> {
        let _ = info;
        let _ = label;
        let _ = exported_handle;
        Err(CryptoError::NotImplemented)
    }

    #[cfg(feature = "cfi")]
    fn __cfi_derive_key_pair(
        &mut self,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, crate::PubKey), CryptoError> {
        let _ = info;
        let _ = label;
        let _ = cdi;
        Err(CryptoError::NotImplemented)
    }

    #[cfg(feature = "cfi")]
    fn __cfi_derive_key_pair_exported(
        &mut self,
        exported_handle: &crate::ExportedCdiHandle,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, crate::PubKey), CryptoError> {
        let _ = info;
        let _ = label;
        let _ = exported_handle;
        Err(CryptoError::NotImplemented)
    }

    fn sign_with_alias(&mut self, data: &crate::SignData) -> Result<crate::Signature, CryptoError> {
        let _ = data;
        Err(CryptoError::NotImplemented)
    }

    fn sign_with_derived(
        &mut self,
        data: &crate::SignData,
        priv_key: &Self::PrivKey,
        pub_key: &crate::PubKey,
    ) -> Result<crate::Signature, CryptoError> {
        let _ = pub_key;
        let _ = priv_key;
        let _ = data;
        Err(CryptoError::NotImplemented)
    }
}

impl CryptoSuite for DummyCrypto {}
impl SignatureType for DummyCrypto {
    const SIGNATURE_ALGORITHM: crate::SignatureAlgorithm =
        SignatureAlgorithm::Ecdsa(crate::ecdsa::EcdsaAlgorithm::Bit256);
}
impl DigestType for DummyCrypto {
    const DIGEST_ALGORITHM: crate::DigestAlgorithm = DigestAlgorithm::Sha256;
}

pub struct DummyHasher;

impl Hasher for DummyHasher {
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        let _ = bytes;
        Err(CryptoError::NotImplemented)
    }

    fn finish(self) -> Result<crate::Digest, CryptoError> {
        Err(CryptoError::NotImplemented)
    }
}
