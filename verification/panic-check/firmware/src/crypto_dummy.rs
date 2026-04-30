// Licensed under the Apache-2.0 license

use crypto::{
    CdiManager, CryptoError, CryptoSuite, Digest, DigestAlgorithm, DigestType, ExportedCdiHandle,
    Hasher, PubKey, SignData, SignatureAlgorithm, SignatureType, Signer,
};

use crypto::Crypto;

pub struct DummyCrypto {
    hasher: DummyHasher,
    _cdi_manager: DummyCdiManager,
}

impl DummyCrypto {
    pub fn new() -> DummyCrypto {
        DummyCrypto {
            hasher: DummyHasher,
            _cdi_manager: DummyCdiManager {
                _signer: DummySigner,
            },
        }
    }
}

impl Default for DummyCrypto {
    fn default() -> Self {
        Self::new()
    }
}

impl Crypto for DummyCrypto {
    fn rand_bytes(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        let _ = dst;
        Err(CryptoError::NotImplemented)
    }

    fn hasher(&mut self) -> Result<&mut dyn Hasher, CryptoError> {
        Ok(&mut self.hasher)
    }

    #[cfg_attr(feature = "cfi", caliptra_cfi_derive::cfi_impl_fn)]
    fn derive_cdi(
        &mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<&mut dyn CdiManager, CryptoError> {
        let _ = info;
        let _ = measurement;
        Err(CryptoError::NotImplemented)
    }

    #[cfg_attr(feature = "cfi", caliptra_cfi_derive::cfi_impl_fn)]
    fn derive_exported_cdi(
        &mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<ExportedCdiHandle, CryptoError> {
        let _ = info;
        let _ = measurement;
        Err(CryptoError::NotImplemented)
    }

    #[cfg_attr(feature = "cfi", caliptra_cfi_derive::cfi_impl_fn)]
    fn derive_key_pair_exported(
        &mut self,
        exported_handle: &ExportedCdiHandle,
        label: &[u8],
        info: &[u8],
    ) -> Result<&mut dyn Signer, CryptoError> {
        let _ = info;
        let _ = label;
        let _ = exported_handle;
        Err(CryptoError::NotImplemented)
    }

    fn sign_with_alias(&mut self, data: &SignData) -> Result<crypto::Signature, CryptoError> {
        let _ = data;
        Err(CryptoError::NotImplemented)
    }
}

impl CryptoSuite for DummyCrypto {}

impl SignatureType for DummyCrypto {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ecdsa(crypto::ecdsa::EcdsaAlgorithm::Bit256)
    }
}

impl DigestType for DummyCrypto {
    fn digest_algorithm(&self) -> DigestAlgorithm {
        DigestAlgorithm::Sha256
    }
}

pub struct DummyHasher;

impl Hasher for DummyHasher {
    fn initialize(&mut self) -> Result<(), CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        let _ = bytes;
        Err(CryptoError::NotImplemented)
    }

    fn finish(&mut self) -> Result<Digest, CryptoError> {
        Err(CryptoError::NotImplemented)
    }
}

pub struct DummyCdiManager {
    _signer: DummySigner,
}

impl CdiManager for DummyCdiManager {
    #[cfg_attr(feature = "cfi", caliptra_cfi_derive::cfi_impl_fn)]
    fn derive_key_pair(
        &mut self,
        label: &[u8],
        info: &[u8],
    ) -> Result<&mut dyn Signer, CryptoError> {
        let _ = label;
        let _ = info;
        Err(CryptoError::NotImplemented)
    }

    fn as_slice(&self) -> &[u8] {
        &[]
    }
}

pub struct DummySigner;

impl Signer for DummySigner {
    fn sign(&mut self, data: &SignData) -> Result<crypto::Signature, CryptoError> {
        let _ = data;
        Err(CryptoError::NotImplemented)
    }

    fn public_key(&mut self) -> Result<PubKey, CryptoError> {
        Err(CryptoError::NotImplemented)
    }
}
