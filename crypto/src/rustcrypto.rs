// Licensed under the Apache-2.0 license

use crate::{
    hkdf::*, AlgLen, Crypto, CryptoBuf, CryptoError, Digest, EcdsaPub, EcdsaSig, ExportedCdiHandle,
    Hasher, MAX_EXPORTED_CDI_SIZE,
};
use core::ops::Deref;
use ecdsa::{signature::hazmat::PrehashSigner, Signature};
use p256::NistP256;
use p384::NistP384;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sec1::DecodeEcPrivateKey;
use sha2::{digest::DynDigest, Sha256, Sha384};
use std::boxed::Box;

#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;

const RUSTCRYPTO_ECDSA_ERROR: CryptoError = CryptoError::CryptoLibError(1);
const RUSTCRYPTO_SEC_ERROR: CryptoError = CryptoError::CryptoLibError(2);

impl From<ecdsa::Error> for CryptoError {
    fn from(_value: ecdsa::Error) -> Self {
        RUSTCRYPTO_ECDSA_ERROR
    }
}

impl From<sec1::Error> for CryptoError {
    fn from(_value: sec1::Error) -> Self {
        RUSTCRYPTO_SEC_ERROR
    }
}

impl TryFrom<Signature<NistP256>> for EcdsaSig {
    type Error = CryptoError;

    fn try_from(value: Signature<NistP256>) -> Result<Self, Self::Error> {
        let r = CryptoBuf::new(&value.r().deref().to_bytes())?;
        let s = CryptoBuf::new(&value.s().deref().to_bytes())?;
        Ok(EcdsaSig { r, s })
    }
}
impl TryFrom<Signature<NistP384>> for EcdsaSig {
    type Error = CryptoError;

    fn try_from(value: Signature<NistP384>) -> Result<Self, Self::Error> {
        let r = CryptoBuf::new(&value.r().deref().to_bytes())?;
        let s = CryptoBuf::new(&value.s().deref().to_bytes())?;
        Ok(EcdsaSig { r, s })
    }
}

pub struct RustCryptoHasher(Box<dyn DynDigest>);
impl Hasher for RustCryptoHasher {
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        self.0.update(bytes);
        Ok(())
    }
    fn finish(self) -> Result<Digest, CryptoError> {
        Digest::new(&self.0.finalize())
    }
}

// Currently only supports one CDI handle but in the future we may want to support multiple.
const MAX_CDI_HANDLES: usize = 1;

pub struct RustCryptoImpl {
    rng: StdRng,
    export_cdi_slots: Vec<(<RustCryptoImpl as Crypto>::Cdi, ExportedCdiHandle)>,
}

impl Default for RustCryptoImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl RustCryptoImpl {
    #[cfg(not(feature = "deterministic_rand"))]
    pub fn new() -> Self {
        Self {
            rng: StdRng::from_entropy(),
            export_cdi_slots: Vec::new(),
        }
    }

    #[cfg(feature = "deterministic_rand")]
    pub fn new() -> Self {
        const SEED: [u8; 32] = [1; 32];
        let seeded_rng = StdRng::from_seed(SEED);
        Self {
            rng: seeded_rng,
            export_cdi_slots: Vec::new(),
        }
    }

    fn derive_key_pair_inner(
        &mut self,
        algs: AlgLen,
        cdi: &<RustCryptoImpl as Crypto>::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<(<RustCryptoImpl as Crypto>::PrivKey, EcdsaPub), CryptoError> {
        let secret = hkdf_get_priv_key(algs, cdi, label, info)?;
        match algs {
            AlgLen::Bit256 => {
                let signing = p256::ecdsa::SigningKey::from_slice(secret.bytes())?;
                let verifying = p256::ecdsa::VerifyingKey::from(&signing);
                let point = verifying.to_encoded_point(false);
                let x = CryptoBuf::new(point.x().ok_or(RUSTCRYPTO_ECDSA_ERROR)?.as_slice())?;
                let y = CryptoBuf::new(point.y().ok_or(RUSTCRYPTO_ECDSA_ERROR)?.as_slice())?;
                Ok((secret, EcdsaPub { x, y }))
            }
            AlgLen::Bit384 => {
                let signing = p384::ecdsa::SigningKey::from_slice(secret.bytes())?;
                let verifying = p384::ecdsa::VerifyingKey::from(&signing);
                let point = verifying.to_encoded_point(false);
                let x = CryptoBuf::new(point.x().ok_or(RUSTCRYPTO_ECDSA_ERROR)?.as_slice())?;
                let y = CryptoBuf::new(point.y().ok_or(RUSTCRYPTO_ECDSA_ERROR)?.as_slice())?;
                Ok((secret, EcdsaPub { x, y }))
            }
        }
    }
}

impl Crypto for RustCryptoImpl {
    type Cdi = Vec<u8>;
    type Hasher<'c>
        = RustCryptoHasher
    where
        Self: 'c;
    type PrivKey = CryptoBuf;

    fn hash_initialize(&mut self, algs: AlgLen) -> Result<Self::Hasher<'_>, CryptoError> {
        let hasher = match algs {
            AlgLen::Bit256 => RustCryptoHasher(Box::new(Sha256::default())),
            AlgLen::Bit384 => RustCryptoHasher(Box::new(Sha384::default())),
        };
        Ok(hasher)
    }

    fn rand_bytes(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        StdRng::fill_bytes(&mut self.rng, dst);
        Ok(())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_cdi(
        &mut self,
        algs: AlgLen,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<Self::Cdi, CryptoError> {
        hkdf_derive_cdi(algs, measurement, info)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_exported_cdi(
        &mut self,
        algs: AlgLen,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<ExportedCdiHandle, CryptoError> {
        let cdi = hkdf_derive_cdi(algs, measurement, info)?;

        for (stored_cdi, _) in self.export_cdi_slots.iter() {
            if *stored_cdi == cdi {
                return Err(CryptoError::ExportedCdiHandleDuplicateCdi);
            }
        }

        if self.export_cdi_slots.len() >= MAX_CDI_HANDLES {
            return Err(CryptoError::ExportedCdiHandleLimitExceeded);
        }

        let mut exported_cdi_handle = [0; MAX_EXPORTED_CDI_SIZE];
        self.rand_bytes(&mut exported_cdi_handle)?;
        self.export_cdi_slots.push((cdi, exported_cdi_handle));
        Ok(exported_cdi_handle)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_key_pair(
        &mut self,
        algs: AlgLen,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, EcdsaPub), CryptoError> {
        self.derive_key_pair_inner(algs, cdi, label, info)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_key_pair_exported(
        &mut self,
        algs: AlgLen,
        exported_handle: &ExportedCdiHandle,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, EcdsaPub), CryptoError> {
        let cdi = {
            let mut cdi = None;
            for (stored_cdi, stored_handle) in self.export_cdi_slots.iter() {
                if stored_handle == exported_handle {
                    cdi = Some(stored_cdi.clone());
                }
            }
            cdi.ok_or(CryptoError::InvalidExportedCdiHandle)
        }?;
        self.derive_key_pair_inner(algs, &cdi, label, info)
    }

    fn ecdsa_sign_with_alias(
        &mut self,
        algs: AlgLen,
        digest: &Digest,
    ) -> Result<EcdsaSig, CryptoError> {
        match algs {
            AlgLen::Bit256 => {
                let signing_key = p256::ecdsa::SigningKey::from_sec1_pem(include_str!(concat!(
                    env!("OUT_DIR"),
                    "/alias_priv_256.pem"
                )))?;
                let sig: p256::ecdsa::Signature = signing_key.sign_prehash(digest.bytes())?;
                sig.try_into()
            }
            AlgLen::Bit384 => {
                let signing_key = p384::ecdsa::SigningKey::from_sec1_pem(include_str!(concat!(
                    env!("OUT_DIR"),
                    "/alias_priv_384.pem"
                )))?;
                let sig: p384::ecdsa::Signature = signing_key.sign_prehash(digest.bytes())?;
                sig.try_into()
            }
        }
    }

    fn ecdsa_sign_with_derived(
        &mut self,
        algs: AlgLen,
        digest: &Digest,
        priv_key: &Self::PrivKey,
        _pub_key: &EcdsaPub,
    ) -> Result<EcdsaSig, CryptoError> {
        match algs {
            AlgLen::Bit256 => {
                let sig: p256::ecdsa::Signature =
                    p256::ecdsa::SigningKey::from_slice(priv_key.bytes())?
                        .sign_prehash(digest.bytes())?;
                sig.try_into()
            }
            AlgLen::Bit384 => {
                let sig: p384::ecdsa::Signature =
                    p384::ecdsa::SigningKey::from_slice(priv_key.bytes())?
                        .sign_prehash(digest.bytes())?;
                sig.try_into()
            }
        }
    }
}
