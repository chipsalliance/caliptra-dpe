// Licensed under the Apache-2.0 license

use crate::{
    ecdsa::{
        curve_256::EcdsaSignature256, curve_384::EcdsaSignature384, EcdsaAlgorithm, EcdsaPub,
        EcdsaSig,
    },
    hkdf::*,
    CdiManager, Crypto, CryptoError, CryptoSuite, Digest, DigestAlgorithm, DigestType,
    ExportedCdiHandle, Hasher, PubKey, SignData, SignDataAlgorithm, SignDataType,
    SignatureAlgorithm, SignatureType, MAX_EXPORTED_CDI_SIZE,
};

#[cfg(feature = "ml-dsa")]
use {
    crate::ml_dsa::{MldsaAlgorithm, MldsaPublicKey, MldsaSignature},
    ml_dsa::{
        signature::{Keypair, Signer},
        KeyGen, MlDsa87, SigningKey,
    },
    pkcs8::DecodePrivateKey,
    zerocopy::{IntoBytes, SizeError},
};

use constant_time_eq::constant_time_eq;
use core::ops::Deref;
use ecdsa::{signature::hazmat::PrehashSigner, PrimeCurve, Signature};
use p256::NistP256;
use p384::NistP384;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sec1::DecodeEcPrivateKey;
use sha2::{digest::DynDigest, Sha256, Sha384};
use std::boxed::Box;
use zerocopy::FromBytes;

#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_impl_fn;

const RUSTCRYPTO_ECDSA_ERROR: CryptoError = CryptoError::CryptoLibError(1);
const RUSTCRYPTO_SEC_ERROR: CryptoError = CryptoError::CryptoLibError(2);

#[cfg(feature = "ml-dsa")]
const RUSTCRYPTO_ML_DSA_ERROR: CryptoError = CryptoError::CryptoLibError(3);

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

#[cfg(feature = "ml-dsa")]
impl From<pkcs8::Error> for CryptoError {
    fn from(_value: pkcs8::Error) -> Self {
        RUSTCRYPTO_ML_DSA_ERROR
    }
}

#[cfg(feature = "ml-dsa")]
impl From<SizeError<&[u8], MldsaSignature>> for CryptoError {
    fn from(_value: SizeError<&[u8], MldsaSignature>) -> Self {
        RUSTCRYPTO_ML_DSA_ERROR
    }
}

impl From<Signature<NistP256>> for EcdsaSignature256 {
    fn from(value: Signature<NistP256>) -> Self {
        let mut r = [0; EcdsaAlgorithm::Bit256.curve_size()];
        let mut s = [0; EcdsaAlgorithm::Bit256.curve_size()];
        r.clone_from_slice(value.r().deref().to_bytes().as_ref());
        s.clone_from_slice(value.s().deref().to_bytes().as_ref());

        EcdsaSignature256::from_slice(&r, &s)
    }
}
impl From<Signature<NistP384>> for EcdsaSignature384 {
    fn from(value: Signature<NistP384>) -> Self {
        let mut r = [0; EcdsaAlgorithm::Bit384.curve_size()];
        let mut s = [0; EcdsaAlgorithm::Bit384.curve_size()];
        r.clone_from_slice(value.r().deref().to_bytes().as_ref());
        s.clone_from_slice(value.s().deref().to_bytes().as_ref());

        EcdsaSignature384::from_slice(&r, &s)
    }
}

pub struct RustCryptoHasher {
    hasher: Option<Box<dyn DynDigest>>,
    alg: DigestAlgorithm,
}

impl RustCryptoHasher {
    fn new(alg: DigestAlgorithm) -> Self {
        Self {
            hasher: Some(Self::new_hasher(alg)),
            alg,
        }
    }

    fn new_hasher(alg: DigestAlgorithm) -> Box<dyn DynDigest> {
        match alg {
            DigestAlgorithm::Sha256 => Box::new(Sha256::default()),
            DigestAlgorithm::Sha384 => Box::new(Sha384::default()),
        }
    }
}

impl Hasher for RustCryptoHasher {
    fn initialize(&mut self) -> Result<(), CryptoError> {
        self.hasher = Some(Self::new_hasher(self.alg));
        Ok(())
    }
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        let Some(hasher) = self.hasher.as_mut() else {
            return Err(CryptoError::HashError(0));
        };
        hasher.update(bytes);
        Ok(())
    }
    fn finish(&mut self) -> Result<Digest, CryptoError> {
        let hasher = self.hasher.take().ok_or(CryptoError::HashError(1))?;
        let digest = &hasher.finalize();
        let digest = match self.alg {
            DigestAlgorithm::Sha256 => {
                let sha256 =
                    crate::Sha256::read_from_bytes(digest).map_err(|_| CryptoError::Size)?;
                Digest::Sha256(sha256)
            }
            DigestAlgorithm::Sha384 => {
                let sha384 =
                    crate::Sha384::read_from_bytes(digest).map_err(|_| CryptoError::Size)?;
                Digest::Sha384(sha384)
            }
        };
        Ok(digest)
    }
}

// Currently only supports one CDI handle but in the future we may want to support multiple.
const MAX_CDI_HANDLES: usize = 1;

pub struct RustCryptoSigner {
    priv_key: Vec<u8>,
    signature_alg: SignatureAlgorithm,
}

impl crate::Signer for RustCryptoSigner {
    fn sign(&mut self, data: &SignData) -> Result<super::Signature, CryptoError> {
        match self.signature_alg {
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
                let signing = p256::ecdsa::SigningKey::from_slice(self.priv_key.as_slice())?;
                let sig =
                    RustCryptoImpl::ecdsa_sign_data_inner(&signing, data, self.signature_alg)?;
                Ok(EcdsaSig::from(sig).into())
            }
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
                let signing = p384::ecdsa::SigningKey::from_slice(self.priv_key.as_slice())?;
                let sig =
                    RustCryptoImpl::ecdsa_sign_data_inner(&signing, data, self.signature_alg)?;
                Ok(EcdsaSig::from(sig).into())
            }
            #[cfg(feature = "ml-dsa")]
            SignatureAlgorithm::Mldsa(MldsaAlgorithm::Mldsa87) => {
                let kp = MlDsa87::from_seed(
                    self.priv_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| RUSTCRYPTO_ML_DSA_ERROR)?,
                );
                RustCryptoImpl::mldsa_sign_data_inner(&kp, data)
            }
        }
    }

    fn public_key(&mut self) -> Result<PubKey, CryptoError> {
        match self.signature_alg {
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
                let signing = p256::ecdsa::SigningKey::from_slice(self.priv_key.as_slice())?;
                let verifying = p256::ecdsa::VerifyingKey::from(&signing);
                let point = verifying.to_encoded_point(false);

                let mut x = [0; EcdsaAlgorithm::Bit256.curve_size()];
                let mut y = [0; EcdsaAlgorithm::Bit256.curve_size()];
                x.clone_from_slice(point.x().ok_or(RUSTCRYPTO_ECDSA_ERROR)?.as_ref());
                y.clone_from_slice(point.y().ok_or(RUSTCRYPTO_ECDSA_ERROR)?.as_ref());

                Ok(EcdsaPub::from_slice(&x, &y).into())
            }
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
                let signing = p384::ecdsa::SigningKey::from_slice(self.priv_key.as_slice())?;
                let verifying = p384::ecdsa::VerifyingKey::from(&signing);
                let point = verifying.to_encoded_point(false);

                let mut x = [0; EcdsaAlgorithm::Bit384.curve_size()];
                let mut y = [0; EcdsaAlgorithm::Bit384.curve_size()];
                x.clone_from_slice(point.x().ok_or(RUSTCRYPTO_ECDSA_ERROR)?.as_ref());
                y.clone_from_slice(point.y().ok_or(RUSTCRYPTO_ECDSA_ERROR)?.as_ref());

                Ok(EcdsaPub::from_slice(&x, &y).into())
            }
            #[cfg(feature = "ml-dsa")]
            SignatureAlgorithm::Mldsa(MldsaAlgorithm::Mldsa87) => {
                let kp = MlDsa87::from_seed(
                    self.priv_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| RUSTCRYPTO_ML_DSA_ERROR)?,
                );
                let verifying = kp.verifying_key();
                let encoded_key = verifying.encode();
                Ok(PubKey::Mldsa(
                    MldsaPublicKey::read_from_bytes(encoded_key.as_bytes())
                        .map_err(|_| RUSTCRYPTO_ML_DSA_ERROR)?,
                ))
            }
        }
    }
}

pub struct RustCryptoCdi {
    cdi: Vec<u8>,
    signature_alg: SignatureAlgorithm,
    signer: RustCryptoSigner,
}

impl crate::CdiManager for RustCryptoCdi {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn derive_key_pair(
        &mut self,
        label: &[u8],
        info: &[u8],
    ) -> Result<&mut dyn crate::Signer, CryptoError> {
        self.signer.priv_key = hkdf_get_priv_key(self.signature_alg, &self.cdi, label, info)?;
        self.signer.signature_alg = self.signature_alg;
        Ok(&mut self.signer)
    }

    fn as_slice(&self) -> &[u8] {
        &self.cdi
    }
}

pub struct RustCryptoImpl {
    rng: StdRng,
    export_cdi_slots: Vec<(Vec<u8>, ExportedCdiHandle)>,
    signature_alg: SignatureAlgorithm,
    digest_alg: DigestAlgorithm,
    sign_data_alg: SignDataAlgorithm,
    hasher: RustCryptoHasher,
    cdi: RustCryptoCdi,
}

impl SignatureType for RustCryptoImpl {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.signature_alg
    }
}

impl DigestType for RustCryptoImpl {
    fn digest_algorithm(&self) -> DigestAlgorithm {
        self.digest_alg
    }
}

impl SignDataType for RustCryptoImpl {
    fn sign_data_algorithm(&self) -> SignDataAlgorithm {
        self.sign_data_alg
    }
}

impl CryptoSuite for RustCryptoImpl {}

impl RustCryptoImpl {
    #[cfg(not(feature = "deterministic_rand"))]
    pub fn new(
        signature_alg: SignatureAlgorithm,
        digest_alg: DigestAlgorithm,
        sign_data_alg: SignDataAlgorithm,
    ) -> Self {
        Self {
            rng: StdRng::from_entropy(),
            export_cdi_slots: Vec::new(),
            signature_alg,
            digest_alg,
            sign_data_alg,
            hasher: RustCryptoHasher::new(digest_alg),
            cdi: RustCryptoCdi {
                cdi: Vec::new(),
                signature_alg,
                signer: RustCryptoSigner {
                    priv_key: Vec::new(),
                    signature_alg,
                },
            },
        }
    }

    #[cfg(feature = "deterministic_rand")]
    pub fn new(
        signature_alg: SignatureAlgorithm,
        digest_alg: DigestAlgorithm,
        sign_data_alg: SignDataAlgorithm,
    ) -> Self {
        const SEED: [u8; 32] = [1; 32];
        let seeded_rng = StdRng::from_seed(SEED);
        Self {
            rng: seeded_rng,
            export_cdi_slots: Vec::new(),
            signature_alg,
            digest_alg,
            sign_data_alg,
            hasher: RustCryptoHasher::new(digest_alg),
            cdi: RustCryptoCdi {
                cdi: Vec::new(),
                signature_alg,
                signer: RustCryptoSigner {
                    priv_key: Vec::new(),
                    signature_alg,
                },
            },
        }
    }

    pub fn new_ecc256() -> Self {
        Self::new(
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256),
            DigestAlgorithm::Sha256,
            SignDataAlgorithm::Sha256,
        )
    }

    pub fn new_ecc384() -> Self {
        Self::new(
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384),
            DigestAlgorithm::Sha384,
            SignDataAlgorithm::Sha384,
        )
    }

    #[cfg(feature = "ml-dsa")]
    pub fn new_mldsa87() -> Self {
        Self::new(
            SignatureAlgorithm::Mldsa(MldsaAlgorithm::Mldsa87),
            DigestAlgorithm::Sha384,
            SignDataAlgorithm::Mu,
        )
    }

    fn ecdsa_sign_data_inner<C: PrimeCurve>(
        key: &dyn PrehashSigner<Signature<C>>,
        data: &SignData,
        alg: SignatureAlgorithm,
    ) -> Result<Signature<C>, CryptoError> {
        match data {
            SignData::Digest(dig) => Ok(key.sign_prehash(dig.as_slice())?),
            SignData::Raw(raw) => {
                let digest_bytes = match alg {
                    SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
                        use sha2::{Digest, Sha256};
                        Sha256::digest(raw).to_vec()
                    }
                    SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
                        use sha2::{Digest, Sha384};
                        Sha384::digest(raw).to_vec()
                    }
                    #[allow(unreachable_patterns)]
                    _ => return Err(CryptoError::MismatchedAlgorithm),
                };
                Ok(key.sign_prehash(&digest_bytes)?)
            }
            _ => Err(CryptoError::MismatchedAlgorithm),
        }
    }

    #[cfg(feature = "ml-dsa")]
    fn mldsa_sign_data_inner(
        key: &SigningKey<MlDsa87>,
        data: &SignData,
    ) -> Result<super::Signature, CryptoError> {
        let sig = match data {
            SignData::Mu(mu) => key.signing_key().sign_mu_deterministic((&mu.0).into()),
            SignData::Raw(raw) => key.sign(raw),
            SignData::Digest(_) => return Err(CryptoError::MismatchedAlgorithm),
        };
        let sig = sig.encode();
        Ok(super::Signature::Mldsa(MldsaSignature::read_from_bytes(
            sig.as_slice(),
        )?))
    }
}

impl Crypto for RustCryptoImpl {
    fn hasher(&mut self) -> Result<&mut dyn Hasher, CryptoError> {
        Ok(&mut self.hasher)
    }

    fn rand_bytes(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        StdRng::fill_bytes(&mut self.rng, dst);
        Ok(())
    }

    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn derive_cdi(
        &mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<&mut dyn crate::CdiManager, CryptoError> {
        let cdi_key = hkdf_derive_cdi(self.signature_alg, measurement, info)?;
        self.cdi.cdi.clear();
        self.cdi.cdi.extend_from_slice(cdi_key.as_slice());
        Ok(&mut self.cdi)
    }

    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn derive_exported_cdi(
        &mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<ExportedCdiHandle, CryptoError> {
        let cdi = hkdf_derive_cdi(self.signature_alg, measurement, info)?;

        for (stored_cdi, _) in self.export_cdi_slots.iter() {
            if constant_time_eq(stored_cdi.as_slice(), cdi.as_slice()) {
                return Err(CryptoError::ExportedCdiHandleDuplicateCdi);
            }
        }

        if self.export_cdi_slots.len() >= MAX_CDI_HANDLES {
            return Err(CryptoError::ExportedCdiHandleLimitExceeded);
        }

        let mut exported_cdi_handle = [0; MAX_EXPORTED_CDI_SIZE];
        self.rand_bytes(&mut exported_cdi_handle)?;
        self.export_cdi_slots
            .push((cdi.as_slice().to_vec(), exported_cdi_handle));
        Ok(exported_cdi_handle)
    }

    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn derive_key_pair_exported(
        &mut self,
        exported_handle: &ExportedCdiHandle,
        label: &[u8],
        info: &[u8],
    ) -> Result<&mut dyn crate::Signer, CryptoError> {
        for (cdi, handle) in &self.export_cdi_slots {
            if constant_time_eq(handle.as_slice(), exported_handle.as_slice()) {
                self.cdi.cdi.clear();
                self.cdi.cdi.extend_from_slice(cdi);
                self.cdi.signature_alg = self.signature_alg;
                return self.cdi.derive_key_pair(label, info);
            }
        }
        Err(CryptoError::InvalidExportedCdiHandle)
    }

    fn sign_with_alias(&mut self, data: &SignData) -> Result<super::Signature, CryptoError> {
        use crate::artifacts;
        match self.signature_alg {
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
                let signing_key = p256::ecdsa::SigningKey::from_sec1_pem(artifacts::KEY_P256_PEM)?;
                let sig = Self::ecdsa_sign_data_inner(&signing_key, data, self.signature_alg)?;
                Ok(EcdsaSig::from(sig).into())
            }
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
                let signing_key = p384::ecdsa::SigningKey::from_sec1_pem(artifacts::KEY_P384_PEM)?;
                let sig = Self::ecdsa_sign_data_inner(&signing_key, data, self.signature_alg)?;
                Ok(EcdsaSig::from(sig).into())
            }
            #[cfg(feature = "ml-dsa")]
            SignatureAlgorithm::Mldsa(MldsaAlgorithm::Mldsa87) => {
                let ml_dsa_secret =
                    SigningKey::<MlDsa87>::from_pkcs8_pem(artifacts::KEY_MLDSA_87_PEM)?;
                Self::mldsa_sign_data_inner(&ml_dsa_secret, data)
            }
        }
    }
}
