// Licensed under the Apache-2.0 license

use crate::{
    ecdsa::{
        curve_256::{Curve256, EcdsaSignature256},
        curve_384::{Curve384, EcdsaSignature384},
        EcdsaAlgorithm, EcdsaPub, EcdsaSig,
    },
    hkdf::*,
    Crypto, CryptoError, CryptoSuite, Digest, DigestAlgorithm, DigestType, ExportedCdiHandle,
    Hasher, PubKey, SignatureAlgorithm, SignatureType, MAX_EXPORTED_CDI_SIZE,
};

#[cfg(feature = "ml-dsa")]
use {
    crate::ml_dsa::{ExternalMu, MldsaAlgorithm, MldsaPublicKey, MldsaSignature},
    ml_dsa::{signature::Signer, KeyGen, KeyPair, MlDsa87},
    pkcs8::{DecodePrivateKey, EncodePublicKey},
    zerocopy::{IntoBytes, SizeError},
};

use core::marker::PhantomData;
use core::ops::Deref;
use ecdsa::{signature::hazmat::PrehashSigner, Signature};
use p256::NistP256;
use p384::NistP384;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sec1::DecodeEcPrivateKey;
use sha2::{digest::DynDigest, Sha256, Sha384};
use std::boxed::Box;
use zerocopy::FromBytes;

#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;

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
        r.clone_from_slice(value.r().deref().to_bytes().as_slice());
        s.clone_from_slice(value.s().deref().to_bytes().as_slice());

        EcdsaSignature256::from_slice(&r, &s)
    }
}
impl From<Signature<NistP384>> for EcdsaSignature384 {
    fn from(value: Signature<NistP384>) -> Self {
        let mut r = [0; EcdsaAlgorithm::Bit384.curve_size()];
        let mut s = [0; EcdsaAlgorithm::Bit384.curve_size()];
        r.clone_from_slice(value.r().deref().to_bytes().as_slice());
        s.clone_from_slice(value.s().deref().to_bytes().as_slice());

        EcdsaSignature384::from_slice(&r, &s)
    }
}

pub struct RustCryptoHasher<D: DigestType> {
    hasher: Box<dyn DynDigest>,
    _alg: PhantomData<D>,
}

impl<D: DigestType> Hasher for RustCryptoHasher<D> {
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        self.hasher.update(bytes);
        Ok(())
    }
    fn finish(self) -> Result<Digest, CryptoError> {
        let digest = &self.hasher.finalize();
        let digest = match D::DIGEST_ALGORITHM {
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

pub type Ecdsa256RustCrypto = RustCryptoImpl<Curve256, crate::Sha256>;
impl CryptoSuite for Ecdsa256RustCrypto {}
impl SignatureType for Ecdsa256RustCrypto {
    const SIGNATURE_ALGORITHM: SignatureAlgorithm = Curve256::SIGNATURE_ALGORITHM;
}
impl DigestType for Ecdsa256RustCrypto {
    const DIGEST_ALGORITHM: DigestAlgorithm = crate::Sha256::DIGEST_ALGORITHM;
}

pub type Ecdsa384RustCrypto = RustCryptoImpl<Curve384, crate::Sha384>;
impl CryptoSuite for Ecdsa384RustCrypto {}
impl SignatureType for Ecdsa384RustCrypto {
    const SIGNATURE_ALGORITHM: SignatureAlgorithm = Curve384::SIGNATURE_ALGORITHM;
}

impl DigestType for Ecdsa384RustCrypto {
    const DIGEST_ALGORITHM: DigestAlgorithm = crate::Sha384::DIGEST_ALGORITHM;
}

#[cfg(feature = "ml-dsa")]
pub type MldsaRustCrypto = RustCryptoImpl<ExternalMu, crate::Sha384>;

#[cfg(feature = "ml-dsa")]
impl CryptoSuite for MldsaRustCrypto {}

#[cfg(feature = "ml-dsa")]
impl SignatureType for MldsaRustCrypto {
    const SIGNATURE_ALGORITHM: SignatureAlgorithm = ExternalMu::SIGNATURE_ALGORITHM;
}

// TODO(clundin): Should this instead be an External Mu variant?
#[cfg(feature = "ml-dsa")]
impl DigestType for MldsaRustCrypto {
    const DIGEST_ALGORITHM: DigestAlgorithm = crate::Sha384::DIGEST_ALGORITHM;
}

pub struct RustCryptoImpl<S: SignatureType, D: DigestType> {
    rng: StdRng,
    export_cdi_slots: Vec<(<RustCryptoImpl<S, D> as Crypto>::Cdi, ExportedCdiHandle)>,
    _signature_alg: PhantomData<S>,
    _digest_alg: PhantomData<D>,
}

impl<S: SignatureType, D: DigestType> Default for RustCryptoImpl<S, D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: SignatureType, D: DigestType> RustCryptoImpl<S, D> {
    #[cfg(not(feature = "deterministic_rand"))]
    pub fn new() -> Self {
        Self {
            rng: StdRng::from_entropy(),
            export_cdi_slots: Vec::new(),
            _signature_alg: Default::default(),
            _digest_alg: Default::default(),
        }
    }

    #[cfg(feature = "deterministic_rand")]
    pub fn new() -> Self {
        const SEED: [u8; 32] = [1; 32];
        let seeded_rng = StdRng::from_seed(SEED);
        Self {
            rng: seeded_rng,
            export_cdi_slots: Vec::new(),
            _signature_alg: Default::default(),
            _digest_alg: Default::default(),
        }
    }

    #[allow(clippy::type_complexity)]
    fn derive_key_pair_inner(
        &mut self,
        cdi: &<RustCryptoImpl<S, D> as Crypto>::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<(<RustCryptoImpl<S, D> as Crypto>::PrivKey, PubKey), CryptoError> {
        match S::SIGNATURE_ALGORITHM {
            alg @ SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
                let secret = hkdf_get_priv_key(alg, cdi, label, info)?;
                let signing = p256::ecdsa::SigningKey::from_slice(secret.as_slice())?;
                let verifying = p256::ecdsa::VerifyingKey::from(&signing);
                let point = verifying.to_encoded_point(false);

                let mut x = [0; EcdsaAlgorithm::Bit256.curve_size()];
                let mut y = [0; EcdsaAlgorithm::Bit256.curve_size()];
                x.clone_from_slice(point.x().ok_or(RUSTCRYPTO_ECDSA_ERROR)?.as_slice());
                y.clone_from_slice(point.y().ok_or(RUSTCRYPTO_ECDSA_ERROR)?.as_slice());

                Ok((
                    RustCryptoPrivKey(secret),
                    EcdsaPub::from_slice(&x, &y).into(),
                ))
            }
            alg @ SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
                let secret = hkdf_get_priv_key(alg, cdi, label, info)?;
                let signing = p384::ecdsa::SigningKey::from_slice(secret.as_slice())?;
                let verifying = p384::ecdsa::VerifyingKey::from(&signing);
                let point = verifying.to_encoded_point(false);

                let mut x = [0; EcdsaAlgorithm::Bit384.curve_size()];
                let mut y = [0; EcdsaAlgorithm::Bit384.curve_size()];
                x.clone_from_slice(point.x().ok_or(RUSTCRYPTO_ECDSA_ERROR)?.as_slice());
                y.clone_from_slice(point.y().ok_or(RUSTCRYPTO_ECDSA_ERROR)?.as_slice());

                Ok((
                    RustCryptoPrivKey(secret),
                    EcdsaPub::from_slice(&x, &y).into(),
                ))
            }
            #[cfg(feature = "ml-dsa")]
            alg @ SignatureAlgorithm::MlDsa(MldsaAlgorithm::ExternalMu87) => {
                let secret = hkdf_get_priv_key(alg, cdi, label, info)?;
                let kp = MlDsa87::key_gen_internal(
                    secret
                        .as_slice()
                        .try_into()
                        .map_err(|_| RUSTCRYPTO_ML_DSA_ERROR)?,
                );
                let verifying = kp.verifying_key();
                let encoded_key = verifying.encode();
                Ok((
                    RustCryptoPrivKey(secret),
                    PubKey::MlDsa(
                        MldsaPublicKey::read_from_bytes(encoded_key.as_bytes())
                            .map_err(|_| RUSTCRYPTO_ML_DSA_ERROR)?,
                    ),
                ))
            }
        }
    }
}

pub struct RustCryptoPrivKey(Vec<u8>);

impl<S: SignatureType, D: DigestType> Crypto for RustCryptoImpl<S, D> {
    type Cdi = Vec<u8>;
    type Hasher<'c>
        = RustCryptoHasher<D>
    where
        Self: 'c;
    type PrivKey = RustCryptoPrivKey;

    fn hash_initialize(&mut self) -> Result<Self::Hasher<'_>, CryptoError> {
        let hasher = match D::DIGEST_ALGORITHM {
            DigestAlgorithm::Sha256 => RustCryptoHasher {
                hasher: Box::new(Sha256::default()),
                _alg: Default::default(),
            },
            DigestAlgorithm::Sha384 => RustCryptoHasher {
                hasher: Box::new(Sha384::default()),
                _alg: Default::default(),
            },
        };
        Ok(hasher)
    }

    fn rand_bytes(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        StdRng::fill_bytes(&mut self.rng, dst);
        Ok(())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_cdi(&mut self, measurement: &Digest, info: &[u8]) -> Result<Self::Cdi, CryptoError> {
        hkdf_derive_cdi(S::SIGNATURE_ALGORITHM, measurement, info)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_exported_cdi(
        &mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<ExportedCdiHandle, CryptoError> {
        let cdi = hkdf_derive_cdi(S::SIGNATURE_ALGORITHM, measurement, info)?;

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
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, PubKey), CryptoError> {
        self.derive_key_pair_inner(cdi, label, info)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_key_pair_exported(
        &mut self,
        exported_handle: &ExportedCdiHandle,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, PubKey), CryptoError> {
        let cdi = {
            let mut cdi = None;
            for (stored_cdi, stored_handle) in self.export_cdi_slots.iter() {
                if stored_handle == exported_handle {
                    cdi = Some(stored_cdi.clone());
                }
            }
            cdi.ok_or(CryptoError::InvalidExportedCdiHandle)
        }?;
        self.derive_key_pair_inner(&cdi, label, info)
    }

    fn sign_with_alias(&mut self, digest: &Digest) -> Result<super::Signature, CryptoError> {
        match S::SIGNATURE_ALGORITHM {
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
                let signing_key = p256::ecdsa::SigningKey::from_sec1_pem(include_str!(concat!(
                    env!("OUT_DIR"),
                    "/alias_priv_256.pem"
                )))?;
                let sig: p256::ecdsa::Signature = signing_key.sign_prehash(digest.as_slice())?;
                Ok(EcdsaSig::from(sig).into())
            }
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
                let signing_key = p384::ecdsa::SigningKey::from_sec1_pem(include_str!(concat!(
                    env!("OUT_DIR"),
                    "/alias_priv_384.pem"
                )))?;
                let sig: p384::ecdsa::Signature = signing_key.sign_prehash(digest.as_slice())?;
                Ok(EcdsaSig::from(sig).into())
            }
            #[cfg(feature = "ml-dsa")]
            SignatureAlgorithm::MlDsa(MldsaAlgorithm::ExternalMu87) => {
                let ml_dsa_secret = KeyPair::<MlDsa87>::from_pkcs8_pem(include_str!(concat!(
                    env!("OUT_DIR"),
                    "/alias_priv_mldsa_87.pem"
                )))?;
                let sig = ml_dsa_secret.signing_key().sign(digest.as_slice());
                let sig = sig.encode();
                Ok(super::Signature::MlDsa(MldsaSignature::read_from_bytes(
                    sig.as_slice(),
                )?))
            }
        }
    }

    fn sign_with_derived(
        &mut self,
        digest: &Digest,
        priv_key: &Self::PrivKey,
        _pub_key: &PubKey,
    ) -> Result<super::Signature, CryptoError> {
        match S::SIGNATURE_ALGORITHM {
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
                let sig: p256::ecdsa::Signature =
                    p256::ecdsa::SigningKey::from_slice(priv_key.0.as_slice())?
                        .sign_prehash(digest.as_slice())?;
                Ok(EcdsaSig::from(sig).into())
            }
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
                let sig: p384::ecdsa::Signature =
                    p384::ecdsa::SigningKey::from_slice(priv_key.0.as_slice())?
                        .sign_prehash(digest.as_slice())?;
                Ok(EcdsaSig::from(sig).into())
            }
            #[cfg(feature = "ml-dsa")]
            SignatureAlgorithm::MlDsa(MldsaAlgorithm::ExternalMu87) => {
                let ml_dsa_secret =
                    MlDsa87::key_gen_internal(priv_key.0.as_slice().try_into().unwrap());
                let sig = ml_dsa_secret.signing_key().sign(digest.as_slice());
                let sig = sig.encode();
                Ok(super::Signature::MlDsa(MldsaSignature::read_from_bytes(
                    sig.as_slice(),
                )?))
            }
        }
    }
}
