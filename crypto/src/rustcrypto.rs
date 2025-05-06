// Licensed under the Apache-2.0 license

use crate::{
    ecdsa::{
        curve_256::{Curve256, EcdsaPub256, EcdsaSignature256},
        curve_384::{Curve384, EcdsaPub384, EcdsaSignature384},
        EcdsaAlgorithm, EcdsaPubKey, EcdsaSignature,
    },
    hkdf::*,
    Crypto, CryptoEngine, CryptoError, Digest, DigestAlgorithm, DigestType, ExportedCdiHandle,
    ExportedPubKey, Hasher, SignatureAlgorithm, SignatureType, MAX_EXPORTED_CDI_SIZE,
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

impl TryFrom<Signature<NistP256>> for EcdsaSignature256 {
    type Error = CryptoError;

    fn try_from(value: Signature<NistP256>) -> Result<Self, Self::Error> {
        let mut r = [0; EcdsaAlgorithm::Bit256.curve_size()];
        let mut s = [0; EcdsaAlgorithm::Bit256.curve_size()];
        r.clone_from_slice(value.r().deref().to_bytes().as_slice());
        s.clone_from_slice(value.s().deref().to_bytes().as_slice());

        EcdsaSignature256::from_slice(&r, &s)
    }
}
impl TryFrom<Signature<NistP384>> for EcdsaSignature384 {
    type Error = CryptoError;

    fn try_from(value: Signature<NistP384>) -> Result<Self, Self::Error> {
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
impl CryptoEngine for Ecdsa256RustCrypto {}
impl SignatureType for Ecdsa256RustCrypto {
    const SIGNATURE_ALGORITHM: SignatureAlgorithm = Curve256::SIGNATURE_ALGORITHM;
}
impl DigestType for Ecdsa256RustCrypto {
    const DIGEST_ALGORITHM: DigestAlgorithm = crate::Sha256::DIGEST_ALGORITHM;
}

pub type Ecdsa384RustCrypto = RustCryptoImpl<Curve384, crate::Sha384>;
impl CryptoEngine for Ecdsa384RustCrypto {}
impl SignatureType for Ecdsa384RustCrypto {
    const SIGNATURE_ALGORITHM: SignatureAlgorithm = Curve384::SIGNATURE_ALGORITHM;
}

impl DigestType for Ecdsa384RustCrypto {
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
    ) -> Result<
        (
            <RustCryptoImpl<S, D> as Crypto>::PrivKey,
            <RustCryptoImpl<S, D> as Crypto>::PubKey,
        ),
        CryptoError,
    > {
        match S::SIGNATURE_ALGORITHM {
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
                let secret = hkdf_get_priv_key(
                    SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256),
                    cdi,
                    label,
                    info,
                )?;
                let signing = p256::ecdsa::SigningKey::from_slice(secret.as_slice())?;
                let verifying = p256::ecdsa::VerifyingKey::from(&signing);
                let point = verifying.to_encoded_point(false);

                let mut x = [0; EcdsaAlgorithm::Bit256.curve_size()];
                let mut y = [0; EcdsaAlgorithm::Bit256.curve_size()];
                x.clone_from_slice(point.x().ok_or(RUSTCRYPTO_ECDSA_ERROR)?.as_slice());
                y.clone_from_slice(point.y().ok_or(RUSTCRYPTO_ECDSA_ERROR)?.as_slice());

                Ok((
                    RustCryptoPrivKey(secret),
                    ExportedPubKey::Ecdsa(EcdsaPubKey::Ecdsa256(EcdsaPub256::from_slice(&x, &y)?)),
                ))
            }
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
                let secret = hkdf_get_priv_key(
                    SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384),
                    cdi,
                    label,
                    info,
                )?;
                let signing = p384::ecdsa::SigningKey::from_slice(secret.as_slice())?;
                let verifying = p384::ecdsa::VerifyingKey::from(&signing);
                let point = verifying.to_encoded_point(false);

                let mut x = [0; EcdsaAlgorithm::Bit384.curve_size()];
                let mut y = [0; EcdsaAlgorithm::Bit384.curve_size()];
                x.clone_from_slice(point.x().ok_or(RUSTCRYPTO_ECDSA_ERROR)?.as_slice());
                y.clone_from_slice(point.y().ok_or(RUSTCRYPTO_ECDSA_ERROR)?.as_slice());

                Ok((
                    RustCryptoPrivKey(secret),
                    ExportedPubKey::Ecdsa(EcdsaPubKey::Ecdsa384(EcdsaPub384::from_slice(&x, &y)?)),
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
    type PubKey = ExportedPubKey;

    fn hash_initialize(&mut self) -> Result<Self::Hasher<'_>, CryptoError> {
        let hasher = match S::SIGNATURE_ALGORITHM {
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => RustCryptoHasher {
                hasher: Box::new(Sha256::default()),
                _alg: Default::default(),
            },
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => RustCryptoHasher {
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
    ) -> Result<(Self::PrivKey, Self::PubKey), CryptoError> {
        self.derive_key_pair_inner(cdi, label, info)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_key_pair_exported(
        &mut self,
        exported_handle: &ExportedCdiHandle,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, Self::PubKey), CryptoError> {
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
                let sig: p256::ecdsa::Signature = signing_key.sign_prehash(digest.bytes())?;
                Ok(super::Signature::Ecdsa(EcdsaSignature::Ecdsa256(
                    sig.try_into()?,
                )))
            }
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
                let signing_key = p384::ecdsa::SigningKey::from_sec1_pem(include_str!(concat!(
                    env!("OUT_DIR"),
                    "/alias_priv_384.pem"
                )))?;
                let sig: p384::ecdsa::Signature = signing_key.sign_prehash(digest.bytes())?;
                Ok(super::Signature::Ecdsa(EcdsaSignature::Ecdsa384(
                    sig.try_into()?,
                )))
            }
        }
    }

    fn sign_with_derived(
        &mut self,
        digest: &Digest,
        priv_key: &Self::PrivKey,
        _pub_key: &Self::PubKey,
    ) -> Result<super::Signature, CryptoError> {
        match S::SIGNATURE_ALGORITHM {
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
                let sig: p256::ecdsa::Signature =
                    p256::ecdsa::SigningKey::from_slice(priv_key.0.as_slice())?
                        .sign_prehash(digest.bytes())?;
                Ok(super::Signature::Ecdsa(EcdsaSignature::Ecdsa256(
                    sig.try_into()?,
                )))
            }
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
                let sig: p384::ecdsa::Signature =
                    p384::ecdsa::SigningKey::from_slice(priv_key.0.as_slice())?
                        .sign_prehash(digest.bytes())?;
                Ok(super::Signature::Ecdsa(EcdsaSignature::Ecdsa384(
                    sig.try_into()?,
                )))
            }
        }
    }

    fn get_pubkey_serial(
        &mut self,
        pub_key: &ExportedPubKey,
        serial: &mut [u8],
    ) -> Result<(), CryptoError> {
        if serial.len() < D::DIGEST_ALGORITHM.size() {
            return Err(CryptoError::Size);
        }
        let mut hasher = self.hash_initialize()?;
        match S::SIGNATURE_ALGORITHM {
            SignatureAlgorithm::Ecdsa(_) => {
                let ExportedPubKey::Ecdsa(pub_key) = pub_key;
                let (x, y) = pub_key.as_slice()?;

                hasher.update(&[0x4u8])?;
                hasher.update(x)?;
                hasher.update(y)?;
            }
        }

        let digest = hasher.finish()?;
        let src = digest.bytes();
        //if serial.len() != src.len() * 2 {
        //    return Err(CryptoError::Size);
        //}

        let mut curr_idx = 0;
        const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";
        for &b in src {
            let h1 = (b >> 4) as usize;
            let h2 = (b & 0xF) as usize;
            if h1 >= HEX_CHARS.len()
                || h2 >= HEX_CHARS.len()
                || curr_idx >= serial.len()
                || curr_idx + 1 >= serial.len()
            {
                return Err(CryptoError::CryptoLibError(0));
            }
            serial[curr_idx] = HEX_CHARS[h1];
            serial[curr_idx + 1] = HEX_CHARS[h2];
            curr_idx += 2;
        }
        Ok(())
    }

    fn export_public_key(
        &self,
        pub_key: &Self::PubKey,
    ) -> Result<crate::ExportedPubKey, CryptoError> {
        Ok(pub_key.clone())
    }
}
