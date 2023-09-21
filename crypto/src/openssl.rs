// Licensed under the Apache-2.0 license

use crate::{AlgLen, Crypto, CryptoBuf, CryptoError, Digest, EcdsaPub, Hasher, HmacSig};
use hkdf::Hkdf;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
};
#[cfg(feature = "deterministic_rand")]
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sha2::{Sha256, Sha384};

pub struct OpensslHasher(openssl::hash::Hasher, AlgLen);

impl Hasher for OpensslHasher {
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        self.0
            .update(bytes)
            .map_err(|_| CryptoError::CryptoLibError)
    }

    fn finish(mut self) -> Result<Digest, CryptoError> {
        Digest::new(
            &self.0.finish().map_err(|_| CryptoError::CryptoLibError)?,
            self.1,
        )
    }
}

#[cfg(feature = "deterministic_rand")]
pub struct OpensslCrypto(StdRng);

#[cfg(not(feature = "deterministic_rand"))]
pub struct OpensslCrypto;

impl OpensslCrypto {
    #[cfg(feature = "deterministic_rand")]
    pub fn new() -> Self {
        const SEED: [u8; 32] = [1; 32];
        let seeded_rng = StdRng::from_seed(SEED);
        OpensslCrypto(seeded_rng)
    }

    #[cfg(not(feature = "deterministic_rand"))]
    pub fn new() -> Self {
        Self {}
    }

    fn get_digest(algs: AlgLen) -> MessageDigest {
        match algs {
            AlgLen::Bit256 => MessageDigest::sha256(),
            AlgLen::Bit384 => MessageDigest::sha384(),
        }
    }

    fn get_curve(algs: AlgLen) -> Nid {
        match algs {
            AlgLen::Bit256 => Nid::X9_62_PRIME256V1,
            AlgLen::Bit384 => Nid::SECP384R1,
        }
    }

    fn ec_key_from_priv_key(
        algs: AlgLen,
        priv_key: &OpensslPrivKey,
    ) -> Result<EcKey<Private>, ErrorStack> {
        let nid = Self::get_curve(algs);
        let group = EcGroup::from_curve_name(nid).unwrap();

        let mut pub_point = EcPoint::new(&group).unwrap();
        let bn_ctx = BigNumContext::new().unwrap();
        let priv_key_bn = &BigNum::from_slice(priv_key.bytes()).unwrap();
        pub_point
            .mul_generator(&group, priv_key_bn, &bn_ctx)
            .unwrap();

        EcKey::from_private_components(&group, priv_key_bn, &pub_point)
    }
}

type OpensslCdi = Vec<u8>;

type OpensslPrivKey = CryptoBuf;

impl Crypto for OpensslCrypto {
    type Cdi = OpensslCdi;
    type Hasher<'c> = OpensslHasher where Self: 'c;
    type PrivKey = OpensslPrivKey;

    #[cfg(feature = "deterministic_rand")]
    fn rand_bytes(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        StdRng::fill_bytes(&mut self.0, dst);
        Ok(())
    }

    #[cfg(not(feature = "deterministic_rand"))]
    fn rand_bytes(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        openssl::rand::rand_bytes(dst).map_err(|_| CryptoError::CryptoLibError)
    }

    fn hash_initialize(&mut self, algs: AlgLen) -> Result<Self::Hasher<'_>, CryptoError> {
        let md = Self::get_digest(algs);
        Ok(OpensslHasher(
            openssl::hash::Hasher::new(md).map_err(|_| CryptoError::CryptoLibError)?,
            algs,
        ))
    }

    fn derive_cdi(
        &mut self,
        algs: AlgLen,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<Self::Cdi, CryptoError> {
        match algs {
            AlgLen::Bit256 => {
                let hk = Hkdf::<Sha256>::new(Some(info), measurement.bytes());
                let mut cdi = [0u8; AlgLen::Bit256.size()];
                hk.expand(measurement.bytes(), &mut cdi)
                    .map_err(|_| CryptoError::CryptoLibError)?;

                Ok(cdi.to_vec())
            }
            AlgLen::Bit384 => {
                let hk = Hkdf::<Sha384>::new(Some(info), measurement.bytes());
                let mut cdi = [0u8; AlgLen::Bit384.size()];
                hk.expand(measurement.bytes(), &mut cdi)
                    .map_err(|_| CryptoError::CryptoLibError)?;

                Ok(cdi.to_vec())
            }
        }
    }

    fn derive_key_pair(
        &mut self,
        algs: AlgLen,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, EcdsaPub), CryptoError> {
        let priv_key = match algs {
            AlgLen::Bit256 => {
                let hk = Hkdf::<Sha256>::new(Some(info), cdi);
                let mut priv_key = [0u8; AlgLen::Bit256.size()];
                hk.expand(label, &mut priv_key)
                    .map_err(|_| CryptoError::CryptoLibError)?;

                Ok(CryptoBuf::new(&priv_key, algs).unwrap())
            }
            AlgLen::Bit384 => {
                let hk = Hkdf::<Sha384>::new(Some(info), cdi);
                let mut priv_key = [0u8; AlgLen::Bit384.size()];
                hk.expand(label, &mut priv_key)
                    .map_err(|_| CryptoError::CryptoLibError)?;

                Ok(CryptoBuf::new(&priv_key, algs).unwrap())
            }
        }?;

        let ec_priv_key = OpensslCrypto::ec_key_from_priv_key(algs, &priv_key)
            .map_err(|_| CryptoError::CryptoLibError)?;
        let nid = OpensslCrypto::get_curve(algs);

        let group = EcGroup::from_curve_name(nid).unwrap();
        let mut bn_ctx = BigNumContext::new().unwrap();

        let mut x = BigNum::new().unwrap();
        let mut y = BigNum::new().unwrap();

        ec_priv_key
            .public_key()
            .affine_coordinates(&group, &mut x, &mut y, &mut bn_ctx)
            .unwrap();

        let x = CryptoBuf::new(&x.to_vec_padded(algs.size() as i32).unwrap(), algs).unwrap();
        let y = CryptoBuf::new(&y.to_vec_padded(algs.size() as i32).unwrap(), algs).unwrap();

        Ok((priv_key, EcdsaPub { x, y }))
    }

    fn ecdsa_sign_with_alias(
        &mut self,
        algs: AlgLen,
        digest: &Digest,
    ) -> Result<super::EcdsaSig, CryptoError> {
        let pem = include_bytes!(concat!(env!("OUT_DIR"), "/alias_priv.pem"));
        let ec_priv: EcKey<Private> = EcKey::private_key_from_pem(pem).unwrap();

        let sig = EcdsaSig::sign::<Private>(digest.bytes(), &ec_priv)
            .map_err(|_| CryptoError::CryptoLibError)?;

        let r = CryptoBuf::new(&sig.r().to_vec_padded(algs.size() as i32).unwrap(), algs).unwrap();
        let s = CryptoBuf::new(&sig.s().to_vec_padded(algs.size() as i32).unwrap(), algs).unwrap();

        Ok(super::EcdsaSig { r, s })
    }

    fn ecdsa_sign_with_derived(
        &mut self,
        algs: AlgLen,
        digest: &Digest,
        priv_key: &Self::PrivKey,
        _pub_key: EcdsaPub,
    ) -> Result<super::EcdsaSig, CryptoError> {
        let ec_priv_key = OpensslCrypto::ec_key_from_priv_key(algs, priv_key)
            .map_err(|_| CryptoError::CryptoLibError)?;
        let sig = EcdsaSig::sign::<Private>(digest.bytes(), &ec_priv_key).unwrap();

        let r = CryptoBuf::new(&sig.r().to_vec_padded(algs.size() as i32).unwrap(), algs).unwrap();
        let s = CryptoBuf::new(&sig.s().to_vec_padded(algs.size() as i32).unwrap(), algs).unwrap();

        Ok(super::EcdsaSig { r, s })
    }

    fn hmac_sign_with_derived(
        &mut self,
        algs: AlgLen,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
        digest: &Digest,
    ) -> Result<HmacSig, CryptoError> {
        let (symmetric_key, _) = self.derive_key_pair(algs, cdi, label, info)?;
        let hmac_key = PKey::hmac(symmetric_key.bytes()).unwrap();

        let sha_size = Self::get_digest(algs);
        let mut signer = Signer::new(sha_size, &hmac_key).unwrap();
        signer.update(digest.bytes()).unwrap();
        let hmac = signer.sign_to_vec().unwrap();

        Ok(HmacSig::new(&hmac, algs).unwrap())
    }
}
