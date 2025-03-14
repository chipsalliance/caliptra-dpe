// Licensed under the Apache-2.0 license

use crate::{
    hkdf::*, AlgLen, Crypto, CryptoBuf, CryptoError, Digest, EcdsaPub, ExportedCdiHandle, Hasher,
    MAX_EXPORTED_CDI_SIZE,
};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::Private,
};
#[cfg(feature = "deterministic_rand")]
use rand::{rngs::StdRng, RngCore, SeedableRng};

impl From<ErrorStack> for CryptoError {
    fn from(e: ErrorStack) -> Self {
        // Just return the top error on the stack
        let s = e.errors();
        let e_code = if !s.is_empty() {
            s[0].code().try_into().unwrap_or(0u32)
        } else {
            0u32
        };

        CryptoError::CryptoLibError(e_code)
    }
}

pub struct OpensslHasher(openssl::hash::Hasher);

impl Hasher for OpensslHasher {
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        Ok(self.0.update(bytes)?)
    }

    fn finish(mut self) -> Result<Digest, CryptoError> {
        Digest::new(&self.0.finish()?)
    }
}

// Currently only supports one CDI handle but in the future we may want to support multiple.
const MAX_CDI_HANDLES: usize = 1;

#[cfg(feature = "deterministic_rand")]
pub struct OpensslCrypto {
    rng: StdRng,
    export_cdi_slots: Vec<(<OpensslCrypto as Crypto>::Cdi, ExportedCdiHandle)>,
}

#[cfg(not(feature = "deterministic_rand"))]
pub struct OpensslCrypto {
    export_cdi_slots: Vec<(<OpensslCrypto as Crypto>::Cdi, ExportedCdiHandle)>,
}

impl OpensslCrypto {
    #[cfg(feature = "deterministic_rand")]
    pub fn new() -> Self {
        const SEED: [u8; 32] = [1; 32];
        let seeded_rng = StdRng::from_seed(SEED);
        Self {
            rng: seeded_rng,
            export_cdi_slots: Vec::new(),
        }
    }

    #[cfg(not(feature = "deterministic_rand"))]
    pub fn new() -> Self {
        Self {
            export_cdi_slots: Vec::new(),
        }
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

    fn derive_key_pair_inner(
        &mut self,
        algs: AlgLen,
        cdi: &<OpensslCrypto as Crypto>::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<(<OpensslCrypto as Crypto>::PrivKey, EcdsaPub), CryptoError> {
        let priv_key = hkdf_get_priv_key(algs, cdi, label, info)?;

        let ec_priv_key = OpensslCrypto::ec_key_from_priv_key(algs, &priv_key)?;
        let nid = OpensslCrypto::get_curve(algs);

        let group = EcGroup::from_curve_name(nid).unwrap();
        let mut bn_ctx = BigNumContext::new().unwrap();

        let mut x = BigNum::new().unwrap();
        let mut y = BigNum::new().unwrap();

        ec_priv_key
            .public_key()
            .affine_coordinates(&group, &mut x, &mut y, &mut bn_ctx)
            .unwrap();

        let x = CryptoBuf::new(&x.to_vec_padded(algs.size() as i32).unwrap()).unwrap();
        let y = CryptoBuf::new(&y.to_vec_padded(algs.size() as i32).unwrap()).unwrap();

        Ok((priv_key, EcdsaPub { x, y }))
    }
}

impl Default for OpensslCrypto {
    fn default() -> Self {
        Self::new()
    }
}

type OpensslCdi = Vec<u8>;

type OpensslPrivKey = CryptoBuf;

impl Crypto for OpensslCrypto {
    type Cdi = OpensslCdi;
    type Hasher<'c>
        = OpensslHasher
    where
        Self: 'c;
    type PrivKey = OpensslPrivKey;

    #[cfg(feature = "deterministic_rand")]
    fn rand_bytes(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        StdRng::fill_bytes(&mut self.rng, dst);
        Ok(())
    }

    #[cfg(not(feature = "deterministic_rand"))]
    fn rand_bytes(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        Ok(openssl::rand::rand_bytes(dst)?)
    }

    fn hash_initialize(&mut self, algs: AlgLen) -> Result<Self::Hasher<'_>, CryptoError> {
        let md = Self::get_digest(algs);
        Ok(OpensslHasher(openssl::hash::Hasher::new(md)?))
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_cdi(
        &mut self,
        algs: AlgLen,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<Self::Cdi, CryptoError> {
        let cdi = hkdf_derive_cdi(algs, measurement, info)?;
        Ok(cdi)
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
    ) -> Result<super::EcdsaSig, CryptoError> {
        let ec_priv: EcKey<Private> = match algs {
            AlgLen::Bit256 => EcKey::private_key_from_pem(include_bytes!(concat!(
                env!("OUT_DIR"),
                "/alias_priv_256.pem"
            )))
            .unwrap(),
            AlgLen::Bit384 => EcKey::private_key_from_pem(include_bytes!(concat!(
                env!("OUT_DIR"),
                "/alias_priv_384.pem"
            )))
            .unwrap(),
        };

        let sig = EcdsaSig::sign::<Private>(digest.bytes(), &ec_priv)?;

        let r = CryptoBuf::new(&sig.r().to_vec_padded(algs.size() as i32).unwrap()).unwrap();
        let s = CryptoBuf::new(&sig.s().to_vec_padded(algs.size() as i32).unwrap()).unwrap();

        Ok(super::EcdsaSig { r, s })
    }

    fn ecdsa_sign_with_derived(
        &mut self,
        algs: AlgLen,
        digest: &Digest,
        priv_key: &Self::PrivKey,
        _pub_key: &EcdsaPub,
    ) -> Result<super::EcdsaSig, CryptoError> {
        let ec_priv_key = OpensslCrypto::ec_key_from_priv_key(algs, priv_key)?;
        let sig = EcdsaSig::sign::<Private>(digest.bytes(), &ec_priv_key).unwrap();

        let r = CryptoBuf::new(&sig.r().to_vec_padded(algs.size() as i32).unwrap()).unwrap();
        let s = CryptoBuf::new(&sig.s().to_vec_padded(algs.size() as i32).unwrap()).unwrap();

        Ok(super::EcdsaSig { r, s })
    }
}
