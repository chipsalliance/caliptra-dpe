// Licensed under the Apache-2.0 license

use crate::{AlgLen, Crypto, CryptoError, Hasher};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::Private,
};
use openssl_kdf::{perform_kdf, KdfArgument, KdfKbMode, KdfMacType, KdfType};

pub struct OpensslHasher(openssl::hash::Hasher);

impl Hasher for OpensslHasher {
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        self.0
            .update(bytes)
            .map_err(|_| CryptoError::CryptoLibError)
    }

    fn finish(mut self, digest: &mut [u8]) -> Result<(), CryptoError> {
        digest.copy_from_slice(&self.0.finish().map_err(|_| CryptoError::CryptoLibError)?);
        Ok(())
    }
}

pub struct OpensslCrypto;

impl OpensslCrypto {
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

    fn get_priv_byes(algs: AlgLen) -> Result<Vec<u8>, CryptoError> {
        let priv_bytes = vec![0u8; algs.size()];
        let mut priv_digest = vec![0u8; algs.size()];
        Self::hash(algs, &priv_bytes, &mut priv_digest)?;
        Ok(priv_digest)
    }

    pub fn derive_ecdsa_key(
        algs: AlgLen,
        cdi: &<OpensslCrypto as Crypto>::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> EcKey<Private> {
        let nid = Self::get_curve(algs);
        let md = Self::get_digest(algs);
        let args = [
            &KdfArgument::KbMode(KdfKbMode::Counter),
            &KdfArgument::Mac(KdfMacType::Hmac(md)),
            &KdfArgument::KbInfo(label),
            &KdfArgument::Salt(info),
            &KdfArgument::Key(cdi),
        ];

        // Generate key
        let priv_bn = BigNum::from_slice(
            perform_kdf(KdfType::KeyBased, &args, md.size())
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        let group = EcGroup::from_curve_name(nid).unwrap();

        let mut pub_point = EcPoint::new(&group).unwrap();
        let bn_ctx = BigNumContext::new().unwrap();
        pub_point.mul_generator(&group, &priv_bn, &bn_ctx).unwrap();

        EcKey::from_private_components(&group, &priv_bn, &pub_point).unwrap()
    }
}

impl Crypto for OpensslCrypto {
    type Cdi = Vec<u8>;
    type Hasher = OpensslHasher;

    #[cfg(feature = "deterministic_rand")]
    fn rand_bytes(dst: &mut [u8]) -> Result<(), CryptoError> {
        for (i, char) in dst.iter_mut().enumerate() {
            *char = (i + 1) as u8;
        }
        Ok(())
    }

    #[cfg(not(feature = "deterministic_rand"))]
    fn rand_bytes(dst: &mut [u8]) -> Result<(), CryptoError> {
        openssl::rand::rand_bytes(dst).map_err(|_| CryptoError::CryptoLibError)
    }

    fn hash_initialize(algs: AlgLen) -> Result<Self::Hasher, CryptoError> {
        let md = Self::get_digest(algs);
        Ok(OpensslHasher(
            openssl::hash::Hasher::new(md).map_err(|_| CryptoError::CryptoLibError)?,
        ))
    }

    fn derive_cdi(
        algs: AlgLen,
        measurement_digest: &[u8],
        info: &[u8],
    ) -> Result<Self::Cdi, CryptoError> {
        let md = Self::get_digest(algs);
        let args = [
            &KdfArgument::KbMode(KdfKbMode::Counter),
            &KdfArgument::Mac(KdfMacType::Hmac(md)),
            &KdfArgument::KbInfo(measurement_digest),
            &KdfArgument::Salt(info),
            &KdfArgument::Key(&measurement_digest),
        ];

        perform_kdf(KdfType::KeyBased, &args, md.size()).map_err(|_| CryptoError::CryptoLibError)
    }

    fn derive_ecdsa_pub(
        algs: AlgLen,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
        pub_x: &mut [u8],
        pub_y: &mut [u8],
    ) -> Result<(), CryptoError> {
        let nid = Self::get_curve(algs);

        // Generate public key
        let priv_key = Self::derive_ecdsa_key(algs, cdi, label, info);

        let group = EcGroup::from_curve_name(nid).unwrap();
        let mut bn_ctx = BigNumContext::new().unwrap();

        let mut x = BigNum::new().unwrap();
        let mut y = BigNum::new().unwrap();

        priv_key
            .public_key()
            .affine_coordinates(&group, &mut x, &mut y, &mut bn_ctx)
            .unwrap();

        pub_x.copy_from_slice(
            &x.to_vec_padded((group.order_bits() / 8).try_into().unwrap())
                .unwrap(),
        );
        pub_y.copy_from_slice(
            &y.to_vec_padded((group.order_bits() / 8).try_into().unwrap())
                .unwrap(),
        );
        Ok(())
    }

    fn ecdsa_sign_with_alias(
        algs: AlgLen,
        digest: &[u8],
        sig_r: &mut [u8],
        sig_s: &mut [u8],
    ) -> Result<(), CryptoError> {
        let nid = Self::get_curve(algs);
        let priv_bytes = Self::get_priv_byes(algs)?;
        let group = EcGroup::from_curve_name(nid).map_err(|_| CryptoError::CryptoLibError)?;
        let priv_bn =
            BigNum::from_slice(priv_bytes.as_slice()).map_err(|_| CryptoError::CryptoLibError)?;

        let mut pub_point = EcPoint::new(&group).map_err(|_| CryptoError::CryptoLibError)?;
        let bn_ctx = BigNumContext::new().map_err(|_| CryptoError::CryptoLibError)?;
        pub_point.mul_generator(&group, &priv_bn, &bn_ctx).unwrap();

        let ec_priv = EcKey::from_private_components(&group, &priv_bn, &pub_point)
            .map_err(|_| CryptoError::CryptoLibError)?;

        let sig =
            EcdsaSig::sign::<Private>(digest, &ec_priv).map_err(|_| CryptoError::CryptoLibError)?;
        sig_r.copy_from_slice(
            sig.r()
                .to_vec_padded((group.order_bits() / 8).try_into().unwrap())
                .unwrap()
                .as_slice(),
        );
        sig_s.copy_from_slice(
            sig.s()
                .to_vec_padded((group.order_bits() / 8).try_into().unwrap())
                .unwrap()
                .as_slice(),
        );
        Ok(())
    }

    fn ecdsa_sign_with_derived(
        algs: AlgLen,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
        digest: &[u8],
        sig_r: &mut [u8],
        sig_s: &mut [u8],
    ) -> Result<(), CryptoError> {
        let nid = Self::get_curve(algs);
        let priv_key = Self::derive_ecdsa_key(algs, cdi, label, info);
        let group = EcGroup::from_curve_name(nid).unwrap();

        let sig = EcdsaSig::sign::<Private>(digest, &priv_key).unwrap();
        sig_r.copy_from_slice(
            sig.r()
                .to_vec_padded((group.order_bits() / 8).try_into().unwrap())
                .unwrap()
                .as_slice(),
        );
        sig_s.copy_from_slice(
            sig.s()
                .to_vec_padded((group.order_bits() / 8).try_into().unwrap())
                .unwrap()
                .as_slice(),
        );
        Ok(())
    }

    fn get_ecdsa_alias_serial(algs: AlgLen, serial: &mut [u8]) -> Result<(), CryptoError> {
        let nid = Self::get_curve(algs);
        let priv_bytes = Self::get_priv_byes(algs)?;

        let group = EcGroup::from_curve_name(nid).map_err(|_| CryptoError::CryptoLibError)?;
        let priv_bn =
            BigNum::from_slice(priv_bytes.as_slice()).map_err(|_| CryptoError::CryptoLibError)?;

        let mut pub_point = EcPoint::new(&group).map_err(|_| CryptoError::CryptoLibError)?;
        let mut bn_ctx = BigNumContext::new().map_err(|_| CryptoError::CryptoLibError)?;
        pub_point.mul_generator(&group, &priv_bn, &bn_ctx).unwrap();

        let mut x = BigNum::new().map_err(|_| CryptoError::CryptoLibError)?;
        let mut y = BigNum::new().map_err(|_| CryptoError::CryptoLibError)?;
        pub_point
            .affine_coordinates(&group, &mut x, &mut y, &mut bn_ctx)
            .map_err(|_| CryptoError::CryptoLibError)?;

        Self::get_pubkey_serial(
            algs,
            x.to_vec_padded((group.order_bits() / 8).try_into().unwrap())
                .unwrap()
                .as_slice(),
            y.to_vec_padded((group.order_bits() / 8).try_into().unwrap())
                .unwrap()
                .as_slice(),
            serial,
        )
    }
}
