// Licensed under the Apache-2.0 license

//! Helper routines for doing common DPE crypto operations
//!
//! This is intended to implement the DPE Crypto trait in the DPE simulator
//! and unit tests. Because it is used in the tests of the dpe crate, this
//! crate cannot directly implement the Crypto trait (since that would require
//! depending on the DPE crate).

use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcPoint},
    error::ErrorStack,
    hash::{hash, MessageDigest},
    nid::Nid,
};
use openssl_kdf::{perform_kdf, KdfArgument, KdfKbMode, KdfMacType, KdfType};
use std::vec::Vec;

pub struct EccPoint {
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

pub struct OpensslHasher {
    hasher: openssl::hash::Hasher,
}

impl OpensslHasher {
    pub fn new(md: MessageDigest) -> Result<OpensslHasher, ErrorStack> {
        Ok(OpensslHasher { hasher: openssl::hash::Hasher::new(md)? })
    }

    pub fn update(&mut self, bytes: &[u8]) -> Result<(), ErrorStack> {
        self.hasher
            .update(bytes)
    }

    pub fn finish(mut self, digest: &mut [u8]) -> Result<(), ErrorStack> {
        digest.copy_from_slice(
            &self
                .hasher
                .finish()?,
        );
        Ok(())
    }
}

/// Uses known values for outputs to simulate operations that can be easily checked in tests.
pub struct OpensslCrypto;

impl OpensslCrypto {
    /// Generate random bytes to fill `dst`
    pub fn rand_bytes(dst: &mut [u8]) -> Result<(), ErrorStack> {
        openssl::rand::rand_bytes(dst)
    }

    /// Compute a hash over `bytes` and write to `digest`
    pub fn hash(bytes: &[u8], digest: &mut [u8], md: MessageDigest) -> Result<(), ErrorStack> {
        digest.copy_from_slice(&hash(md, bytes)?);
        Ok(())
    }

    /// Use SP800-108 HMAC-CTR KDF to derive a CDI
    pub fn derive_cdi(
        base_cdi: Vec<u8>,
        context: &[u8],
        info: &[u8],
        md: MessageDigest,
    ) -> Result<Vec<u8>, ErrorStack> {
        let args = [
            &KdfArgument::KbMode(KdfKbMode::Counter),
            &KdfArgument::Mac(KdfMacType::Hmac(md)),
            &KdfArgument::KbInfo(context),
            &KdfArgument::Salt(info),
            &KdfArgument::Key(&base_cdi),
        ];

        Ok(perform_kdf(KdfType::KeyBased, &args, md.size()).unwrap())
    }

    /// Use SP800-108 HMAC-CTR KDF to derive a private key and return the
    /// corresponding public key
    pub fn derive_ecdsa_pub(
        cdi: &Vec<u8>,
        label: &[u8],
        info: &[u8],
        md: MessageDigest,
        nid: Nid,
    ) -> Result<EccPoint, ErrorStack> {
        let args = [
            &KdfArgument::KbMode(KdfKbMode::Counter),
            &KdfArgument::Mac(KdfMacType::Hmac(md)),
            &KdfArgument::KbInfo(label),
            &KdfArgument::Salt(info),
            &KdfArgument::Key(cdi),
        ];

        // Generate public key
        let priv_bn = BigNum::from_slice(
            perform_kdf(KdfType::KeyBased, &args, md.size())
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        let group = EcGroup::from_curve_name(nid).unwrap();

        let mut pub_point = EcPoint::new(&group).unwrap();
        let mut bn_ctx = BigNumContext::new().unwrap();
        pub_point
            .mul_generator(&group, &priv_bn, &mut bn_ctx)
            .unwrap();

        let mut x = BigNum::new().unwrap();
        let mut y = BigNum::new().unwrap();
        pub_point
            .affine_coordinates(&group, &mut x, &mut y, &mut bn_ctx)
            .unwrap();

        Ok(EccPoint {
            x: x.to_vec_padded((group.order_bits() / 8).try_into().unwrap())
                .unwrap(),
            y: y.to_vec_padded((group.order_bits() / 8).try_into().unwrap())
                .unwrap(),
        })
    }
}
