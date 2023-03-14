/*++
Licensed under the Apache-2.0 license.
Abstract:
    Generic trait definition of Cryptographic functions.
--*/

use crate::{response::DpeErrorCode, DpeProfile, DPE_PROFILE};
use core::mem::size_of;

// An ECDSA signature
pub struct EcdsaSignature {
    pub(crate) r: [u8; DPE_PROFILE.get_ecc_int_size()],
    pub(crate) s: [u8; DPE_PROFILE.get_ecc_int_size()],
}

// An ECDSA public key
pub struct EcdsaPub {
    pub x: [u8; DPE_PROFILE.get_ecc_int_size()],
    pub y: [u8; DPE_PROFILE.get_ecc_int_size()],
}

impl EcdsaPub {
    pub fn serialize(&self, dst: &mut [u8]) -> Result<usize, DpeErrorCode> {
        if dst.len() < size_of::<Self>() {
            return Err(DpeErrorCode::InternalError);
        }

        let mut offset: usize = 0;
        dst[offset..offset + self.x.len()].copy_from_slice(&self.x);
        offset += self.x.len();
        dst[offset..offset + self.y.len()].copy_from_slice(&self.y);
        offset += self.y.len();

        Ok(offset)
    }
}

impl Default for EcdsaPub {
    fn default() -> EcdsaPub {
        EcdsaPub {
            x: [0; DPE_PROFILE.get_ecc_int_size()],
            y: [0; DPE_PROFILE.get_ecc_int_size()],
        }
    }
}

pub trait Crypto {
    type Cdi;

    /// Fills the buffer with random values.
    ///
    /// # Arguments
    ///
    /// * `dst` - The buffer to be filled.
    fn rand_bytes(dst: &mut [u8]) -> Result<(), DpeErrorCode>;

    /// Cryptographically hashes the given buffer.
    ///
    /// # Arguments
    ///
    /// * `profile` - Which profile is being used. This will tell the platform which algorithm to
    ///   use.
    /// * `bytes` - Value to be hashed.
    /// * `digest` - Where the computed digest should be written.
    fn hash(profile: DpeProfile, bytes: &[u8], digest: &mut [u8]) -> Result<(), DpeErrorCode>;

    /// Derive a CDI based on the current base CDI and measurements.
    ///
    /// # Arguments
    ///
    /// * `profile` - Which profile is being used. This will tell the platform
    ///   which algorithm to use
    /// * `measurement_digest` - A digest of the measurements which should be
    ///   used for CDI derivation
    /// * `info` - Caller-supplied info string to use in CDI derivation
    fn derive_cdi(
        profile: DpeProfile,
        measurement_digest: &[u8],
        info: &[u8],
    ) -> Result<Self::Cdi, DpeErrorCode>;

    /// Derives an ECDSA keypair from `cdi` and returns the public key
    ///
    /// # Arguments
    ///
    /// * `profile` - Which profile is being used. This will tell the platform
    ///    which algorithm to use
    /// * `cdi` - CDI from which to derive the signing key
    /// * `label` - Caller-supplied label to use in asymmetric key derivation
    /// * `info` - Caller-supplied info string to use in asymmetric key derivation
    ///
    /// Returns a derived public key
    fn derive_ecdsa_pub(
        profile: DpeProfile,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<EcdsaPub, DpeErrorCode>;
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use openssl::{hash::MessageDigest, nid::Nid};
    use ossl_crypto::OpensslCrypto;
    use std::vec::Vec;

    /// Uses known values for outputs to simulate operations that can be easily checked in tests.
    pub struct DeterministicCrypto;

    impl DeterministicCrypto {
        fn get_digest(profile: &DpeProfile) -> MessageDigest {
            match profile {
                DpeProfile::P256Sha256 => MessageDigest::sha256(),
                DpeProfile::P384Sha384 => MessageDigest::sha384(),
            }
        }
    }

    impl Crypto for DeterministicCrypto {
        type Cdi = Vec<u8>;

        /// Uses incrementing values for each byte to ensure tests are
        /// deterministic
        fn rand_bytes(dst: &mut [u8]) -> Result<(), DpeErrorCode> {
            for (i, char) in dst.iter_mut().enumerate() {
                *char = (i + 1) as u8;
            }
            Ok(())
        }

        fn hash(profile: DpeProfile, bytes: &[u8], digest: &mut [u8]) -> Result<(), DpeErrorCode> {
            let md = Self::get_digest(&profile);
            OpensslCrypto::hash(bytes, digest, md).map_err(|_| DpeErrorCode::InternalError)
        }

        fn derive_cdi(
            profile: DpeProfile,
            measurement_digest: &[u8],
            info: &[u8],
        ) -> Result<Self::Cdi, DpeErrorCode> {
            let md = Self::get_digest(&profile);
            let base_cdi = vec![0u8; profile.get_cdi_size()];

            OpensslCrypto::derive_cdi(base_cdi, measurement_digest, info, md)
                .map_err(|_| DpeErrorCode::InternalError)
        }

        fn derive_ecdsa_pub(
            profile: DpeProfile,
            cdi: &Self::Cdi,
            label: &[u8],
            info: &[u8],
        ) -> Result<EcdsaPub, DpeErrorCode> {
            let md = Self::get_digest(&profile);
            let nid = match profile {
                DpeProfile::P256Sha256 => Nid::X9_62_PRIME256V1,
                DpeProfile::P384Sha384 => Nid::SECP384R1,
            };

            let point = OpensslCrypto::derive_ecdsa_pub(cdi, label, info, md, nid)
                .map_err(|_| DpeErrorCode::InternalError)?;

            let mut pub_out = EcdsaPub::default();
            pub_out.x.copy_from_slice(point.x.as_slice());
            pub_out.y.copy_from_slice(point.y.as_slice());
            Ok(pub_out)
        }
    }
}
