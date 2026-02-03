// Licensed under the Apache-2.0 license

use crate::{DigestAlgorithm, DigestType, SignatureAlgorithm, SignatureType};

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(Debug, Clone, Copy)]
pub enum MldsaAlgorithm {
    Mldsa87,
}

#[cfg(test)]
impl Default for MldsaAlgorithm {
    fn default() -> Self {
        Self::Mldsa87
    }
}

impl MldsaAlgorithm {
    pub const fn seed_size(self) -> usize {
        match self {
            Self::Mldsa87 => 32,
        }
    }
    pub const fn signature_size(self) -> usize {
        match self {
            Self::Mldsa87 => 4627,
        }
    }
    pub const fn public_key_size(self) -> usize {
        match self {
            Self::Mldsa87 => 2592,
        }
    }
    pub const fn private_key_size(self) -> usize {
        match self {
            Self::Mldsa87 => 4896,
        }
    }
    pub const fn external_mu_size(self) -> usize {
        match self {
            Self::Mldsa87 => 64,
        }
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct ExternalMu(pub [u8; MldsaAlgorithm::Mldsa87.external_mu_size()]);

impl SignatureType for ExternalMu {
    const SIGNATURE_ALGORITHM: SignatureAlgorithm =
        SignatureAlgorithm::Mldsa(MldsaAlgorithm::Mldsa87);
}

impl DigestType for ExternalMu {
    const DIGEST_ALGORITHM: DigestAlgorithm = DigestAlgorithm::Sha384;
}

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct MldsaPublicKey(pub [u8; MldsaAlgorithm::Mldsa87.public_key_size()]);

impl MldsaPublicKey {
    pub fn from_slice(pub_key: &[u8; MldsaAlgorithm::Mldsa87.public_key_size()]) -> Self {
        Self(*pub_key)
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct MldsaSignature(pub [u8; MldsaAlgorithm::Mldsa87.signature_size()]);

impl MldsaSignature {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}
