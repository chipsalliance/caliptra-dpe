// Licensed under the Apache-2.0 license

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(Debug, Clone, Copy)]
pub enum MldsaAlgorithm {
    ExternalMu87,
}

#[cfg(test)]
impl Default for MldsaAlgorithm {
    fn default() -> Self {
        Self::ExternalMu87
    }
}

impl MldsaAlgorithm {
    pub const fn seed_size(self) -> usize {
        match self {
            Self::ExternalMu87 => 32,
        }
    }
    pub const fn signature_size(self) -> usize {
        match self {
            Self::ExternalMu87 => 4627,
        }
    }
    pub const fn public_key_size(self) -> usize {
        match self {
            Self::ExternalMu87 => 2592,
        }
    }
    pub const fn private_key_size(self) -> usize {
        match self {
            Self::ExternalMu87 => 4896,
        }
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct ExternalMu(pub [u8; Self::SIZE]);

impl ExternalMu {
    const SIZE: usize = 64;
}

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct MldsaPublicKey(pub [u8; MldsaAlgorithm::ExternalMu87.public_key_size()]);

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct MldsaSignature(pub [u8; MldsaAlgorithm::ExternalMu87.signature_size()]);
