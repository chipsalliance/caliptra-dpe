/*++
Licensed under the Apache-2.0 license.
Abstract:
    Generic trait definition of Cryptographic functions.
--*/

use crate::{DigestAlgorithm, DigestType, SignatureAlgorithm, SignatureType};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
use zeroize::ZeroizeOnDrop;

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable, ZeroizeOnDrop)]
#[repr(C)]
pub struct EcdsaPub<const K: usize> {
    pub x: [u8; K],
    pub y: [u8; K],
}

impl<const K: usize> EcdsaPub<K> {
    pub fn from_slice(x: &[u8; K], y: &[u8; K]) -> Self {
        let mut key = Self::default();
        key.x.clone_from_slice(x);
        key.y.clone_from_slice(y);
        key
    }

    pub fn as_slice(&self) -> (&[u8; K], &[u8; K]) {
        (&self.x, &self.y)
    }

    pub const fn curve_size(&self) -> usize {
        K
    }
}

impl<const K: usize> Default for EcdsaPub<K> {
    fn default() -> Self {
        Self {
            x: [0; K],
            y: [0; K],
        }
    }
}

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable, ZeroizeOnDrop)]
#[repr(C)]
pub struct EcdsaSig<const K: usize> {
    pub r: [u8; K],
    pub s: [u8; K],
}

impl<const K: usize> EcdsaSig<K> {
    pub fn from_slice(r: &[u8; K], s: &[u8; K]) -> Self {
        let mut key = Self::default();
        key.r.clone_from_slice(r);
        key.s.clone_from_slice(s);
        key
    }

    pub fn as_slice(&self) -> (&[u8; K], &[u8; K]) {
        (&self.r, &self.s)
    }

    pub const fn curve_size(&self) -> usize {
        K
    }
}

impl<const K: usize> Default for EcdsaSig<K> {
    fn default() -> Self {
        Self {
            r: [0; K],
            s: [0; K],
        }
    }
}

pub mod curve_256 {

    use super::*;

    /// Marker type to statically check conversions.
    #[derive(Clone)]
    pub struct Curve256;
    pub const CURVE_SIZE: usize = 256 / 8;

    pub type EcdsaPub256 = EcdsaPub<CURVE_SIZE>;
    pub type EcdsaSignature256 = EcdsaSig<CURVE_SIZE>;

    impl SignatureType for Curve256 {
        const SIGNATURE_ALGORITHM: SignatureAlgorithm =
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256);
    }

    impl DigestType for Curve256 {
        const DIGEST_ALGORITHM: DigestAlgorithm = DigestAlgorithm::Sha256;
    }
}

pub mod curve_384 {
    use super::*;

    /// Marker type to statically check conversions.
    #[derive(Clone)]
    pub struct Curve384;
    pub const CURVE_SIZE: usize = 384 / 8;

    pub type EcdsaPub384 = EcdsaPub<CURVE_SIZE>;
    pub type EcdsaSignature384 = EcdsaSig<CURVE_SIZE>;

    impl SignatureType for Curve384 {
        const SIGNATURE_ALGORITHM: SignatureAlgorithm =
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384);
    }

    impl DigestType for Curve384 {
        const DIGEST_ALGORITHM: DigestAlgorithm = DigestAlgorithm::Sha384;
    }
}

#[derive(Debug, Clone, Copy)]
pub enum EcdsaAlgorithm {
    Bit256,
    Bit384,
}

impl EcdsaAlgorithm {
    pub const fn curve_size(self) -> usize {
        match self {
            EcdsaAlgorithm::Bit256 => 256 / 8,
            EcdsaAlgorithm::Bit384 => 384 / 8,
        }
    }
}

#[derive(Clone)]
pub enum EcdsaPubKey {
    Ecdsa256(curve_256::EcdsaPub256),
    Ecdsa384(curve_384::EcdsaPub384),
}

impl From<curve_256::EcdsaPub256> for EcdsaPubKey {
    fn from(key: curve_256::EcdsaPub256) -> Self {
        Self::Ecdsa256(key)
    }
}

impl From<curve_384::EcdsaPub384> for EcdsaPubKey {
    fn from(key: curve_384::EcdsaPub384) -> Self {
        Self::Ecdsa384(key)
    }
}

impl EcdsaPubKey {
    pub fn as_slice(&self) -> (&[u8], &[u8]) {
        match self {
            Self::Ecdsa256(key) => {
                let (x, y) = key.as_slice();
                (x.as_slice(), y.as_slice())
            }
            Self::Ecdsa384(key) => {
                let (x, y) = key.as_slice();
                (x.as_slice(), y.as_slice())
            }
        }
    }

    pub fn curve_size(&self) -> usize {
        match self {
            Self::Ecdsa256(_) => curve_256::CURVE_SIZE,
            Self::Ecdsa384(_) => curve_384::CURVE_SIZE,
        }
    }
}

#[derive(Clone)]
pub enum EcdsaSignature {
    Ecdsa256(curve_256::EcdsaSignature256),
    Ecdsa384(curve_384::EcdsaSignature384),
}

impl EcdsaSignature {
    pub fn as_slice(&self) -> (&[u8], &[u8]) {
        match self {
            Self::Ecdsa256(sig) => {
                let (r, s) = sig.as_slice();
                (r.as_slice(), s.as_slice())
            }
            Self::Ecdsa384(sig) => {
                let (r, s) = sig.as_slice();
                (r.as_slice(), s.as_slice())
            }
        }
    }

    pub fn curve_size(&self) -> usize {
        match self {
            Self::Ecdsa256(key) => key.curve_size(),
            Self::Ecdsa384(key) => key.curve_size(),
        }
    }
}

impl From<curve_256::EcdsaSignature256> for EcdsaSignature {
    fn from(sig: curve_256::EcdsaSignature256) -> Self {
        Self::Ecdsa256(sig)
    }
}

impl From<curve_384::EcdsaSignature384> for EcdsaSignature {
    fn from(sig: curve_384::EcdsaSignature384) -> Self {
        Self::Ecdsa384(sig)
    }
}
