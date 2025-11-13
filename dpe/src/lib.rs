/*++
Licensed under the Apache-2.0 license.

Abstract:
    DPE Library Crate.
--*/
#![cfg_attr(not(test), no_std)]

pub use dpe_instance::DpeInstance;
pub use state::{DpeFlags, State};

use zeroize::Zeroize;

pub mod commands;
pub mod context;
pub mod dpe_instance;
pub mod response;
mod state;
pub mod support;
pub mod validation;

#[cfg(not(feature = "disable_internal_info"))]
use core::mem::size_of;
#[cfg(not(feature = "disable_internal_info"))]
use response::GetProfileResp;
pub mod tci;
pub mod x509;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};

pub use crypto::{ecdsa::EcdsaAlgorithm, ExportedCdiHandle, MAX_EXPORTED_CDI_SIZE};

// Max cert size returned by CertifyKey
const MAX_CERT_SIZE: usize = 7872;
#[cfg(not(feature = "arbitrary_max_handles"))]
pub const MAX_HANDLES: usize = 24;
#[cfg(feature = "arbitrary_max_handles")]
include!(concat!(env!("OUT_DIR"), "/arbitrary_max_handles.rs"));

const CURRENT_PROFILE_MAJOR_VERSION: u16 = 0;
const CURRENT_PROFILE_MINOR_VERSION: u16 = 13;

#[cfg(not(feature = "disable_internal_info"))]
const INTERNAL_INPUT_INFO_SIZE: usize = size_of::<GetProfileResp>() + size_of::<u32>();

/// A type with u8 backing memory but bool semantics
/// This is needed to safely serialize booleans in the persisted DPE state
/// using zerocopy.
#[derive(
    Default, IntoBytes, FromBytes, Copy, Clone, PartialEq, Eq, Zeroize, Immutable, KnownLayout,
)]
#[repr(C, align(1))]
pub struct U8Bool {
    pub val: u8,
}

impl U8Bool {
    pub const fn new(val: bool) -> Self {
        Self { val: val as u8 }
    }

    pub fn get(&self) -> bool {
        self.val != 0
    }
}

impl From<bool> for U8Bool {
    fn from(item: bool) -> Self {
        Self { val: item as u8 }
    }
}

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, IntoBytes, TryFromBytes, KnownLayout, Immutable, Zeroize,
)]
#[repr(u32)]
pub enum DpeProfile {
    // Note: Min profiles (1 & 2) are not supported by this implementation
    P256Sha256 = 3,
    P384Sha384 = 4,
    #[cfg(feature = "ml-dsa")]
    Mldsa87ExternalMu = 5, // TODO(clundin): Added this to get past compiler / feature flags. We
                           // will want a real solution here.
}

impl DpeProfile {
    pub const fn tci_size(&self) -> usize {
        match self {
            DpeProfile::P256Sha256 => 32,
            DpeProfile::P384Sha384 => 48,
            #[cfg(feature = "ml-dsa")]
            DpeProfile::Mldsa87ExternalMu => 48,
        }
    }
    pub const fn ecc_int_size(&self) -> usize {
        self.tci_size()
    }
    pub const fn hash_size(&self) -> usize {
        self.tci_size()
    }
    pub const fn alg(&self) -> crypto::SignatureAlgorithm {
        match self {
            DpeProfile::P256Sha256 => crypto::SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256),
            DpeProfile::P384Sha384 => crypto::SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384),
            #[cfg(feature = "ml-dsa")]
            DpeProfile::Mldsa87ExternalMu => {
                crypto::SignatureAlgorithm::MlDsa(crypto::ml_dsa::MldsaAlgorithm::ExternalMu87)
            }
        }
    }
}

#[cfg(feature = "p256")]
pub const DPE_PROFILE: DpeProfile = DpeProfile::P256Sha256;

#[cfg(feature = "p384")]
pub const DPE_PROFILE: DpeProfile = DpeProfile::P384Sha384;

#[cfg(feature = "ml-dsa")]
pub const DPE_PROFILE: DpeProfile = DpeProfile::Mldsa87ExternalMu;

// Recursive macro that does a union of all the flags passed to it. This is
// const and looks about as nice as using the | operator.
#[macro_export]
macro_rules! bitflags_join {
    // If input is just one element, output it
    ($x: expr) => ($x);
    // In input is 1 or more comma separated things, take the first one, and call
    // .union(bitflags_join!(remaining))
    ($x: expr, $($z: expr),+) => ($x.union(bitflags_join!($($z),*)));
}
