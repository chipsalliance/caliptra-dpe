/*++
Licensed under the Apache-2.0 license.

Abstract:
    DPE Library Crate.
--*/
#![cfg_attr(not(any(test, target_arch = "x86_64")), no_std)]

#[cfg(not(feature = "log"))]
#[allow(unused_macros)]
#[macro_use]
mod log_stub;
#[cfg(feature = "log")]
#[allow(unused_imports)]
#[macro_use(debug, error, info, trace, warn)]
extern crate log;

pub use dpe_instance::DpeInstance;
pub use operation_handle::OperationHandle;
pub use state::{DpeFlags, State};

use zeroize::Zeroize;

pub mod commands;
pub mod context;
pub mod dpe_instance;
mod operation_handle;
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

use crate::response::{DpeErrorCode, ResponseHdr};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};

pub use crypto::{ecdsa::EcdsaAlgorithm, ExportedCdiHandle, MAX_EXPORTED_CDI_SIZE};

// Max cert size returned by CertifyKey
#[cfg(feature = "ml-dsa")]
const MAX_CERT_SIZE: usize = 22 * 1024;
#[cfg(not(feature = "ml-dsa"))]
const MAX_CERT_SIZE: usize = 11 * 1024;
#[cfg(not(feature = "arbitrary_max_handles"))]
pub const MAX_HANDLES: usize = 64;
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
    Mldsa87 = 5, // TODO(clundin): Added this to get past compiler / feature flags. We
                 // will want a real solution here.
}

impl DpeProfile {
    pub const fn tci_size(&self) -> usize {
        match self {
            DpeProfile::P256Sha256 => 32,
            DpeProfile::P384Sha384 => 48,
            #[cfg(feature = "ml-dsa")]
            DpeProfile::Mldsa87 => 48,
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
            DpeProfile::Mldsa87 => {
                crypto::SignatureAlgorithm::MlDsa(crypto::ml_dsa::MldsaAlgorithm::Mldsa87)
            }
        }
    }
    pub fn key_context(&self) -> &[u8] {
        match self {
            DpeProfile::P256Sha256 | DpeProfile::P384Sha384 => b"ECC",
            #[cfg(feature = "ml-dsa")]
            DpeProfile::Mldsa87 => b"MLDSA",
        }
    }
}

impl From<DpeProfile> for u32 {
    fn from(item: DpeProfile) -> Self {
        item as u32
    }
}

#[cfg(feature = "p256")]
pub const TCI_SIZE: usize = 32;

#[cfg(any(feature = "p384", feature = "ml-dsa"))]
pub const TCI_SIZE: usize = 48;

#[cfg(feature = "p256")]
pub const HASH_SIZE: usize = 32;

#[cfg(any(feature = "p384", feature = "ml-dsa"))]
pub const HASH_SIZE: usize = 48;

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

// Copied from https://github.com/chipsalliance/caliptra-sw/tree/main/common/okref
// unfortunately we cannot depend on caliptra-okref directly due to dependency
// cycles. So we copy the relevant code here.
#[inline(always)]
pub(crate) fn okref<T, E: Copy>(r: &Result<T, E>) -> Result<&T, E> {
    match r {
        Ok(r) => Ok(r),
        Err(e) => Err(*e),
    }
}

#[inline(always)]
pub(crate) fn _okmutref<T, E: Copy>(r: &mut Result<T, E>) -> Result<&mut T, E> {
    match r {
        Ok(r) => Ok(r),
        Err(e) => Err(*e),
    }
}

#[inline(always)]
pub(crate) fn mutrefbytes<R: TryFromBytes + IntoBytes + KnownLayout>(
    resp: &mut [u8],
) -> Result<&mut R, DpeErrorCode> {
    let (resp, _) = R::try_mut_from_prefix(resp).map_err(|_| DpeErrorCode::InvalidMutRefBuf)?;
    Ok(resp)
}

#[inline(always)]
pub(crate) fn mutresp<R: TryFromBytes + IntoBytes + KnownLayout>(
    p: DpeProfile,
    resp: &mut [u8],
) -> Result<&mut R, DpeErrorCode> {
    // Give a default in the response header so it can parse correctly. More than likely the
    // buffer will be zeroized, but `try_from_prefix` can't parse a DPE profile from zero.
    resp.get_mut(..size_of::<ResponseHdr>())
        .ok_or(DpeErrorCode::InvalidResponseBuf)?
        .copy_from_slice(ResponseHdr::new(p, DpeErrorCode::UninitializedResponseHeader).as_bytes());
    mutrefbytes(resp)
}

#[cfg(test)]
pub(crate) mod tests {
    /// Convenience function to initialize logging for unit tests
    ///
    /// Since unit tests are not compiled and executed seperately,
    /// we have to ensure the initialization is only called once.
    #[allow(unused)]
    pub fn logger_init() {
        use std::sync::Once;
        static LOGGER: Once = Once::new();
        LOGGER.call_once(|| {
            flexi_logger::Logger::try_with_env_or_str("info")
                .unwrap()
                .write_mode(flexi_logger::WriteMode::SupportCapture)
                .start()
                .ok();
        });
    }
}
