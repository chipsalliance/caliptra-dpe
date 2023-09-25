/*++
Licensed under the Apache-2.0 license.

Abstract:
    DPE Library Crate.
--*/
#![cfg_attr(not(test), no_std)]

pub use dpe_instance::DpeInstance;

pub mod commands;
pub mod context;
pub mod dpe_instance;
pub mod response;
pub mod support;

use core::mem::size_of;
use response::GetProfileResp;
pub mod tci;
pub mod x509;

use zerocopy::{AsBytes, FromBytes};

const MAX_CERT_SIZE: usize = 2048;
const MAX_HANDLES: usize = 24;
const CURRENT_PROFILE_MAJOR_VERSION: u16 = 0;
const CURRENT_PROFILE_MINOR_VERSION: u16 = 8;

const INTERNAL_INPUT_INFO_SIZE: usize = size_of::<GetProfileResp>() + size_of::<u32>();

/// A type with u8 backing memory but bool semantics
/// This is needed to safely serialize booleans in the persisted DPE state
/// using zerocopy.
#[derive(Default, AsBytes, FromBytes, Copy, Clone, PartialEq, Eq)]
#[repr(C, align(1))]
pub struct U8Bool {
    val: u8,
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

pub enum DpeProfile {
    P256Sha256 = 1,
    P384Sha384 = 2,
}

impl DpeProfile {
    pub const fn get_tci_size(&self) -> usize {
        match self {
            DpeProfile::P256Sha256 => 32,
            DpeProfile::P384Sha384 => 48,
        }
    }
    pub const fn get_ecc_int_size(&self) -> usize {
        self.get_tci_size()
    }
    pub const fn get_hash_size(&self) -> usize {
        self.get_tci_size()
    }
    pub const fn alg_len(&self) -> crypto::AlgLen {
        match self {
            DpeProfile::P256Sha256 => crypto::AlgLen::Bit256,
            DpeProfile::P384Sha384 => crypto::AlgLen::Bit384,
        }
    }
}

#[cfg(feature = "dpe_profile_p256_sha256")]
pub const DPE_PROFILE: DpeProfile = DpeProfile::P256Sha256;

#[cfg(feature = "dpe_profile_p384_sha384")]
pub const DPE_PROFILE: DpeProfile = DpeProfile::P384Sha384;
