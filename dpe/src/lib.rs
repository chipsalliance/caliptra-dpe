/*++
Licensed under the Apache-2.0 license.

Abstract:
    DPE Library Crate.
--*/
#![cfg_attr(not(test), no_std)]

pub use dpe_instance::DpeInstance;
pub use support::Support;

pub mod commands;
pub mod context;
pub mod dpe_instance;
pub mod response;
pub mod support;

use core::mem::size_of;
use response::GetProfileResp;
mod tci;
mod x509;

const MAX_CERT_SIZE: usize = 2048;
const MAX_HANDLES: usize = 24;
const CURRENT_PROFILE_MAJOR_VERSION: u16 = 0;
const CURRENT_PROFILE_MINOR_VERSION: u16 = 8;

const INTERNAL_INPUT_INFO_SIZE: usize = size_of::<GetProfileResp>() + size_of::<u32>();

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
    pub const fn get_cdi_size(&self) -> usize {
        self.get_tci_size()
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

fn _set_flag(field: &mut u32, mask: u32, value: bool) {
    *field = if value { *field | mask } else { *field & !mask };
}
