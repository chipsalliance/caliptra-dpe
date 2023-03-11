/*++
Licensed under the Apache-2.0 license.

Abstract:
    DPE Library Crate.
--*/
#![cfg_attr(not(test), no_std)]

use crypto::Crypto;
use response::{DpeErrorCode, ResponseHdr};
pub mod commands;
pub mod crypto;
pub mod dpe_instance;
pub mod response;
mod x509;

const MAX_HANDLES: usize = 24;
const HANDLE_SIZE: usize = 16;
const CURRENT_PROFILE_VERSION: u32 = 0;

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
}

#[cfg(feature = "dpe_profile_p256_sha256")]
pub const DPE_PROFILE: DpeProfile = DpeProfile::P256Sha256;
#[cfg(feature = "dpe_profile_p384_sha384")]
pub const DPE_PROFILE: DpeProfile = DpeProfile::P384Sha384;

/// Execute a DPE command.
/// Returns the number of bytes written to `response`.
pub fn execute_command<C: Crypto>(
    dpe: &mut dpe_instance::DpeInstance,
    cmd: &[u8],
    response: &mut [u8],
) -> Result<usize, DpeErrorCode> {
    match dpe.execute_serialized_command::<C>(cmd) {
        Ok(response_data) => {
            // Add the response header.
            let header_len = ResponseHdr::new(DpeErrorCode::NoError).serialize(response)?;

            // Add the response data.
            let data_len = response_data.serialize(&mut response[header_len..])?;
            Ok(header_len + data_len)
        }
        Err(error_code) => Ok(ResponseHdr::new(error_code).serialize(response)?),
    }
}

fn set_flag(field: &mut u32, mask: u32, value: bool) {
    *field = if value { *field | mask } else { *field & !mask };
}
