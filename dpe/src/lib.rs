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
const HANDLE_SIZE: usize = 20;
const CURRENT_PROFILE_VERSION: u32 = 0;
#[allow(dead_code)]
pub const DPE_PROFILE_P256_SHA256: u32 = 1;
#[allow(dead_code)]
pub const DPE_PROFILE_P384_SHA384: u32 = 2;

#[cfg(feature = "dpe_profile_p256_sha256")]
mod profile {
    pub const DPE_PROFILE_CONSTANT: u32 = super::DPE_PROFILE_P256_SHA256;
    pub const TCI_SIZE: usize = 32;
    pub const CDI_SIZE: usize = 32;
    pub const ECC_INT_SIZE: usize = 32;
}

#[cfg(feature = "dpe_profile_p384_sha384")]
mod profile {
    pub const DPE_PROFILE_CONSTANT: u32 = super::DPE_PROFILE_P384_SHA384;
    pub const TCI_SIZE: usize = 48;
    pub const CDI_SIZE: usize = 48;
    pub const ECC_INT_SIZE: usize = 48;
}

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
