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
use common;

const MAX_CERT_SIZE: usize = 2048;
const MAX_HANDLES: usize = 24;
const CURRENT_PROFILE_MAJOR_VERSION: u16 = 0;
const CURRENT_PROFILE_MINOR_VERSION: u16 = 8;

const INTERNAL_INPUT_INFO_SIZE: usize = size_of::<GetProfileResp>() + size_of::<u32>();
