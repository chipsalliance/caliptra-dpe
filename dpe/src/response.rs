/*++
Licensed under the Apache-2.0 license.

Abstract:
    DPE reponses and serialization.
--*/
use crate::profile;

pub enum Response {
    GetProfile(GetProfileResp),
    InitCtx(InitCtxResp),
}

// ABI Response structures

#[repr(C)]
pub struct ResponseHdr {
    pub magic: u32,
    pub status: u32,
    pub profile: u32,
}

impl ResponseHdr {
    const DPE_RESPONSE_MAGIC: u32 = u32::from_be_bytes(*b"DPER");

    pub fn new(error_code: DpeErrorCode) -> ResponseHdr {
        ResponseHdr {
            magic: Self::DPE_RESPONSE_MAGIC,
            status: error_code as u32,
            profile: profile::DPE_PROFILE_CONSTANT,
        }
    }
}

#[repr(C)]
pub struct GetProfileResp {
    pub flags: u32,
}

#[repr(C)]
pub struct InitCtxResp {
    pub handle: [u8; 20],
}

#[derive(Debug, PartialEq, Eq)]
pub enum DpeErrorCode {
    NoError = 0,
    InternalError = 1,
    InvalidCommand = 2,
    InvalidArgument = 3,
    ArgumentNotSupported = 4,
    SessionExhausted = 5,
}
