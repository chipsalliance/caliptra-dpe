/*++
Licensed under the Apache-2.0 license.

Abstract:
    DPE reponses and serialization.
--*/
use crate::{CURRENT_PROFILE_VERSION, DPE_PROFILE, HANDLE_SIZE, MAX_CERT_SIZE, MAX_HANDLES};
use core::mem::size_of;

#[derive(Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Response {
    GetProfile(GetProfileResp),
    InitCtx(NewHandleResp),
    RotateCtx(NewHandleResp),
    CertifyKey(CertifyKeyResp),
    DestroyCtx,
    TagTci(NewHandleResp),
}

impl Response {
    /// Copies a serialized version of the response to the given buffer and returns the number of
    /// bytes copied.
    ///
    /// # Arguments
    ///
    /// * `dst` - Buffer where the response should be copied.
    pub fn serialize(&self, dst: &mut [u8]) -> Result<usize, DpeErrorCode> {
        match self {
            Response::GetProfile(response) => response.serialize(dst),
            Response::InitCtx(response) => response.serialize(dst),
            Response::CertifyKey(response) => response.serialize(dst),
            Response::RotateCtx(response) => response.serialize(dst),
            Response::DestroyCtx => Ok(0),
            Response::TagTci(response) => response.serialize(dst),
        }
    }
}

// ABI Response structures

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(zerocopy::AsBytes, zerocopy::FromBytes))]
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
            profile: DPE_PROFILE as u32,
        }
    }

    pub fn serialize(&self, dst: &mut [u8]) -> Result<usize, DpeErrorCode> {
        if dst.len() < size_of::<Self>() {
            return Err(DpeErrorCode::InternalError);
        }

        dst[0..4].copy_from_slice(&self.magic.to_le_bytes());
        dst[4..8].copy_from_slice(&self.status.to_le_bytes());
        dst[8..12].copy_from_slice(&self.profile.to_le_bytes());
        Ok(12)
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(zerocopy::AsBytes, zerocopy::FromBytes))]
pub struct GetProfileResp {
    pub version: u32,
    pub max_tci_nodes: u32,
    pub flags: u32,
}

impl GetProfileResp {
    pub fn new(flags: u32) -> GetProfileResp {
        GetProfileResp {
            version: CURRENT_PROFILE_VERSION,
            max_tci_nodes: MAX_HANDLES as u32,
            flags,
        }
    }

    pub fn serialize(&self, dst: &mut [u8]) -> Result<usize, DpeErrorCode> {
        if dst.len() < size_of::<Self>() {
            return Err(DpeErrorCode::InternalError);
        }

        dst[0..4].copy_from_slice(&self.version.to_le_bytes());
        dst[4..8].copy_from_slice(&self.max_tci_nodes.to_le_bytes());
        dst[8..12].copy_from_slice(&self.flags.to_le_bytes());
        Ok(size_of::<GetProfileResp>())
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(zerocopy::AsBytes, zerocopy::FromBytes))]
pub struct NewHandleResp {
    pub handle: [u8; HANDLE_SIZE],
}

impl NewHandleResp {
    pub fn serialize(&self, dst: &mut [u8]) -> Result<usize, DpeErrorCode> {
        if dst.len() < size_of::<Self>() {
            return Err(DpeErrorCode::InternalError);
        }

        dst[..HANDLE_SIZE].copy_from_slice(&self.handle);
        Ok(HANDLE_SIZE)
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub struct CertifyKeyResp {
    pub new_context_handle: [u8; HANDLE_SIZE],
    pub derived_pubkey_x: [u8; DPE_PROFILE.get_ecc_int_size()],
    pub derived_pubkey_y: [u8; DPE_PROFILE.get_ecc_int_size()],
    pub cert_size: u32,
    pub cert: [u8; MAX_CERT_SIZE],
}

impl CertifyKeyResp {
    pub fn serialize(&self, dst: &mut [u8]) -> Result<usize, DpeErrorCode> {
        if dst.len() < size_of::<Self>() {
            return Err(DpeErrorCode::InternalError);
        }

        let mut offset: usize = 0;
        dst[offset..offset + HANDLE_SIZE].copy_from_slice(&self.new_context_handle);
        offset += HANDLE_SIZE;
        dst[offset..offset + DPE_PROFILE.get_ecc_int_size()]
            .copy_from_slice(&self.derived_pubkey_x);
        offset += self.derived_pubkey_x.len();
        dst[offset..offset + DPE_PROFILE.get_ecc_int_size()]
            .copy_from_slice(&self.derived_pubkey_y);
        offset += self.derived_pubkey_y.len();
        dst[offset..offset + size_of::<u32>()].copy_from_slice(&self.cert_size.to_le_bytes());
        offset += size_of::<u32>();
        dst[offset..offset + self.cert.len()].copy_from_slice(&self.cert);
        offset += self.cert.len();

        Ok(offset)
    }
}

impl Default for CertifyKeyResp {
    fn default() -> Self {
        Self {
            new_context_handle: [0; HANDLE_SIZE],
            derived_pubkey_x: [0; DPE_PROFILE.get_ecc_int_size()],
            derived_pubkey_y: [0; DPE_PROFILE.get_ecc_int_size()],
            cert_size: 0,
            cert: [0; MAX_CERT_SIZE],
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DpeErrorCode {
    NoError = 0,
    InternalError = 1,
    InvalidCommand = 2,
    InvalidArgument = 3,
    ArgumentNotSupported = 4,
    InvalidHandle = 0x1000,
    InvalidLocality = 0x1001,
    BadTag = 0x1002,
    HandleDefined = 0x1003,
    MaxTcis = 0x1004,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpe_instance::tests::TEST_HANDLE;
    use zerocopy::AsBytes;

    const TEST_FLAGS: u32 = 0x7E57_B175;
    const DEFAULT_GET_PROFILE_RESPONSE: GetProfileResp = GetProfileResp {
        version: CURRENT_PROFILE_VERSION,
        max_tci_nodes: MAX_HANDLES as u32,
        flags: TEST_FLAGS,
    };
    const TEST_NEW_HANDLE_RESP: NewHandleResp = NewHandleResp {
        handle: TEST_HANDLE,
    };

    #[test]
    fn test_response_serialize() {
        // Generic oversized destinations for serialization.
        let mut answer = [0; 32];
        let mut response = [0; 32];

        // Get profile
        DEFAULT_GET_PROFILE_RESPONSE.serialize(&mut answer).unwrap();
        Response::GetProfile(DEFAULT_GET_PROFILE_RESPONSE)
            .serialize(&mut response)
            .unwrap();
        assert_eq!(answer, response);

        // Initialize context
        TEST_NEW_HANDLE_RESP.serialize(&mut answer).unwrap();
        Response::InitCtx(TEST_NEW_HANDLE_RESP)
            .serialize(&mut response)
            .unwrap();
        assert_eq!(answer, response);
    }

    #[test]
    fn test_response_header_serialize() {
        // Test too small slice.
        let mut response_buffer = [0; size_of::<ResponseHdr>() - 1];
        assert_eq!(
            Err(DpeErrorCode::InternalError),
            ResponseHdr::new(DpeErrorCode::NoError).serialize(response_buffer.as_mut_slice())
        );
        test_error_code_serialize(DpeErrorCode::NoError);
        test_error_code_serialize(DpeErrorCode::InternalError);
        test_error_code_serialize(DpeErrorCode::InvalidCommand);
        test_error_code_serialize(DpeErrorCode::InvalidArgument);
        test_error_code_serialize(DpeErrorCode::ArgumentNotSupported);
        test_error_code_serialize(DpeErrorCode::InvalidHandle);
        test_error_code_serialize(DpeErrorCode::InvalidLocality);
        test_error_code_serialize(DpeErrorCode::BadTag);
        test_error_code_serialize(DpeErrorCode::HandleDefined);
        test_error_code_serialize(DpeErrorCode::MaxTcis);
    }

    #[test]
    fn test_get_profile_serialize() {
        // Test too small slice.
        let mut response_buffer = [0; size_of::<GetProfileResp>() - 1];
        assert_eq!(
            Err(DpeErrorCode::InternalError),
            DEFAULT_GET_PROFILE_RESPONSE.serialize(response_buffer.as_mut_slice())
        );
        let mut response_buffer = [0; size_of::<GetProfileResp>()];

        assert_eq!(
            12,
            DEFAULT_GET_PROFILE_RESPONSE
                .serialize(response_buffer.as_mut_slice())
                .unwrap()
        );
        assert_eq!(DEFAULT_GET_PROFILE_RESPONSE.as_bytes(), response_buffer);
    }

    #[test]
    fn test_serialize_new_handle_response() {
        // Test too small slice.
        let mut response_buffer = [0; size_of::<NewHandleResp>() - 1];
        assert_eq!(
            Err(DpeErrorCode::InternalError),
            TEST_NEW_HANDLE_RESP.serialize(response_buffer.as_mut_slice())
        );
        let mut response_buffer = [0; size_of::<NewHandleResp>()];

        assert_eq!(
            HANDLE_SIZE,
            TEST_NEW_HANDLE_RESP
                .serialize(response_buffer.as_mut_slice())
                .unwrap()
        );
        assert_eq!(TEST_NEW_HANDLE_RESP.as_bytes(), response_buffer);
    }

    fn test_error_code_serialize(error_code: DpeErrorCode) {
        let rsp_hdr = ResponseHdr::new(error_code);
        let mut response_buffer = [0; size_of::<ResponseHdr>()];

        assert_eq!(
            12,
            rsp_hdr.serialize(response_buffer.as_mut_slice()).unwrap()
        );
        assert_eq!(rsp_hdr.as_bytes(), response_buffer);
    }
}
