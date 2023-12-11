/*++
Licensed under the Apache-2.0 license.

Abstract:
    DPE reponses and serialization.
--*/
use crate::{
    context::ContextHandle, validation::ValidationError, CURRENT_PROFILE_MAJOR_VERSION,
    CURRENT_PROFILE_MINOR_VERSION, DPE_PROFILE, MAX_CERT_SIZE, MAX_HANDLES,
};
use crypto::CryptoError;
use platform::PlatformError;
use zerocopy::AsBytes;

#[cfg_attr(test, derive(PartialEq, Debug, Eq))]
#[allow(clippy::large_enum_variant)]
pub enum Response {
    GetProfile(GetProfileResp),
    InitCtx(NewHandleResp),
    DeriveChild(DeriveChildResp),
    RotateCtx(NewHandleResp),
    CertifyKey(CertifyKeyResp),
    Sign(SignResp),
    DestroyCtx(ResponseHdr),
    ExtendTci(NewHandleResp),
    GetCertificateChain(GetCertificateChainResp),
    Error(ResponseHdr),
}

impl Response {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Response::GetProfile(res) => res.as_bytes(),
            Response::InitCtx(res) => res.as_bytes(),
            Response::DeriveChild(res) => res.as_bytes(),
            Response::RotateCtx(res) => res.as_bytes(),
            Response::CertifyKey(res) => res.as_bytes(),
            Response::Sign(res) => res.as_bytes(),
            Response::DestroyCtx(res) => res.as_bytes(),
            Response::ExtendTci(res) => res.as_bytes(),
            Response::GetCertificateChain(res) => res.as_bytes(),
            Response::Error(res) => res.as_bytes(),
        }
    }
}

// ABI Response structures

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::AsBytes, zerocopy::FromBytes)]
pub struct ResponseHdr {
    pub magic: u32,
    pub status: u32,
    pub profile: u32,
}

impl ResponseHdr {
    pub const DPE_RESPONSE_MAGIC: u32 = u32::from_be_bytes(*b"DPER");

    pub fn new(error_code: DpeErrorCode) -> ResponseHdr {
        ResponseHdr {
            magic: Self::DPE_RESPONSE_MAGIC,
            status: error_code.get_error_code(),
            profile: DPE_PROFILE as u32,
        }
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::AsBytes, zerocopy::FromBytes)]
pub struct GetProfileResp {
    pub resp_hdr: ResponseHdr,
    pub major_version: u16,
    pub minor_version: u16,
    pub vendor_id: u32,
    pub vendor_sku: u32,
    pub max_tci_nodes: u32,
    pub flags: u32,
}

impl GetProfileResp {
    pub const fn new(flags: u32, vendor_id: u32, vendor_sku: u32) -> GetProfileResp {
        GetProfileResp {
            major_version: CURRENT_PROFILE_MAJOR_VERSION,
            minor_version: CURRENT_PROFILE_MINOR_VERSION,
            vendor_id,
            vendor_sku,
            max_tci_nodes: MAX_HANDLES as u32,
            flags,
            resp_hdr: ResponseHdr {
                magic: ResponseHdr::DPE_RESPONSE_MAGIC,
                status: 0,
                profile: DPE_PROFILE as u32,
            },
        }
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::AsBytes, zerocopy::FromBytes)]
pub struct NewHandleResp {
    pub resp_hdr: ResponseHdr,
    pub handle: ContextHandle,
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::AsBytes, zerocopy::FromBytes)]
pub struct DeriveChildResp {
    pub resp_hdr: ResponseHdr,
    pub handle: ContextHandle,
    pub parent_handle: ContextHandle,
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::AsBytes, zerocopy::FromBytes)]
pub struct CertifyKeyResp {
    pub resp_hdr: ResponseHdr,
    pub new_context_handle: ContextHandle,
    pub derived_pubkey_x: [u8; DPE_PROFILE.get_ecc_int_size()],
    pub derived_pubkey_y: [u8; DPE_PROFILE.get_ecc_int_size()],
    pub cert_size: u32,
    pub cert: [u8; MAX_CERT_SIZE],
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::AsBytes, zerocopy::FromBytes)]
pub struct SignResp {
    pub resp_hdr: ResponseHdr,
    pub new_context_handle: ContextHandle,
    pub sig_r_or_hmac: [u8; DPE_PROFILE.get_ecc_int_size()],
    pub sig_s: [u8; DPE_PROFILE.get_ecc_int_size()],
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::AsBytes, zerocopy::FromBytes)]
pub struct GetCertificateChainResp {
    pub resp_hdr: ResponseHdr,
    pub certificate_size: u32,
    pub certificate_chain: [u8; MAX_CERT_SIZE],
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
pub enum DpeErrorCode {
    NoError = 0,
    InternalError = 1,
    InvalidCommand = 2,
    InvalidArgument = 3,
    ArgumentNotSupported = 4,
    InvalidHandle = 0x1000,
    InvalidLocality = 0x1001,
    MaxTcis = 0x1003,
    Platform(PlatformError) = 0x01000000,
    Crypto(CryptoError) = 0x02000000,
    Validation(ValidationError) = 0x03000000,
}

impl From<PlatformError> for DpeErrorCode {
    fn from(e: PlatformError) -> Self {
        DpeErrorCode::Platform(e)
    }
}

impl From<CryptoError> for DpeErrorCode {
    fn from(e: CryptoError) -> Self {
        DpeErrorCode::Crypto(e)
    }
}

impl DpeErrorCode {
    /// Get the spec-defined numeric error code. This does not include the
    /// extended error information returned from the Platform and Crypto
    /// implementations.
    pub fn discriminant(&self) -> u32 {
        // SAFETY: Because `Self` is marked `repr(u32)`, its layout is a `repr(C)` `union`
        // between `repr(C)` structs, each of which has the `u32` discriminant as its first
        // field, so we can read the discriminant without offsetting the pointer.
        unsafe { *<*const _>::from(self).cast::<u32>() }
    }

    pub fn get_error_code(&self) -> u32 {
        match self {
            DpeErrorCode::Platform(e) => self.discriminant() | e.discriminant() as u32,
            DpeErrorCode::Crypto(e) => self.discriminant() | e.discriminant() as u32,
            DpeErrorCode::Validation(e) => self.discriminant() | e.discriminant() as u32,
            _ => self.discriminant(),
        }
    }

    /// For error variants which have extended error info returned from
    /// underlying libraries (Platform and Crypto), return that extended error
    /// code. For all other variants, return None.
    ///
    /// Reporting of detailed error information is platform-defined.
    pub fn get_error_detail(&self) -> Option<u32> {
        match self {
            DpeErrorCode::Platform(e) => e.get_error_detail(),
            DpeErrorCode::Crypto(e) => e.get_error_detail(),
            _ => None,
        }
    }
}
