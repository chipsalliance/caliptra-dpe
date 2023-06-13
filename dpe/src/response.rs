/*++
Licensed under the Apache-2.0 license.

Abstract:
    DPE reponses and serialization.
--*/
use crate::{
    context::ContextHandle, tci::TciMeasurement, CURRENT_PROFILE_MAJOR_VERSION,
    CURRENT_PROFILE_MINOR_VERSION, DPE_PROFILE, MAX_CERT_SIZE, MAX_HANDLES,
};
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
    TagTci(NewHandleResp),
    GetTaggedTci(GetTaggedTciResp),
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
            Response::TagTci(res) => res.as_bytes(),
            Response::GetTaggedTci(res) => res.as_bytes(),
            Response::GetCertificateChain(res) => res.as_bytes(),
            Response::Error(res) => res.as_bytes(),
        }
    }
}

// ABI Response structures

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::AsBytes)]
#[cfg_attr(test, derive(zerocopy::FromBytes))]
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
            status: error_code as u32,
            profile: DPE_PROFILE as u32,
        }
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::AsBytes)]
#[cfg_attr(test, derive(zerocopy::FromBytes))]
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
                status: DpeErrorCode::NoError as u32,
                profile: DPE_PROFILE as u32,
            },
        }
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::AsBytes)]
#[cfg_attr(test, derive(zerocopy::FromBytes))]
pub struct NewHandleResp {
    pub resp_hdr: ResponseHdr,
    pub handle: ContextHandle,
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::AsBytes)]
#[cfg_attr(test, derive(zerocopy::FromBytes))]
pub struct DeriveChildResp {
    pub resp_hdr: ResponseHdr,
    pub handle: ContextHandle,
    pub parent_handle: ContextHandle,
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::AsBytes)]
pub struct CertifyKeyResp {
    pub resp_hdr: ResponseHdr,
    pub new_context_handle: ContextHandle,
    pub derived_pubkey_x: [u8; DPE_PROFILE.get_ecc_int_size()],
    pub derived_pubkey_y: [u8; DPE_PROFILE.get_ecc_int_size()],
    pub cert_size: u32,
    pub cert: [u8; MAX_CERT_SIZE],
}

impl Default for CertifyKeyResp {
    fn default() -> Self {
        Self {
            resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
            new_context_handle: ContextHandle::default(),
            derived_pubkey_x: [0; DPE_PROFILE.get_ecc_int_size()],
            derived_pubkey_y: [0; DPE_PROFILE.get_ecc_int_size()],
            cert_size: 0,
            cert: [0; MAX_CERT_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::AsBytes)]
#[cfg_attr(test, derive(zerocopy::FromBytes))]
pub struct SignResp {
    pub resp_hdr: ResponseHdr,
    pub new_context_handle: ContextHandle,
    pub sig_r_or_hmac: [u8; DPE_PROFILE.get_ecc_int_size()],
    pub sig_s: [u8; DPE_PROFILE.get_ecc_int_size()],
}

#[repr(C)]
#[derive(Debug, zerocopy::AsBytes)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct GetTaggedTciResp {
    pub resp_hdr: ResponseHdr,
    pub tci_cumulative: TciMeasurement,
    pub tci_current: TciMeasurement,
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::AsBytes)]
#[cfg_attr(test, derive(zerocopy::FromBytes))]
pub struct GetCertificateChainResp {
    pub resp_hdr: ResponseHdr,
    pub certificate_size: u32,
    pub certificate_chain: [u8; MAX_CERT_SIZE],
}

impl Default for GetCertificateChainResp {
    fn default() -> Self {
        Self {
            certificate_size: 0,
            certificate_chain: [0; MAX_CERT_SIZE],
            resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
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
