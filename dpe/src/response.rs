/*++
Licensed under the Apache-2.0 license.

Abstract:
    DPE reponses and serialization.
--*/
use crate::{
    commands::{CertifyKeyCommand, Command, SignCommand},
    context::ContextHandle,
    error::{DpeErrorCode, InternalErrorCode},
    AlignedBuf, DpeProfile, CURRENT_PROFILE_MAJOR_VERSION, CURRENT_PROFILE_MINOR_VERSION,
    MAX_CERT_SIZE, MAX_EXPORTED_CDI_SIZE, MAX_HANDLES,
};
use caliptra_dpe_crypto::ecdsa::EcdsaAlgorithm;
use caliptra_dpe_platform::MAX_CHUNK_SIZE;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

#[cfg(feature = "ml-dsa")]
use caliptra_dpe_crypto::ml_dsa::MldsaAlgorithm;

#[cfg_attr(test, derive(PartialEq, Debug, Eq))]
#[allow(clippy::large_enum_variant)]
pub enum Response {
    GetProfile(GetProfileResp),
    InitCtx(NewHandleResp),
    DeriveContext(DeriveContextResp),
    DeriveContextExportedCdi(DeriveContextExportedCdiResp),
    #[cfg(not(feature = "disable_rotate_context"))]
    RotateCtx(NewHandleResp),
    CertifyKey(CertifyKeyResp),
    Sign(SignResp),
    DestroyCtx(ResponseHdr),
    GetCertificateChain(GetCertificateChainResp),
    UpdateContextMeasurement(UpdateContextMeasurementResp),
    Error(ResponseHdr),
}

impl Response {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Response::GetProfile(res) => res.as_bytes(),
            Response::InitCtx(res) => res.as_bytes(),
            Response::DeriveContext(res) => res.as_bytes(),
            Response::DeriveContextExportedCdi(res) => res.as_bytes(),
            #[cfg(not(feature = "disable_rotate_context"))]
            Response::RotateCtx(res) => res.as_bytes(),
            Response::CertifyKey(res) => res.as_bytes(),
            Response::Sign(res) => res.as_bytes(),
            Response::DestroyCtx(res) => res.as_bytes(),
            Response::GetCertificateChain(res) => res.as_bytes(),
            Response::UpdateContextMeasurement(res) => res.as_bytes(),
            Response::Error(res) => res.as_bytes(),
        }
    }

    /// Returns a slice to only the relevant parts of the response.
    ///
    /// For example, in `CertifyKey` there will be empty bytes at the end of the certificate. This
    /// will return the response bytes up until the end of the certificate.
    pub fn as_bytes_partial(&self) -> Result<&[u8], DpeErrorCode> {
        match self {
            Response::GetProfile(res) => Ok(res.as_bytes()),
            Response::InitCtx(res) => Ok(res.as_bytes()),
            Response::DeriveContext(res) => Ok(res.as_bytes()),
            Response::DeriveContextExportedCdi(res) => res.as_bytes_partial(),
            #[cfg(not(feature = "disable_rotate_context"))]
            Response::RotateCtx(res) => Ok(res.as_bytes()),
            Response::CertifyKey(res) => res.as_bytes_partial(),
            Response::Sign(res) => Ok(res.as_bytes()),
            Response::DestroyCtx(res) => Ok(res.as_bytes()),
            Response::GetCertificateChain(res) => Ok(res.as_bytes()),
            Response::UpdateContextMeasurement(res) => Ok(res.as_bytes()),
            Response::Error(res) => Ok(res.as_bytes()),
        }
    }

    /// Return a valid Response given the command and bytes.
    ///
    /// This is useful for parsing the data as it was received "over the wire". This also works with
    /// the output of `as_bytes_partial`.
    pub fn try_read_from_bytes(cmd: &Command, bytes: &[u8]) -> Result<Response, DpeErrorCode> {
        // miri alignment: copy into an aligned buffer so zerocopy reads from 4-byte aligned memory
        let mut buf = AlignedBuf::<{ size_of::<Self>() }>::new();
        let copy_len = bytes.len().min(buf.as_bytes().len());
        buf.as_mut_bytes()[..copy_len].copy_from_slice(&bytes[..copy_len]);
        let bytes = buf.as_bytes();

        let r = match cmd {
            #[cfg(feature = "p256")]
            Command::CertifyKey(CertifyKeyCommand::P256(_)) => {
                Response::CertifyKey(CertifyKeyResp::P256(
                    CertifyKeyP256Resp::try_read_from_prefix(bytes)
                        .map_err(|_| DpeErrorCode::InvalidArgument)?
                        .0,
                ))
            }
            #[cfg(feature = "p384")]
            Command::CertifyKey(CertifyKeyCommand::P384(_)) => {
                Response::CertifyKey(CertifyKeyResp::P384(
                    CertifyKeyP384Resp::try_read_from_prefix(bytes)
                        .map_err(|_e| DpeErrorCode::InvalidArgument)?
                        .0,
                ))
            }
            #[cfg(feature = "ml-dsa")]
            Command::CertifyKey(CertifyKeyCommand::Mldsa87(_)) => {
                Response::CertifyKey(CertifyKeyResp::Mldsa87(
                    CertifyKeyMldsa87Resp::try_read_from_prefix(bytes)
                        .map_err(|_| DpeErrorCode::InvalidArgument)?
                        .0,
                ))
            }
            Command::DeriveContext(cmd) if cmd.flags().exports_cdi() => {
                Response::DeriveContextExportedCdi(
                    DeriveContextExportedCdiResp::try_read_from_prefix(bytes)
                        .map_err(|_| DpeErrorCode::InvalidArgument)?
                        .0,
                )
            }
            Command::DeriveContext(_) => Response::DeriveContext(
                DeriveContextResp::try_read_from_prefix(bytes)
                    .map_err(|_| DpeErrorCode::InvalidArgument)?
                    .0,
            ),
            Command::GetCertificateChain(_) => Response::GetCertificateChain(
                GetCertificateChainResp::try_read_from_prefix(bytes)
                    .map_err(|_| DpeErrorCode::InvalidArgument)?
                    .0,
            ),
            Command::DestroyCtx(_) => Response::DestroyCtx(
                ResponseHdr::try_read_from_prefix(bytes)
                    .map_err(|_| DpeErrorCode::InvalidArgument)?
                    .0,
            ),
            Command::GetProfile(_) => Response::GetProfile(
                GetProfileResp::try_read_from_prefix(bytes)
                    .map_err(|_| DpeErrorCode::InvalidArgument)?
                    .0,
            ),
            Command::InitCtx(_) => Response::InitCtx(
                NewHandleResp::try_read_from_prefix(bytes)
                    .map_err(|_| DpeErrorCode::InvalidArgument)?
                    .0,
            ),
            #[cfg(not(feature = "disable_rotate_context"))]
            Command::RotateCtx(_) => Response::RotateCtx(
                NewHandleResp::try_read_from_prefix(bytes)
                    .map_err(|_| DpeErrorCode::InvalidArgument)?
                    .0,
            ),
            #[cfg(feature = "p256")]
            Command::Sign(SignCommand::P256(_)) => Response::Sign(SignResp::P256(
                SignP256Resp::try_read_from_prefix(bytes)
                    .map_err(|_| DpeErrorCode::InvalidArgument)?
                    .0,
            )),
            #[cfg(feature = "p384")]
            Command::Sign(SignCommand::P384(_)) => Response::Sign(SignResp::P384(
                SignP384Resp::try_read_from_prefix(bytes)
                    .map_err(|_| DpeErrorCode::InvalidArgument)?
                    .0,
            )),
            #[cfg(feature = "ml-dsa")]
            Command::Sign(SignCommand::Mldsa87(_)) => Response::Sign(SignResp::Mldsa87(
                SignMlDsaResp::try_read_from_prefix(bytes)
                    .map_err(|_| DpeErrorCode::InvalidArgument)?
                    .0,
            )),
            #[cfg(feature = "ml-dsa")]
            Command::Sign(SignCommand::Mldsa87Raw(_)) => Response::Sign(SignResp::Mldsa87(
                SignMlDsaResp::try_read_from_prefix(bytes)
                    .map_err(|_| DpeErrorCode::InvalidArgument)?
                    .0,
            )),
            Command::UpdateContextMeasurement(_) => Response::UpdateContextMeasurement(
                UpdateContextMeasurementResp::try_read_from_prefix(bytes)
                    .map_err(|_| DpeErrorCode::InvalidArgument)?
                    .0,
            ),
        };
        Ok(r)
    }
}

// ABI Response structures

#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct ResponseHdr {
    pub magic: u32,
    pub status: u32,
    pub profile: DpeProfile,
}

impl ResponseHdr {
    pub const DPE_RESPONSE_MAGIC: u32 = u32::from_be_bytes(*b"DPER");

    pub fn new(profile: DpeProfile, error_code: DpeErrorCode) -> ResponseHdr {
        ResponseHdr {
            magic: Self::DPE_RESPONSE_MAGIC,
            status: error_code.get_error_code(),
            profile,
        }
    }
}

#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
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
    pub const fn new(
        profile: DpeProfile,
        flags: u32,
        vendor_id: u32,
        vendor_sku: u32,
    ) -> GetProfileResp {
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
                profile,
            },
        }
    }
}

#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, KnownLayout, Immutable)]
pub struct NewHandleResp {
    pub resp_hdr: ResponseHdr,
    pub handle: ContextHandle,
}

#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct DeriveContextResp {
    pub resp_hdr: ResponseHdr,
    pub handle: ContextHandle,
    pub parent_handle: ContextHandle,
}

/// Response for the UpdateContextMeasurement vendor command.
#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct UpdateContextMeasurementResp {
    pub resp_hdr: ResponseHdr,
    /// Rotated handle for the updated child context.
    pub new_context_handle: ContextHandle,
    /// Rotated handle for the parent context (always retained).
    pub new_parent_context_handle: ContextHandle,
}

#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct DeriveContextExportedCdiResp {
    pub header: DeriveContextExportedCdiRespHdr,
    pub new_certificate: [u8; MAX_CERT_SIZE],
}

impl DeriveContextExportedCdiResp {
    pub fn as_bytes_partial(&self) -> Result<&[u8], DpeErrorCode> {
        let len = size_of::<Self>() - MAX_CERT_SIZE + self.header.certificate_size as usize;
        self.as_bytes()
            .get(..len)
            .ok_or(DpeErrorCode::from(InternalErrorCode::DeriveCtxRespSliceOob))
    }
}

#[derive(PartialEq, Debug, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum CertifyKeyResp {
    #[cfg(feature = "p256")]
    P256(CertifyKeyP256Resp),
    #[cfg(feature = "p384")]
    P384(CertifyKeyP384Resp),
    #[cfg(feature = "ml-dsa")]
    Mldsa87(CertifyKeyMldsa87Resp),
}

impl CertifyKeyResp {
    pub fn set_handle(&mut self, handle: &ContextHandle) {
        match self {
            #[cfg(feature = "p256")]
            CertifyKeyResp::P256(resp) => resp.header.new_context_handle = *handle,
            #[cfg(feature = "p384")]
            CertifyKeyResp::P384(resp) => resp.header.new_context_handle = *handle,
            #[cfg(feature = "ml-dsa")]
            CertifyKeyResp::Mldsa87(resp) => resp.header.new_context_handle = *handle,
        }
    }

    pub fn resp_hdr(&self) -> &ResponseHdr {
        match self {
            #[cfg(feature = "p256")]
            CertifyKeyResp::P256(resp) => &resp.header.resp_hdr,
            #[cfg(feature = "p384")]
            CertifyKeyResp::P384(resp) => &resp.header.resp_hdr,
            #[cfg(feature = "ml-dsa")]
            CertifyKeyResp::Mldsa87(resp) => &resp.header.resp_hdr,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            #[cfg(feature = "p256")]
            CertifyKeyResp::P256(resp) => resp.as_bytes(),
            #[cfg(feature = "p384")]
            CertifyKeyResp::P384(resp) => resp.as_bytes(),
            #[cfg(feature = "ml-dsa")]
            CertifyKeyResp::Mldsa87(resp) => resp.as_bytes(),
        }
    }

    pub fn as_bytes_partial(&self) -> Result<&[u8], DpeErrorCode> {
        match self {
            #[cfg(feature = "p256")]
            CertifyKeyResp::P256(resp) => resp.as_bytes_partial(),
            #[cfg(feature = "p384")]
            CertifyKeyResp::P384(resp) => resp.as_bytes_partial(),
            #[cfg(feature = "ml-dsa")]
            CertifyKeyResp::Mldsa87(resp) => resp.as_bytes_partial(),
        }
    }

    pub fn cert(&self) -> Result<&[u8], DpeErrorCode> {
        let (buf, size) = match self {
            #[cfg(feature = "p256")]
            CertifyKeyResp::P256(r) => (&r.cert, r.header.cert_size),
            #[cfg(feature = "p384")]
            CertifyKeyResp::P384(r) => (&r.cert, r.header.cert_size),
            #[cfg(feature = "ml-dsa")]
            CertifyKeyResp::Mldsa87(r) => (&r.cert, r.header.cert_size),
        };
        buf.get(..size as usize).ok_or(DpeErrorCode::from(
            InternalErrorCode::CertifyKeyCertSliceOob,
        ))
    }
}

#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct CertifyKeyP256Resp {
    pub header: CertifyKeyP256RespHdr,
    pub cert: [u8; MAX_CERT_SIZE],
}

impl CertifyKeyP256Resp {
    pub fn as_bytes_partial(&self) -> Result<&[u8], DpeErrorCode> {
        let len = size_of::<Self>() - MAX_CERT_SIZE + self.header.cert_size as usize;
        self.as_bytes().get(..len).ok_or(DpeErrorCode::from(
            InternalErrorCode::CertifyKeyP256RespSliceOob,
        ))
    }
}

#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct CertifyKeyP384Resp {
    pub header: CertifyKeyP384RespHdr,
    pub cert: [u8; MAX_CERT_SIZE],
}

impl CertifyKeyP384Resp {
    pub fn as_bytes_partial(&self) -> Result<&[u8], DpeErrorCode> {
        let len = size_of::<Self>() - MAX_CERT_SIZE + self.header.cert_size as usize;
        self.as_bytes().get(..len).ok_or(DpeErrorCode::from(
            InternalErrorCode::CertifyKeyP384RespSliceOob,
        ))
    }
}

#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
#[cfg(feature = "ml-dsa")]
pub struct CertifyKeyMldsa87Resp {
    pub header: CertifyKeyMldsa87RespHdr,
    pub cert: [u8; MAX_CERT_SIZE],
}

#[cfg(feature = "ml-dsa")]
impl CertifyKeyMldsa87Resp {
    pub fn as_bytes_partial(&self) -> Result<&[u8], DpeErrorCode> {
        let len = size_of::<Self>() - MAX_CERT_SIZE + self.header.cert_size as usize;
        self.as_bytes().get(..len).ok_or(DpeErrorCode::from(
            InternalErrorCode::CertifyKeyMldsa87RespSliceOob,
        ))
    }
}

#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct CertifyKeyP256RespHdr {
    pub resp_hdr: ResponseHdr,
    pub new_context_handle: ContextHandle,
    pub derived_pubkey_x: [u8; EcdsaAlgorithm::Bit256.curve_size()],
    pub derived_pubkey_y: [u8; EcdsaAlgorithm::Bit256.curve_size()],
    pub cert_size: u32,
}

#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct CertifyKeyP384RespHdr {
    pub resp_hdr: ResponseHdr,
    pub new_context_handle: ContextHandle,
    pub derived_pubkey_x: [u8; EcdsaAlgorithm::Bit384.curve_size()],
    pub derived_pubkey_y: [u8; EcdsaAlgorithm::Bit384.curve_size()],
    pub cert_size: u32,
}

#[cfg(feature = "ml-dsa")]
#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct CertifyKeyMldsa87RespHdr {
    pub resp_hdr: ResponseHdr,
    pub new_context_handle: ContextHandle,
    pub pubkey: [u8; MldsaAlgorithm::Mldsa87.public_key_size()],
    pub cert_size: u32,
}

#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct DeriveContextExportedCdiRespHdr {
    pub resp_hdr: ResponseHdr,
    pub handle: ContextHandle,
    pub parent_handle: ContextHandle,
    pub exported_cdi: [u8; MAX_EXPORTED_CDI_SIZE],
    pub certificate_size: u32,
}

#[derive(PartialEq, Debug, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum SignResp {
    #[cfg(feature = "p256")]
    P256(SignP256Resp),
    #[cfg(feature = "p384")]
    P384(SignP384Resp),
    #[cfg(feature = "ml-dsa")]
    Mldsa87(SignMlDsaResp),
}

impl SignResp {
    pub fn set_handle(&mut self, handle: &ContextHandle) {
        match self {
            #[cfg(feature = "p256")]
            SignResp::P256(resp) => resp.new_context_handle = *handle,
            #[cfg(feature = "p384")]
            SignResp::P384(resp) => resp.new_context_handle = *handle,
            #[cfg(feature = "ml-dsa")]
            SignResp::Mldsa87(resp) => resp.new_context_handle = *handle,
        }
    }

    pub fn resp_hdr(&self) -> &ResponseHdr {
        match self {
            #[cfg(feature = "p256")]
            SignResp::P256(resp) => &resp.resp_hdr,
            #[cfg(feature = "p384")]
            SignResp::P384(resp) => &resp.resp_hdr,
            #[cfg(feature = "ml-dsa")]
            SignResp::Mldsa87(resp) => &resp.resp_hdr,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            #[cfg(feature = "p256")]
            SignResp::P256(resp) => resp.as_bytes(),
            #[cfg(feature = "p384")]
            SignResp::P384(resp) => resp.as_bytes(),
            #[cfg(feature = "ml-dsa")]
            SignResp::Mldsa87(resp) => resp.as_bytes(),
        }
    }
}

#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct SignP256Resp {
    pub resp_hdr: ResponseHdr,
    pub new_context_handle: ContextHandle,
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct SignP384Resp {
    pub resp_hdr: ResponseHdr,
    pub new_context_handle: ContextHandle,
    pub sig_r: [u8; 48],
    pub sig_s: [u8; 48],
}

#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
#[cfg(feature = "ml-dsa")]
pub struct SignMlDsaResp {
    pub resp_hdr: ResponseHdr,
    pub new_context_handle: ContextHandle,
    pub sig: [u8; caliptra_dpe_crypto::ml_dsa::MldsaAlgorithm::Mldsa87.signature_size()],
    pub _padding: [u8; 1],
}

#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct GetCertificateChainResp {
    pub resp_hdr: ResponseHdr,
    pub certificate_size: u32,
    pub certificate_chain: [u8; MAX_CHUNK_SIZE],
}
