/*++
Licensed under the Apache-2.0 license.

Abstract:
    DPE reponses and serialization.
--*/
use crate::{
    commands::{CertifyKeyCommand, Command, DeriveContextCmd, SignCommand},
    context::ContextHandle,
    validation::ValidationError,
    DpeProfile, CURRENT_PROFILE_MAJOR_VERSION, CURRENT_PROFILE_MINOR_VERSION, MAX_CERT_SIZE,
    MAX_EXPORTED_CDI_SIZE, MAX_HANDLES,
};
use crypto::{ecdsa::EcdsaAlgorithm, CryptoError};
use platform::{PlatformError, MAX_CHUNK_SIZE};
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

#[cfg(feature = "ml-dsa")]
use crypto::ml_dsa::MldsaAlgorithm;

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
            Response::Error(res) => Ok(res.as_bytes()),
        }
    }

    /// Return a valid Response given the command and bytes.
    ///
    /// This is useful for parsing the data as it was received "over the wire". This also works with
    /// the output of `as_bytes_partial`.
    pub fn try_read_from_bytes(cmd: &Command, bytes: &[u8]) -> Result<Response, DpeErrorCode> {
        // Use a u32 buffer to ensure alignment
        let mut buf = [0u32; size_of::<Self>() / 4];
        buf.as_mut_bytes()[..bytes.len()].copy_from_slice(bytes);
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
            Command::DeriveContext(DeriveContextCmd { flags, .. }) if flags.exports_cdi() => {
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
            Command::Sign(SignCommand::Mldsa87(_)) => Response::Sign(SignResp::MlDsa(
                SignMlDsaResp::try_read_from_prefix(bytes)
                    .map_err(|_| DpeErrorCode::InvalidArgument)?
                    .0,
            )),
            #[cfg(feature = "ml-dsa")]
            Command::Sign(SignCommand::Mldsa87Raw { .. }) => Response::Sign(SignResp::MlDsa(
                SignMlDsaResp::try_read_from_prefix(bytes)
                    .map_err(|_| DpeErrorCode::InvalidArgument)?
                    .0,
            )),
        };
        Ok(r)
    }
}

// ABI Response structures

#[repr(C)]
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

#[repr(C)]
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

#[repr(C)]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, KnownLayout, Immutable)]
pub struct NewHandleResp {
    pub resp_hdr: ResponseHdr,
    pub handle: ContextHandle,
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct DeriveContextResp {
    pub resp_hdr: ResponseHdr,
    pub handle: ContextHandle,
    pub parent_handle: ContextHandle,
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct DeriveContextExportedCdiResp {
    pub resp_hdr: ResponseHdr,
    pub handle: ContextHandle,
    pub parent_handle: ContextHandle,
    pub exported_cdi: [u8; MAX_EXPORTED_CDI_SIZE],
    pub certificate_size: u32,
    pub new_certificate: [u8; MAX_CERT_SIZE],
}

impl DeriveContextExportedCdiResp {
    pub fn as_bytes_partial(&self) -> Result<&[u8], DpeErrorCode> {
        let len = size_of::<Self>() - MAX_CERT_SIZE + self.certificate_size as usize;
        self.as_bytes()
            .get(..len)
            .ok_or(DpeErrorCode::InternalError)
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
            CertifyKeyResp::P256(resp) => resp.new_context_handle = *handle,
            #[cfg(feature = "p384")]
            CertifyKeyResp::P384(resp) => resp.new_context_handle = *handle,
            #[cfg(feature = "ml-dsa")]
            CertifyKeyResp::Mldsa87(resp) => resp.new_context_handle = *handle,
        }
    }

    pub fn resp_hdr(&self) -> &ResponseHdr {
        match self {
            #[cfg(feature = "p256")]
            CertifyKeyResp::P256(resp) => &resp.resp_hdr,
            #[cfg(feature = "p384")]
            CertifyKeyResp::P384(resp) => &resp.resp_hdr,
            #[cfg(feature = "ml-dsa")]
            CertifyKeyResp::Mldsa87(resp) => &resp.resp_hdr,
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
            CertifyKeyResp::P256(r) => (&r.cert, r.cert_size),
            #[cfg(feature = "p384")]
            CertifyKeyResp::P384(r) => (&r.cert, r.cert_size),
            #[cfg(feature = "ml-dsa")]
            CertifyKeyResp::Mldsa87(r) => (&r.cert, r.cert_size),
        };
        buf.get(..size as usize).ok_or(DpeErrorCode::InternalError)
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct CertifyKeyP256Resp {
    pub resp_hdr: ResponseHdr,
    pub new_context_handle: ContextHandle,
    pub derived_pubkey_x: [u8; EcdsaAlgorithm::Bit256.curve_size()],
    pub derived_pubkey_y: [u8; EcdsaAlgorithm::Bit256.curve_size()],
    pub cert_size: u32,
    pub cert: [u8; MAX_CERT_SIZE],
}

impl CertifyKeyP256Resp {
    pub fn as_bytes_partial(&self) -> Result<&[u8], DpeErrorCode> {
        let len = size_of::<Self>() - MAX_CERT_SIZE + self.cert_size as usize;
        self.as_bytes()
            .get(..len)
            .ok_or(DpeErrorCode::InternalError)
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct CertifyKeyP384Resp {
    pub resp_hdr: ResponseHdr,
    pub new_context_handle: ContextHandle,
    pub derived_pubkey_x: [u8; EcdsaAlgorithm::Bit384.curve_size()],
    pub derived_pubkey_y: [u8; EcdsaAlgorithm::Bit384.curve_size()],
    pub cert_size: u32,
    pub cert: [u8; MAX_CERT_SIZE],
}

impl CertifyKeyP384Resp {
    pub fn as_bytes_partial(&self) -> Result<&[u8], DpeErrorCode> {
        let len = size_of::<Self>() - MAX_CERT_SIZE + self.cert_size as usize;
        self.as_bytes()
            .get(..len)
            .ok_or(DpeErrorCode::InternalError)
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
#[cfg(feature = "ml-dsa")]
pub struct CertifyKeyMldsa87Resp {
    pub resp_hdr: ResponseHdr,
    pub new_context_handle: ContextHandle,
    pub pubkey: [u8; MldsaAlgorithm::Mldsa87.public_key_size()],
    pub cert_size: u32,
    pub cert: [u8; MAX_CERT_SIZE],
}

#[cfg(feature = "ml-dsa")]
impl CertifyKeyMldsa87Resp {
    pub fn as_bytes_partial(&self) -> Result<&[u8], DpeErrorCode> {
        let len = size_of::<Self>() - MAX_CERT_SIZE + self.cert_size as usize;
        self.as_bytes()
            .get(..len)
            .ok_or(DpeErrorCode::InternalError)
    }
}

#[derive(PartialEq, Debug, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum SignResp {
    #[cfg(feature = "p256")]
    P256(SignP256Resp),
    #[cfg(feature = "p384")]
    P384(SignP384Resp),
    #[cfg(feature = "ml-dsa")]
    MlDsa(SignMlDsaResp),
}

impl SignResp {
    pub fn set_handle(&mut self, handle: &ContextHandle) {
        match self {
            #[cfg(feature = "p256")]
            SignResp::P256(resp) => resp.new_context_handle = *handle,
            #[cfg(feature = "p384")]
            SignResp::P384(resp) => resp.new_context_handle = *handle,
            #[cfg(feature = "ml-dsa")]
            SignResp::MlDsa(resp) => resp.new_context_handle = *handle,
        }
    }

    pub fn resp_hdr(&self) -> &ResponseHdr {
        match self {
            #[cfg(feature = "p256")]
            SignResp::P256(resp) => &resp.resp_hdr,
            #[cfg(feature = "p384")]
            SignResp::P384(resp) => &resp.resp_hdr,
            #[cfg(feature = "ml-dsa")]
            SignResp::MlDsa(resp) => &resp.resp_hdr,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            #[cfg(feature = "p256")]
            SignResp::P256(resp) => resp.as_bytes(),
            #[cfg(feature = "p384")]
            SignResp::P384(resp) => resp.as_bytes(),
            #[cfg(feature = "ml-dsa")]
            SignResp::MlDsa(resp) => resp.as_bytes(),
        }
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct SignP256Resp {
    pub resp_hdr: ResponseHdr,
    pub new_context_handle: ContextHandle,
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct SignP384Resp {
    pub resp_hdr: ResponseHdr,
    pub new_context_handle: ContextHandle,
    pub sig_r: [u8; 48],
    pub sig_s: [u8; 48],
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
#[cfg(feature = "ml-dsa")]
pub struct SignMlDsaResp {
    pub resp_hdr: ResponseHdr,
    pub new_context_handle: ContextHandle,
    pub sig: [u8; crypto::ml_dsa::MldsaAlgorithm::Mldsa87.signature_size()],
    pub _padding: [u8; 1],
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct GetCertificateChainResp {
    pub resp_hdr: ResponseHdr,
    pub certificate_size: u32,
    pub certificate_chain: [u8; MAX_CHUNK_SIZE],
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
pub enum DpeErrorCode {
    NoError = 0,
    InternalError = 1,
    InvalidCommand = 2,
    InvalidArgument = 3,
    ArgumentNotSupported = 4,
    X509CsrUnset = 5,
    X509InvalidState = 6,
    X509SkipsExhausted = 7,
    X509InvalidWidth = 8,
    X509AlgorithmMismatch = 9,
    InvalidHandle = 0x1000,
    InvalidLocality = 0x1001,
    MaxTcis = 0x1003,
    InvalidMutRefBuf = 0x1004,
    InvalidResponseBuf = 0x1005,
    UninitializedResponseHeader = 0x1006,
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
