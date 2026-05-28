// Licensed under the Apache-2.0 license.

//! DPE error types.

use crate::validation::ValidationError;
use core::error::Error;
use core::fmt::Display;

use caliptra_dpe_crypto::CryptoError;
use caliptra_dpe_platform::PlatformError;

/// Internal error code identifying a specific invariant violation.
///
/// Each variant corresponds to a specific failure site within the DPE
/// implementation. These are diagnostic-only and indicate bugs or
/// corrupted state that should never occur in correct operation.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
pub enum InternalErrorCode {
    DeriveCtxRespSliceOob = 1,
    CertifyKeyCertSliceOob = 2,
    CertifyKeyP256RespSliceOob = 3,
    CertifyKeyP384RespSliceOob = 4,
    CertifyKeyMldsa87RespSliceOob = 5,
    Asn1SizeOverflow = 6,
    EmptyTciNodes = 7,
    EncodeBytesOverflow = 8,
    EncodeBytesSliceOob = 9,
    EncodeByteOverflow = 10,
    IntegerOffsetOob = 11,
    TbsSliceOob = 12,
    CsrTbsSliceOob = 13,
    CmsCsrRangeOob = 14,
    TcbCountOverflow = 15,
    KeyIdHashTooSmall = 16,
    SerialNumberSliceOob = 17,
    CertSizeOverflow = 18,
    CsrSizeOverflow = 19,
    IssuerNameTooLong = 20,
    MissingExportedCdiHandle = 21,
    HandleGenerationExhausted = 22,
    DigestLengthMismatch = 23,
    InputInfoProfileSliceOob = 24,
    InputInfoRemainderSliceOob = 25,
    CertChainChunkSliceOob = 26,
    ChildIndexOob = 27,
    ChildrenBitmapIndexOob = 28,
    ParentChainIndexOob = 29,
    ContextIndexOob = 30,
    ActiveContextNotFound = 31,
    DescendantIndexOob = 32,
    TciNodeArrayOverflow = 33,
    TciNodeCountExceeded = 34,
    DestroyParentIndexOob = 35,
    InitContextIndexOob = 36,
    ResponseDeserializationFailed = 37,
}

impl InternalErrorCode {
    /// Returns the discriminant as a raw `u16`.
    pub const fn discriminant(self) -> u16 {
        self as u16
    }
}

impl Display for InternalErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DeriveCtxRespSliceOob => {
                f.write_str("derive context response slice out of bounds")
            }
            Self::CertifyKeyCertSliceOob => {
                f.write_str("certify key certificate slice out of bounds")
            }
            Self::CertifyKeyP256RespSliceOob => {
                f.write_str("certify key P256 response slice out of bounds")
            }
            Self::CertifyKeyP384RespSliceOob => {
                f.write_str("certify key P384 response slice out of bounds")
            }
            Self::CertifyKeyMldsa87RespSliceOob => {
                f.write_str("certify key ML-DSA-87 response slice out of bounds")
            }
            Self::Asn1SizeOverflow => f.write_str("ASN.1 size exceeds maximum representable value"),
            Self::EmptyTciNodes => f.write_str("TCI nodes slice is unexpectedly empty"),
            Self::EncodeBytesOverflow => {
                f.write_str("encode_bytes: write would exceed certificate buffer")
            }
            Self::EncodeBytesSliceOob => {
                f.write_str("encode_bytes: certificate buffer slice out of bounds")
            }
            Self::EncodeByteOverflow => {
                f.write_str("encode_byte: write offset past end of certificate buffer")
            }
            Self::IntegerOffsetOob => f.write_str("integer encoding offset out of bounds"),
            Self::TbsSliceOob => f.write_str("TBS data slice out of bounds"),
            Self::CsrTbsSliceOob => {
                f.write_str("CSR certification request info slice out of bounds")
            }
            Self::CmsCsrRangeOob => f.write_str("CMS CSR range slice out of bounds"),
            Self::TcbCountOverflow => f.write_str("TCB node count exceeds MAX_HANDLES"),
            Self::KeyIdHashTooSmall => {
                f.write_str("hashed public key too small for key identifier")
            }
            Self::SerialNumberSliceOob => f.write_str("serial number slice out of bounds"),
            Self::CertSizeOverflow => f.write_str("certificate size exceeds u32"),
            Self::CsrSizeOverflow => f.write_str("CSR size exceeds u32"),
            Self::IssuerNameTooLong => f.write_str("issuer name length exceeds maximum"),
            Self::MissingExportedCdiHandle => {
                f.write_str("exported CDI handle is unexpectedly missing")
            }
            Self::HandleGenerationExhausted => {
                f.write_str("no unique handle found after max attempts")
            }
            Self::DigestLengthMismatch => {
                f.write_str("hash digest length does not match TCI buffer")
            }
            Self::InputInfoProfileSliceOob => {
                f.write_str("internal input info profile slice out of bounds")
            }
            Self::InputInfoRemainderSliceOob => {
                f.write_str("internal input info remainder slice out of bounds")
            }
            Self::CertChainChunkSliceOob => f.write_str("cert chain chunk slice out of bounds"),
            Self::ChildIndexOob => f.write_str("child index exceeds MAX_HANDLES"),
            Self::ChildrenBitmapIndexOob => {
                f.write_str("children bitmap index exceeds MAX_HANDLES")
            }
            Self::ParentChainIndexOob => f.write_str("parent chain iterator index out of bounds"),
            Self::ContextIndexOob => f.write_str("context index out of bounds"),
            Self::ActiveContextNotFound => f.write_str("no matching active context found"),
            Self::DescendantIndexOob => f.write_str("descendant index out of bounds"),
            Self::TciNodeArrayOverflow => f.write_str("TCI node output array overflow"),
            Self::TciNodeCountExceeded => f.write_str("TCI node count exceeds array length"),
            Self::DestroyParentIndexOob => {
                f.write_str("parent index out of bounds during context destruction")
            }
            Self::InitContextIndexOob => {
                f.write_str("context index out of bounds during initialization")
            }
            Self::ResponseDeserializationFailed => {
                f.write_str("response deserialization from bytes failed")
            }
        }
    }
}

impl Error for InternalErrorCode {}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
pub enum DpeErrorCode {
    NoError = 0,
    InternalError(InternalErrorCode) = 1,
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
    /// Returned by UpdateContextMeasurement when PARENT_CONTEXT_HANDLE does not
    /// exist in the caller's locality. Value matches the OCP iROT profile spec (0x85).
    InvalidParentLocality = 0x85,
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
}

impl Display for DpeErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoError => f.write_str("no error"),
            Self::InternalError(code) => write!(f, "{code}"),
            Self::InvalidCommand => f.write_str("invalid command"),
            Self::InvalidArgument => f.write_str("invalid argument"),
            Self::ArgumentNotSupported => f.write_str("argument not supported"),
            Self::X509CsrUnset => f.write_str("x509 CSR unset"),
            Self::X509InvalidState => f.write_str("x509 invalid state"),
            Self::X509SkipsExhausted => f.write_str("x509 skips exhausted"),
            Self::X509InvalidWidth => f.write_str("x509 invalid width"),
            Self::X509AlgorithmMismatch => f.write_str("x509 algorithm mismatch"),
            Self::InvalidHandle => f.write_str("invalid handle"),
            Self::InvalidLocality => f.write_str("invalid locality"),
            Self::MaxTcis => f.write_str("max TCIs reached"),
            Self::InvalidMutRefBuf => f.write_str("invalid mutable reference buffer"),
            Self::InvalidResponseBuf => f.write_str("invalid response buffer"),
            Self::UninitializedResponseHeader => f.write_str("uninitialized response header"),
            Self::InvalidParentLocality => f.write_str("invalid parent locality"),
            Self::Platform(e) => write!(f, "platform error: {e}"),
            Self::Crypto(e) => write!(f, "crypto error: {e}"),
            Self::Validation(e) => write!(f, "validation error: {e}"),
        }
    }
}

impl Error for DpeErrorCode {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InternalError(e) => Some(e),
            Self::Platform(e) => Some(e),
            Self::Crypto(e) => Some(e),
            Self::Validation(e) => Some(e),
            _ => None,
        }
    }
}
