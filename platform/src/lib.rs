/*++
Licensed under the Apache-2.0 license.
Abstract:
    Generic trait definition of platform.
--*/
#![cfg_attr(not(any(feature = "openssl", feature = "rustcrypto", test)), no_std)]

#[cfg(feature = "openssl")]
pub use openssl::x509::X509;

pub use arrayvec::ArrayVec;

#[cfg(any(feature = "openssl", feature = "rustcrypto"))]
pub mod default;

pub mod printer;

pub const MAX_CHUNK_SIZE: usize = 2048;
pub const MAX_SN_SIZE: usize = 20;

pub enum SignerIdentifier {
    IssuerAndSerialNumber {
        issuer_name: ArrayVec<u8, { MAX_CHUNK_SIZE }>,
        serial_number: ArrayVec<u8, { MAX_SN_SIZE }>,
    },
    SubjectKeyIdentifier(ArrayVec<u8, { MAX_CHUNK_SIZE }>),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct CertValidity<'a> {
    pub not_before: &'a str,
    pub not_after: &'a str,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
pub enum PlatformError {
    CertificateChainError = 0x1,
    NotImplemented = 0x2,
    IssuerNameError(u32) = 0x3,
    PrintError(u32) = 0x4,
    SerialNumberError(u32) = 0x5,
    SubjectKeyIdentifierError(u32) = 0x6,
}

impl PlatformError {
    pub fn discriminant(&self) -> u16 {
        // SAFETY: Because `Self` is marked `repr(u16)`, its layout is a `repr(C)` `union`
        // between `repr(C)` structs, each of which has the `u16` discriminant as its first
        // field, so we can read the discriminant without offsetting the pointer.
        unsafe { *<*const _>::from(self).cast::<u16>() }
    }

    pub fn get_error_detail(&self) -> Option<u32> {
        match self {
            PlatformError::CertificateChainError => None,
            PlatformError::NotImplemented => None,
            PlatformError::IssuerNameError(code) => Some(*code),
            PlatformError::PrintError(code) => Some(*code),
            PlatformError::SerialNumberError(code) => Some(*code),
            PlatformError::SubjectKeyIdentifierError(code) => Some(*code),
        }
    }
}

pub trait Platform {
    /// Retrieves a chunk of the parent certificates in the certificate chain.
    ///
    /// # Arguments
    ///
    /// * `offset` - Index where to start reading bytes from in the cert chain.
    /// * `size` - The requested size of the chunk. Actual written number of bytes could be smaller, depending on size of chain.
    /// * `out` - Output buffer for cert chain chunk to be written to
    fn get_certificate_chain(
        &mut self,
        offset: u32,
        size: u32,
        out: &mut [u8; MAX_CHUNK_SIZE],
    ) -> Result<u32, PlatformError>;

    /// Retrieves the parent certificate's DER encoded issuer name.
    ///
    /// # Arguments
    ///
    /// * `out` - Output buffer for issuer name to be written to.
    fn get_issuer_name(&mut self, out: &mut [u8; MAX_CHUNK_SIZE]) -> Result<usize, PlatformError>;

    /// Retrieves a CMS Content Info's signer identifier
    ///
    /// This function can simply return an error if the DPE does not support CSRs.
    /// Otherwise, the platform can choose either SubjectKeyIdentifier or IssuerAndSerialNumber.
    fn get_signer_identifier(&mut self) -> Result<SignerIdentifier, PlatformError>;

    fn get_vendor_id(&mut self) -> Result<u32, PlatformError>;

    fn get_vendor_sku(&mut self) -> Result<u32, PlatformError>;

    fn get_auto_init_locality(&mut self) -> Result<u32, PlatformError>;

    fn write_str(&mut self, str: &str) -> Result<(), PlatformError>;

    /// Retrieves the DPE certificate's validity period
    ///
    /// Each output string should represent a valid ISO 8601 date and time
    /// in the yyyyMMddHHmmss format followed by a timezone.
    ///
    /// Example: 99991231235959Z is December 31st, 9999 23:59:59 UTC
    fn get_cert_validity<'a>(&mut self) -> Result<CertValidity<'a>, PlatformError>;
}
