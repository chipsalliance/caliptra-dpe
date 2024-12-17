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

// Max cert chunk returned by GetCertificateChain
pub const MAX_CHUNK_SIZE: usize = 2048;
pub const MAX_ISSUER_NAME_SIZE: usize = 128;
pub const MAX_SN_SIZE: usize = 20;
pub const MAX_KEY_IDENTIFIER_SIZE: usize = 20;
pub const MAX_VALIDITY_SIZE: usize = 24;
pub const MAX_OTHER_NAME_SIZE: usize = 128;
// Hash size of the SHA-384 DPE profile
pub const MAX_UEID_SIZE: usize = 48;

pub struct Ueid {
    pub buf: [u8; MAX_UEID_SIZE],
    pub buf_size: u32,
}

impl Ueid {
    pub fn get(&self) -> Result<&[u8], PlatformError> {
        let ueid = self
            .buf
            .get(..self.buf_size as usize)
            .ok_or(PlatformError::InvalidUeidError)?;
        Ok(ueid)
    }
}

impl Default for Ueid {
    fn default() -> Self {
        Self {
            buf: [0; MAX_UEID_SIZE],
            buf_size: 0,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SignerIdentifier {
    IssuerAndSerialNumber {
        issuer_name: ArrayVec<u8, { MAX_ISSUER_NAME_SIZE }>,
        serial_number: ArrayVec<u8, { MAX_SN_SIZE }>,
    },
    SubjectKeyIdentifier(ArrayVec<u8, { MAX_KEY_IDENTIFIER_SIZE }>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum SubjectAltName {
    OtherName(OtherName),
}

#[derive(Debug, PartialEq, Eq)]
pub struct OtherName {
    pub oid: &'static [u8],
    pub other_name: ArrayVec<u8, { MAX_OTHER_NAME_SIZE }>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CertValidity {
    pub not_before: ArrayVec<u8, { MAX_VALIDITY_SIZE }>,
    pub not_after: ArrayVec<u8, { MAX_VALIDITY_SIZE }>,
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
    CertValidityError(u32) = 0x7,
    IssuerKeyIdentifierError(u32) = 0x8,
    SubjectAlternativeNameError(u32) = 0x9,
    MissingUeidError = 0xA,
    InvalidUeidError = 0xB,
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
            PlatformError::MissingUeidError => None,
            PlatformError::InvalidUeidError => None,
            PlatformError::IssuerNameError(code) => Some(*code),
            PlatformError::PrintError(code) => Some(*code),
            PlatformError::SerialNumberError(code) => Some(*code),
            PlatformError::SubjectKeyIdentifierError(code) => Some(*code),
            PlatformError::CertValidityError(code) => Some(*code),
            PlatformError::IssuerKeyIdentifierError(code) => Some(*code),
            PlatformError::SubjectAlternativeNameError(code) => Some(*code),
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
    fn get_issuer_name(
        &mut self,
        out: &mut [u8; MAX_ISSUER_NAME_SIZE],
    ) -> Result<usize, PlatformError>;

    /// Retrieves a CMS Content Info's signer identifier
    ///
    /// This function can simply return an error if the DPE does not support CSRs.
    /// Otherwise, the platform can choose either SubjectKeyIdentifier or IssuerAndSerialNumber.
    fn get_signer_identifier(&mut self) -> Result<SignerIdentifier, PlatformError>;

    /// Retrieves the issuer certificate's key identifier
    ///
    /// This function can simply return an error if the DPE does not support CAs or X509s.
    fn get_issuer_key_identifier(
        &mut self,
        out: &mut [u8; MAX_KEY_IDENTIFIER_SIZE],
    ) -> Result<(), PlatformError>;

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
    fn get_cert_validity(&mut self) -> Result<CertValidity, PlatformError>;

    /// Retrieves the SubjectAlternativeName extension
    ///
    /// Currently, only the otherName choice is supported. This function
    /// can be left unimplemented if the SubjectAlternativeName extension is
    /// not needed in the DPE leaf cert or CSR.
    fn get_subject_alternative_name(&mut self) -> Result<SubjectAltName, PlatformError>;

    /// Retrieves the device serial number
    ///
    /// This is encoded into certificates created by DPE.
    fn get_ueid(&mut self) -> Result<Ueid, PlatformError>;
}
