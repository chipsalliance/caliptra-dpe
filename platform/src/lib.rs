/*++
Licensed under the Apache-2.0 license.
Abstract:
    Generic trait definition of platform.
--*/
#![cfg_attr(not(any(feature = "openssl", feature = "rustcrypto", test)), no_std)]

#[cfg(feature = "openssl")]
pub use openssl::x509::X509;

#[cfg(any(feature = "openssl", feature = "rustcrypto"))]
pub mod default;

pub mod printer;

pub const MAX_CHUNK_SIZE: usize = 2048;
pub const MAX_SN_SIZE: usize = 20;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
pub enum PlatformError {
    CertificateChainError = 0x1,
    NotImplemented = 0x2,
    IssuerNameError(u32) = 0x3,
    PrintError(u32) = 0x4,
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

    /// Retrives the issuer's Serial Number
    ///
    /// The issuer serial number is a big-endian integer which is at-most 20
    /// bytes. It must adhere to all the requirements of an ASN.1 integer.
    fn get_issuer_sn(&mut self, out: &mut [u8; MAX_SN_SIZE]) -> Result<usize, PlatformError>;

    fn get_vendor_id(&mut self) -> Result<u32, PlatformError>;

    fn get_vendor_sku(&mut self) -> Result<u32, PlatformError>;

    fn get_auto_init_locality(&mut self) -> Result<u32, PlatformError>;

    fn write_str(&mut self, str: &str) -> Result<(), PlatformError>;
}
