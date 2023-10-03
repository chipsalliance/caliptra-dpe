/*++
Licensed under the Apache-2.0 license.
Abstract:
    Generic trait definition of platform.
--*/
#![cfg_attr(not(any(feature = "openssl", test)), no_std)]

#[cfg(feature = "openssl")]
pub use openssl::x509::X509;

#[cfg(feature = "openssl")]
pub mod default;

pub mod printer;

pub const MAX_CHUNK_SIZE: usize = 2048;

#[derive(Debug)]
pub enum PlatformError {
    CertificateChainError,
    NotImplemented,
    IssuerNameError,
    PrintError,
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

    fn get_vendor_id(&mut self) -> Result<u32, PlatformError>;

    fn get_vendor_sku(&mut self) -> Result<u32, PlatformError>;

    fn get_auto_init_locality(&mut self) -> Result<u32, PlatformError>;

    fn write_str(&mut self, str: &str) -> Result<(), PlatformError>;
}
