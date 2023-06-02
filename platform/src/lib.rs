/*++
Licensed under the Apache-2.0 license.
Abstract:
    Generic trait definition of platform.
--*/
#![cfg_attr(not(test), no_std)]

pub use default::*;
mod default;

pub const MAX_CHUNK_SIZE: usize = 2048;

pub enum PlatformError {
    CertificateChainError,
    NotImplemented,
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
        offset: u32,
        size: u32,
        out: &mut [u8; MAX_CHUNK_SIZE],
    ) -> Result<u32, PlatformError>;
}
