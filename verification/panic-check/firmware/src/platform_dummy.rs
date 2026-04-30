// Licensed under the Apache-2.0 license

//! Dummy platform implementation
//!
//! Most of the implementations just return a `NotImplemented`.
//! Usefull for compiletime assertions.

use platform::{
    CertValidity, Platform, PlatformError, SignerIdentifier, SubjectAltName, Ueid, MAX_CHUNK_SIZE,
    MAX_ISSUER_NAME_SIZE, MAX_KEY_IDENTIFIER_SIZE,
};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[allow(dead_code)]
pub enum DefaultPlatformProfile {
    P256,
    P384,
    Mldsa87,
}

#[allow(dead_code)]
pub struct DefaultPlatform(pub DefaultPlatformProfile);

pub const AUTO_INIT_LOCALITY: u32 = 0;
pub const VENDOR_ID: u32 = 0;
pub const VENDOR_SKU: u32 = 0;
pub const TEST_UEID: [u8; 17] = [0xA; 17];

impl Platform for DefaultPlatform {
    fn get_certificate_chain(
        &mut self,
        offset: u32,
        size: u32,
        out: &mut [u8; MAX_CHUNK_SIZE],
    ) -> Result<u32, PlatformError> {
        let _offset = offset;
        let _size = size;
        let _out = out;
        Err(PlatformError::NotImplemented)
    }

    fn get_issuer_name(
        &mut self,
        out: &mut [u8; MAX_ISSUER_NAME_SIZE],
    ) -> Result<usize, PlatformError> {
        let _ = out;
        Err(PlatformError::NotImplemented)
    }

    fn get_signer_identifier(&mut self) -> Result<SignerIdentifier, PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    fn get_issuer_key_identifier(
        &mut self,
        out: &mut [u8; MAX_KEY_IDENTIFIER_SIZE],
    ) -> Result<(), PlatformError> {
        let _ = out;
        Err(PlatformError::NotImplemented)
    }

    fn get_vendor_id(&mut self) -> Result<u32, PlatformError> {
        Ok(VENDOR_ID)
    }

    fn get_vendor_sku(&mut self) -> Result<u32, PlatformError> {
        Ok(VENDOR_SKU)
    }

    fn get_auto_init_locality(&mut self) -> Result<u32, PlatformError> {
        Ok(AUTO_INIT_LOCALITY)
    }

    fn write_str(&mut self, str: &str) -> Result<(), PlatformError> {
        let _ = str;
        Err(PlatformError::NotImplemented)
    }

    fn get_cert_validity(&mut self) -> Result<CertValidity, PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    fn get_subject_alternative_name(&mut self) -> Result<SubjectAltName, PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn get_ueid(&mut self) -> Result<Ueid, PlatformError> {
        let buf_size = TEST_UEID.len() as u32;
        let mut ueid = Ueid::default();

        ueid.buf
            .get_mut(..buf_size as usize)
            .ok_or(PlatformError::InvalidUeidError)?
            .clone_from_slice(&TEST_UEID);
        ueid.buf_size = buf_size;

        Ok(ueid)
    }
}
