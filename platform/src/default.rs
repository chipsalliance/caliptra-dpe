// Licensed under the Apache-2.0 license

#[cfg(all(feature = "openssl", feature = "rustcrypto"))]
compile_error!("feature \"openssl\" and feature \"rustcrypto\" cannot be enabled at the same time, because they provide duplicate definitions");

use crate::{Platform, PlatformError, MAX_CHUNK_SIZE, MAX_SN_SIZE};
use core::cmp::min;

#[cfg(feature = "openssl")]
use openssl::x509::X509;

#[cfg(feature = "rustcrypto")]
use x509_cert::{
    certificate::Certificate,
    der::{DecodePem, Encode},
};

pub struct DefaultPlatform;

pub const AUTO_INIT_LOCALITY: u32 = 0;
pub const VENDOR_ID: u32 = 0;
pub const VENDOR_SKU: u32 = 0;

// Run ./generate.sh to generate all test certs and test private keys
#[cfg(feature = "dpe_profile_p256_sha256")]
pub const TEST_CERT_CHAIN: &[u8] = include_bytes!("test_data/cert_256.der");

#[cfg(feature = "dpe_profile_p384_sha384")]
pub const TEST_CERT_CHAIN: &[u8] = include_bytes!("test_data/cert_384.der");

#[cfg(feature = "dpe_profile_p256_sha256")]
pub const TEST_CERT_PEM: &[u8] = include_bytes!("test_data/cert_256.pem");

#[cfg(feature = "dpe_profile_p384_sha384")]
pub const TEST_CERT_PEM: &[u8] = include_bytes!("test_data/cert_384.pem");

impl DefaultPlatform {
    #[cfg(feature = "openssl")]
    fn parse_issuer_name() -> Vec<u8> {
        X509::from_pem(TEST_CERT_PEM)
            .unwrap()
            .subject_name()
            .to_der()
            .unwrap()
    }

    #[cfg(feature = "openssl")]
    fn parse_issuer_sn() -> Vec<u8> {
        X509::from_pem(TEST_CERT_PEM)
            .unwrap()
            .serial_number()
            .to_bn()
            .unwrap()
            .to_vec()
    }

    #[cfg(feature = "rustcrypto")]
    fn parse_issuer_name() -> Vec<u8> {
        Certificate::from_pem(TEST_CERT_PEM)
            .unwrap()
            .tbs_certificate
            .subject
            .to_der()
            .unwrap()
    }

    #[cfg(feature = "rustcrypto")]
    fn parse_issuer_sn() -> Vec<u8> {
        Certificate::from_pem(TEST_CERT_PEM)
            .unwrap()
            .tbs_certificate
            .serial_number
            .as_bytes()
            .to_vec()
    }
}

impl Platform for DefaultPlatform {
    fn get_certificate_chain(
        &mut self,
        offset: u32,
        size: u32,
        out: &mut [u8; MAX_CHUNK_SIZE],
    ) -> Result<u32, PlatformError> {
        let len = TEST_CERT_CHAIN.len() as u32;
        if offset >= len {
            return Err(PlatformError::CertificateChainError);
        }

        let cert_chunk_range_end = min(offset + size, len);
        let bytes_written = cert_chunk_range_end - offset;
        if bytes_written as usize > MAX_CHUNK_SIZE {
            return Err(PlatformError::CertificateChainError);
        }

        out[..bytes_written as usize]
            .copy_from_slice(&TEST_CERT_CHAIN[offset as usize..cert_chunk_range_end as usize]);
        Ok(bytes_written)
    }

    fn get_issuer_name(&mut self, out: &mut [u8; MAX_CHUNK_SIZE]) -> Result<usize, PlatformError> {
        let issuer_name = DefaultPlatform::parse_issuer_name();
        if issuer_name.len() > out.len() {
            return Err(PlatformError::IssuerNameError(0));
        }
        out[..issuer_name.len()].copy_from_slice(&issuer_name);
        Ok(issuer_name.len())
    }

    fn get_issuer_sn(&mut self, out: &mut [u8; MAX_SN_SIZE]) -> Result<usize, PlatformError> {
        let sn = DefaultPlatform::parse_issuer_sn();
        if sn.len() > out.len() {
            return Err(PlatformError::IssuerNameError(0));
        }
        out[..sn.len()].copy_from_slice(&sn);
        Ok(sn.len())
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
        print!("{str}");
        Ok(())
    }
}
