// Licensed under the Apache-2.0 license

use crate::{
    CertValidity, Platform, PlatformError, SignerIdentifier, SubjectAltName, Ueid, MAX_CHUNK_SIZE,
    MAX_ISSUER_NAME_SIZE, MAX_KEY_IDENTIFIER_SIZE,
};
use arrayvec::ArrayVec;
use cfg_if::cfg_if;
use core::cmp::min;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DefaultPlatformProfile {
    P256,
    P384,
}

// Run ./generate.sh to generate all test certs and test private keys
impl DefaultPlatformProfile {
    pub fn pem(&self) -> &'static [u8] {
        match self {
            DefaultPlatformProfile::P256 => include_bytes!("test_data/cert_256.pem"),
            DefaultPlatformProfile::P384 => include_bytes!("test_data/cert_384.pem"),
        }
    }

    pub fn cert_chain(&self) -> &'static [u8] {
        match self {
            DefaultPlatformProfile::P256 => include_bytes!("test_data/cert_256.der"),
            DefaultPlatformProfile::P384 => include_bytes!("test_data/cert_384.der"),
        }
    }
}

pub struct DefaultPlatform(pub DefaultPlatformProfile);

pub const AUTO_INIT_LOCALITY: u32 = 0;
pub const VENDOR_ID: u32 = 0;
pub const VENDOR_SKU: u32 = 0;
pub const NOT_BEFORE: &str = "20230227000000Z";
pub const NOT_AFTER: &str = "99991231235959Z";
pub const TEST_UEID: [u8; 17] = [0xA; 17];

cfg_if! {
    if #[cfg(feature = "openssl")] {
        mod parse {
            use super::*;
            use openssl::x509::X509;
            pub struct DefaultPlatform;
            impl DefaultPlatform {
                pub fn parse_issuer_name(p: DefaultPlatformProfile) -> Vec<u8> {
                    X509::from_pem(p.pem())
                        .unwrap()
                        .issuer_name()
                        .to_der()
                        .unwrap()
                }
                pub fn parse_issuer_sn(p: DefaultPlatformProfile) -> Vec<u8> {
                    X509::from_pem(p.pem())
                        .unwrap()
                        .serial_number()
                        .to_bn()
                        .unwrap()
                        .to_vec()
                }
                pub fn parse_key_identifier(p: DefaultPlatformProfile) -> Vec<u8> {
                    X509::from_pem(p.pem())
                        .unwrap()
                        .subject_key_id()
                        .unwrap()
                        .as_slice()
                        .to_vec()
                }
            }
        }
    } else if #[cfg(feature = "rustcrypto")] {
        mod parse {
            use super::*;
            use x509_cert::{
                certificate::Certificate,
                der::{DecodePem, Encode},
                ext::pkix::SubjectKeyIdentifier,
            };
            pub struct DefaultPlatform;
            impl DefaultPlatform {
                pub fn parse_issuer_name(p: DefaultPlatformProfile) -> Vec<u8> {
                    Certificate::from_pem(p.pem())
                        .unwrap()
                        .tbs_certificate
                        .issuer
                        .to_der()
                        .unwrap()
                }
                pub fn parse_issuer_sn(p: DefaultPlatformProfile) -> Vec<u8> {
                    Certificate::from_pem(p.pem())
                        .unwrap()
                        .tbs_certificate
                        .serial_number
                        .as_bytes()
                        .to_vec()
                }
                pub fn parse_key_identifier(p: DefaultPlatformProfile) -> Vec<u8> {
                    let (_, ski): (bool, SubjectKeyIdentifier) = Certificate::from_pem(p.pem())
                        .unwrap()
                        .tbs_certificate
                        .get()
                        .unwrap()
                        .unwrap();
                    ski.0.as_bytes().to_vec()
                }
            }
        }
    }
}

impl Platform for DefaultPlatform {
    fn get_certificate_chain(
        &mut self,
        offset: u32,
        size: u32,
        out: &mut [u8; MAX_CHUNK_SIZE],
    ) -> Result<u32, PlatformError> {
        let len = self.0.cert_chain().len() as u32;
        if offset >= len {
            return Err(PlatformError::CertificateChainError);
        }

        let cert_chunk_range_end = min(offset + size, len);
        let bytes_written = cert_chunk_range_end - offset;
        if bytes_written as usize > MAX_CHUNK_SIZE {
            return Err(PlatformError::CertificateChainError);
        }

        out[..bytes_written as usize]
            .copy_from_slice(&self.0.cert_chain()[offset as usize..cert_chunk_range_end as usize]);
        Ok(bytes_written)
    }

    fn get_issuer_name(
        &mut self,
        out: &mut [u8; MAX_ISSUER_NAME_SIZE],
    ) -> Result<usize, PlatformError> {
        let issuer_name = parse::DefaultPlatform::parse_issuer_name(self.0);
        if issuer_name.len() > out.len() {
            return Err(PlatformError::IssuerNameError(0));
        }
        out[..issuer_name.len()].copy_from_slice(&issuer_name);
        Ok(issuer_name.len())
    }

    fn get_signer_identifier(&mut self) -> Result<SignerIdentifier, PlatformError> {
        let mut issuer_name = [0u8; MAX_ISSUER_NAME_SIZE];
        let issuer_len = self.get_issuer_name(&mut issuer_name)?;
        let sn = parse::DefaultPlatform::parse_issuer_sn(self.0);
        let mut issuer_name_vec = ArrayVec::new();
        issuer_name_vec
            .try_extend_from_slice(&issuer_name[..issuer_len])
            .map_err(|_| PlatformError::IssuerNameError(0))?;
        let mut serial_number_vec = ArrayVec::new();
        serial_number_vec
            .try_extend_from_slice(&sn)
            .map_err(|_| PlatformError::SerialNumberError(0))?;
        Ok(SignerIdentifier::IssuerAndSerialNumber {
            issuer_name: issuer_name_vec,
            serial_number: serial_number_vec,
        })
    }

    fn get_issuer_key_identifier(
        &mut self,
        out: &mut [u8; MAX_KEY_IDENTIFIER_SIZE],
    ) -> Result<(), PlatformError> {
        let key_identifier = parse::DefaultPlatform::parse_key_identifier(self.0);
        if key_identifier.len() < MAX_KEY_IDENTIFIER_SIZE {
            return Err(PlatformError::IssuerKeyIdentifierError(0));
        }
        out.copy_from_slice(&key_identifier[..MAX_KEY_IDENTIFIER_SIZE]);
        Ok(())
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

    fn get_cert_validity(&mut self) -> Result<CertValidity, PlatformError> {
        let mut not_before_vec = ArrayVec::new();
        not_before_vec
            .try_extend_from_slice(NOT_BEFORE.as_bytes())
            .map_err(|_| PlatformError::CertValidityError(0))?;
        let mut not_after_vec = ArrayVec::new();
        not_after_vec
            .try_extend_from_slice(NOT_AFTER.as_bytes())
            .map_err(|_| PlatformError::CertValidityError(0))?;
        Ok(CertValidity {
            not_before: not_before_vec,
            not_after: not_after_vec,
        })
    }

    fn get_subject_alternative_name(&mut self) -> Result<SubjectAltName, PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn get_ueid(&mut self) -> Result<Ueid, PlatformError> {
        let buf_size = TEST_UEID.len() as u32;
        let mut ueid = Ueid::default();

        ueid.buf[..buf_size as usize].clone_from_slice(&TEST_UEID);
        ueid.buf_size = buf_size;

        Ok(ueid)
    }
}
