//! Lightweight X.509 encoding routines for DPE
//!
//! DPE requires encoding variable-length certificates. This module provides
//! this functionality for a no_std environment.

use crate::{response::DpeErrorCode, DPE_PROFILE};

pub struct EcdsaSignature {
    r: [u8; DPE_PROFILE.get_ecc_int_size()],
    s: [u8; DPE_PROFILE.get_ecc_int_size()],
}

pub struct EcdsaPub {
    x: [u8; DPE_PROFILE.get_ecc_int_size()],
    y: [u8; DPE_PROFILE.get_ecc_int_size()],
}

/// Calculate the number of bytes the ASN.1 size field will be
fn get_size_width(size: usize) -> Result<usize, DpeErrorCode> {
    if size <= 127 {
        Ok(1)
    } else if size <= 255 {
        Ok(2)
    } else if size <= 65535 {
        Ok(3)
    } else {
        Err(DpeErrorCode::InternalError)
    }
}

/// Calculate the number of bytes the ASN.1 INTEGER will be
fn get_integer_bytes_size(integer: &[u8]) -> usize {
    let mut len = integer.len();
    for (i, &byte) in integer.iter().enumerate() {
        if byte == 0 && i != integer.len() - 1 {
            len -= 1;
        } else if (byte & 0x80) != 0 {
            len += 1;
            break;
        } else {
            break;
        }
    }

    len
}

/// Calculate the number of bytes the ASN.1 INTEGER will be
fn get_integer_size(integer: u32) -> usize {
    let bytes = integer.to_be_bytes();
    get_integer_bytes_size(&bytes)
}

/// Calculate the number of bytes the ASN.1 RelativeDistinguishedName will be
fn get_rdn_size(cn: &str, serial_number: &str) -> Result<u32, DpeErrorCode> {
    Err(DpeErrorCode::InternalError)
}

/// Calculate the number of bytes an ECC AlgorithmIdentifier will be
fn get_ecc_alg_id_size() -> Result<u32, DpeErrorCode> {
    Err(DpeErrorCode::InternalError)
}

/// Calculate the number of bytes an ECC SubjectPublicKeyInfo will be
fn get_ecdsa_subject_pubkey_info_size(pubkey: EcdsaPub) -> Result<u32, DpeErrorCode> {
    Err(DpeErrorCode::InternalError)
}

pub struct X509CertWriter<'a> {
    certificate: &'a mut [u8],
    offset: usize,
}

impl X509CertWriter<'_> {
    const INTEGER_TAG: u8 = 0x2;
    const BIT_STRING_TAG: u8 = 0x3;
    const OCTET_STRING_TAG: u8 = 0x4;
    const OID_TAG: u8 = 0x6;
    const SEQUENCE_TAG: u8 = 0x10;
    const SEQUENCE_OF_TAG: u8 = 0x30;

    pub fn new(cert: &mut [u8]) -> X509CertWriter {
        X509CertWriter {
            certificate: cert,
            offset: 0,
        }
    }

    fn encode_byte(&mut self, byte: u8) -> usize {
        self.certificate[self.offset] = byte;
        self.offset += 1;
        1
    }

    /// DER-encodes the tag field of an ASN.1 type
    fn encode_tag_field(&mut self, tag: u8) -> usize {
        self.encode_byte(tag)
    }

    /// DER-encodes the size field of an ASN.1 type
    fn encode_size_field(&mut self, size: usize) -> Result<usize, DpeErrorCode> {
        let size_width = get_size_width(size)?;

        if size_width == 1 {
            self.encode_byte(size as u8);
        } else {
            self.encode_byte(0x80 | (size_width as u8));
            for i in (0..size_width - 1).rev() {
                self.encode_byte((size >> i) as u8);
            }
        }

        Ok(size_width)
    }

    /// DER-encodes a big-endian integer buffer as an ASN.1 INTEGER
    fn encode_integer_bytes(&mut self, integer: &[u8]) -> Result<usize, DpeErrorCode> {
        let mut bytes_written = self.encode_tag_field(Self::INTEGER_TAG);

        let mut size = get_integer_bytes_size(integer);
        bytes_written += self.encode_size_field(size)?;

        // Compute where to start reading from integer (strips leading zeros)
        let integer_offset = integer.len().saturating_sub(size);

        // If size got larger it is because a null byte needs to be prepended
        if size > integer.len() {
            bytes_written += self.encode_byte(0);
            size -= 1;
        }

        self.certificate[self.offset..self.offset + size]
            .clone_from_slice(&integer[integer_offset..]);

        bytes_written += size;
        self.offset += size;

        Ok(bytes_written)
    }

    /// DER-encodes `integer` as n ASN.1 INTEGER
    fn encode_integer(&mut self, integer: u64) -> Result<usize, DpeErrorCode> {
        self.encode_integer_bytes(&integer.to_be_bytes())
    }

    /// DER-encodes a RelativeDistinguisedName with CommonName and SerialNumber
    /// fields.
    fn encode_rdn(&mut self, cn: &str, serial_number: &str) -> Result<u32, DpeErrorCode> {
        Err(DpeErrorCode::InternalError)
    }

    /// DER-encodes the AlgorithmIdentifier for the signing algorithm used by
    /// the DPE profile.
    ///
    ///AlgorithmIdentifier  ::=  SEQUENCE  {
    ///     algorithm   OBJECT IDENTIFIER,
    ///     parameters  ECParameters
    ///     }
    ///
    /// ECParameters ::= CHOICE {
    ///       namedCurve         OBJECT IDENTIFIER
    ///       -- implicitCurve   NULL
    ///       -- specifiedCurve  SpecifiedECDomain
    ///     }
    fn encode_signature_alg_id(&mut self) -> Result<u32, DpeErrorCode> {
        Err(DpeErrorCode::InternalError)
    }

    /// Encode SubjectPublicKeyInfo for an ECDSA public key
    ///
    /// Returns number of bytes written to `remaining_cert`
    ///
    /// SubjectPublicKeyInfo  ::=  SEQUENCE  {
    ///        algorithm            AlgorithmIdentifier,
    ///        subjectPublicKey     BIT STRING  }
    fn encode_ecdsa_subject_pubkey_info(&mut self, pubkey: &EcdsaPub) -> Result<u32, DpeErrorCode> {
        Err(DpeErrorCode::InternalError)
    }

    /// ECDSA-Sig-Value ::= SEQUENCE {
    ///     r  INTEGER,
    ///     s  INTEGER
    ///   }
    fn encode_ecdsa_signature(&mut self, sig: &EcdsaSignature) -> Result<u32, DpeErrorCode> {
        Err(DpeErrorCode::InternalError)
    }

    /// Encode an ECDSA X.509 certificate
    ///
    /// Returns number of bytes written to `scratch`
    ///
    /// Certificate  ::=  SEQUENCE  {
    ///    tbsCertificate       TBSCertificate,
    ///    signatureAlgorithm   AlgorithmIdentifier,
    ///    signatureValue       BIT STRING  }
    ///
    /// TBSCertificate  ::=  SEQUENCE  {
    ///    version         [0]  EXPLICIT Version DEFAULT v1,
    ///    serialNumber         CertificateSerialNumber,
    ///    signature            AlgorithmIdentifier,
    ///    issuer               Name,
    ///    validity             Validity,
    ///    subject              Name,
    ///    subjectPublicKeyInfo SubjectPublicKeyInfo,
    ///    issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
    ///                         -- If present, version MUST be v2 or v3
    ///    subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
    ///                         -- If present, version MUST be v2 or v3
    ///    extensions      [3]  EXPLICIT Extensions OPTIONAL
    ///                         -- If present, version MUST be v3
    ///    }
    pub fn encode_ecdsa_certificate(
        &mut self,
        pubkey: &EcdsaPub,
        sig: &EcdsaSignature,
    ) -> Result<u32, DpeErrorCode> {
        Err(DpeErrorCode::InternalError)
    }
}

#[cfg(test)]
mod tests {
    use crate::x509::X509CertWriter;
    use asn1;

    #[test]
    fn encode_integers() {
        let buffer_cases = [
            [0; 8],
            [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
            [0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0xFF, 0x04, 0x00, 0x00, 0x00, 0x00],
            [0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00],
        ];

        for c in buffer_cases {
            let mut cert = [0u8; 128];
            let mut w = X509CertWriter::new(&mut cert);
            let byte_count = w.encode_integer_bytes(&c).unwrap();
            let n = asn1::parse_single::<u64>(&cert[..byte_count]).unwrap();
            assert_eq!(n, u64::from_be_bytes(c));
        }

        let integer_cases = [0xFFFFFFFF00000000, 0x0102030405060708];

        for c in integer_cases {
            let mut cert = [0; 128];
            let mut w = X509CertWriter::new(&mut cert);
            let byte_count = w.encode_integer(c).unwrap();
            let n = asn1::parse_single::<u64>(&cert[..byte_count]).unwrap();
            assert_eq!(n, c);
        }
    }
}
