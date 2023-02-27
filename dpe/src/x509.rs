//! Lightweight X.509 encoding routines for DPE
//!
//! DPE requires encoding variable-length certificates. This module provides
//! this functionality for a no_std environment.

use crate::{response::DpeErrorCode, DpeProfile, DPE_PROFILE};

pub struct EcdsaSignature {
    r: [u8; DPE_PROFILE.get_ecc_int_size()],
    s: [u8; DPE_PROFILE.get_ecc_int_size()],
}

pub struct EcdsaPub {
    x: [u8; DPE_PROFILE.get_ecc_int_size()],
    y: [u8; DPE_PROFILE.get_ecc_int_size()],
}

pub struct Name<'a> {
    cn: &'a str,
    serial: &'a str,
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
    const PRINTABLE_STRING_TAG: u8 = 0x13;
    const GENERALIZE_TIME_TAG: u8 = 0x18;
    const SEQUENCE_TAG: u8 = 0x30;
    const SEQUENCE_OF_TAG: u8 = 0x30;
    const SET_TAG: u8 = 0x31;
    const SET_OF_TAG: u8 = 0x31;

    const X509_V3: u64 = 2;

    const ECDSA_OID: &[u8] = match DPE_PROFILE {
        // ECDSA with SHA256
        DpeProfile::P256Sha256 => &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02],
        // ECDSA with SHA384
        DpeProfile::P384Sha384 => &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03],
    };

    const CURVE_OID: &[u8] = match DPE_PROFILE {
        // P256
        DpeProfile::P256Sha256 => &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
        // P384
        DpeProfile::P384Sha384 => &[0x2B, 0x81, 0x04, 0x00, 0x22],
    };

    const RDN_COMMON_NAME_OID: [u8; 3] = [0x55, 0x04, 0x03];
    const RDN_SERIALNUMBER_OID: [u8; 3] = [0x55, 0x04, 0x05];

    // All DPE certs are valid from January 1st, 2023 00:00:00 until
    // December 31st, 9999 23:59:59
    const NOT_BEFORE: &str = "20230227000000Z";
    const NOT_AFTER: &str = "99991231235959Z";

    pub fn new(cert: &mut [u8]) -> X509CertWriter {
        X509CertWriter {
            certificate: cert,
            offset: 0,
        }
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

    /// Get the size of an ASN.1 structure
    /// If tagged, includes the tag and size
    fn get_structure_size(data_size: usize, tagged: bool) -> Result<usize, DpeErrorCode> {
        let size = if tagged {
            1 + Self::get_size_width(data_size)? + data_size
        } else {
            data_size
        };

        Ok(size)
    }

    /// Calculate the number of bytes the ASN.1 INTEGER will be
    /// If `tagged`, include the tag and size fields
    fn get_integer_bytes_size(integer: &[u8], tagged: bool) -> Result<usize, DpeErrorCode> {
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

        Self::get_structure_size(len, tagged)
    }

    /// Calculate the number of bytes the ASN.1 INTEGER will be
    /// If `tagged`, include the tag and size fields
    fn get_integer_size(integer: u64, tagged: bool) -> Result<usize, DpeErrorCode> {
        let bytes = integer.to_be_bytes();
        Self::get_integer_bytes_size(&bytes, tagged)
    }

    /// Calculate the number of bytes an ASN.1 raw bytes field will be.
    /// Can be used for OCTET STRING, OID, UTF8 STRING, etc.
    /// If `tagged`, include the tag and size fields
    fn get_bytes_size(bytes: &[u8], tagged: bool) -> Result<usize, DpeErrorCode> {
        Self::get_structure_size(bytes.len(), tagged)
    }

    /// If `tagged`, include the tag and size fields
    fn get_rdn_size(name: &Name, tagged: bool) -> Result<usize, DpeErrorCode> {
        let cn_seq_size = Self::get_structure_size(
            Self::get_bytes_size(&Self::RDN_COMMON_NAME_OID, /*tagged=*/ true)?
                + Self::get_bytes_size(name.cn.as_bytes(), true)?,
            /*tagged=*/ true,
        )?;
        let serialnumber_seq_size = Self::get_structure_size(
            Self::get_bytes_size(&Self::RDN_COMMON_NAME_OID, /*tagged=*/ true)?
                + Self::get_bytes_size(name.serial.as_bytes(), /*tagged=*/ true)?,
            /*tagged=*/ true,
        )?;

        let set_len =
            Self::get_structure_size(cn_seq_size + serialnumber_seq_size, /*tagged=*/ true)?;

        Self::get_structure_size(set_len, tagged)
    }

    /// Calculate the number of bytes an ECC AlgorithmIdentifier will be
    /// If `tagged`, include the tag and size fields
    fn get_ecc_alg_id_size(tagged: bool) -> Result<usize, DpeErrorCode> {
        let len = Self::get_bytes_size(Self::ECDSA_OID, true)?
            + Self::get_bytes_size(Self::CURVE_OID, true)?;
        Self::get_structure_size(len, tagged)
    }

    /// If `tagged`, include the tag and size fields
    fn get_validity_size(tagged: bool) -> Result<usize, DpeErrorCode> {
        let len = Self::get_bytes_size(Self::NOT_BEFORE.as_bytes(), true)?
            + Self::get_bytes_size(Self::NOT_AFTER.as_bytes(), true)?;
        Self::get_structure_size(len, tagged)
    }

    /// Calculate the number of bytes an ECC SubjectPublicKeyInfo will be
    /// If `tagged`, include the tag and size fields
    fn get_ecdsa_subject_pubkey_info_size(
        pubkey: &EcdsaPub,
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        let point_size = 1 + pubkey.x.len() + pubkey.y.len();
        let len = Self::get_ecc_alg_id_size(/*tagged=*/ true)?
            + Self::get_structure_size(point_size, /*tagged=*/ true)?;

        let bitstring_size = 1 + Self::get_structure_size(point_size, /*tagged=*/ true)?;
        let seq_size = Self::get_structure_size(bitstring_size, /*tagged=*/ true)?
            + Self::get_ecc_alg_id_size(/*tagged=*/ true)?;

        Self::get_structure_size(seq_size, tagged)
    }

    /// If `tagged`, include the tag and size fields
    fn get_ecdsa_signature_size(sig: &EcdsaSignature, tagged: bool) -> Result<usize, DpeErrorCode> {
        let seq_size = Self::get_structure_size(
            Self::get_integer_bytes_size(&sig.r, /*tagged=*/ true)?
                + Self::get_integer_bytes_size(&sig.s, /*tagged=*/ true)?,
            /*tagged=*/ true,
        )?;
        let bitstring_size = Self::get_structure_size(1 + seq_size, /*tagged=*/ true)?;

        Self::get_structure_size(bitstring_size, tagged)
    }

    /// version is marked as EXPLICIT [0]
    /// If `tagged`, include the explicit tag and size fields
    fn get_version_size(tagged: bool) -> Result<usize, DpeErrorCode> {
        let integer_size = Self::get_integer_size(Self::X509_V3, /*tagged=*/ true)?;

        // If tagged, also add explicit wrapping
        Self::get_structure_size(integer_size, tagged)
    }

    /// Get the size of the ASN.1 TBSCertificate structure
    /// If `tagged`, include the tag and size fields
    fn get_tbs_size(
        serial_number: &[u8],
        issuer_name: &Name,
        subject_name: &Name,
        pubkey: &EcdsaPub,
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        let tbs_size = Self::get_version_size(/*tagged=*/ true)?
            + Self::get_integer_bytes_size(serial_number, /*tagged=*/ true)?
            + Self::get_ecc_alg_id_size(/*tagged=*/ true)?
            + Self::get_rdn_size(issuer_name, /*tagged=*/ true)?
            + Self::get_validity_size(/*tagged=*/ true)?
            + Self::get_rdn_size(subject_name, /*tagged=*/ true)?
            + Self::get_ecdsa_subject_pubkey_info_size(pubkey, /*tagged=*/ true)?;

        Self::get_structure_size(tbs_size, tagged)
    }

    /// Write all of `bytes` to the certificate buffer
    fn encode_bytes(&mut self, bytes: &[u8]) -> Result<usize, DpeErrorCode> {
        let size = bytes.len();

        if size > self.certificate.len().saturating_sub(self.offset) {
            return Err(DpeErrorCode::InternalError);
        }

        self.certificate[self.offset..self.offset + size].copy_from_slice(bytes);
        self.offset += size;

        Ok(size)
    }

    /// Write a single `byte` to be certificate buffer
    fn encode_byte(&mut self, byte: u8) -> Result<usize, DpeErrorCode> {
        if self.offset >= self.certificate.len() {
            return Err(DpeErrorCode::InternalError);
        }

        self.certificate[self.offset] = byte;
        self.offset += 1;
        Ok(1)
    }

    /// DER-encodes the tag field of an ASN.1 type
    fn encode_tag_field(&mut self, tag: u8) -> Result<usize, DpeErrorCode> {
        self.encode_byte(tag)
    }

    /// DER-encodes the size field of an ASN.1 type)
    fn encode_size_field(&mut self, size: usize) -> Result<usize, DpeErrorCode> {
        let size_width = Self::get_size_width(size)?;

        if size_width == 1 {
            self.encode_byte(size as u8)?;
        } else {
            let rem = size_width - 1;
            self.encode_byte(0x80 | rem as u8)?;

            for i in (0..rem).rev() {
                self.encode_byte((size >> (i * 8)) as u8)?;
            }
        }

        Ok(size_width)
    }

    /// DER-encodes a big-endian integer buffer as an ASN.1 INTEGER
    fn encode_integer_bytes(&mut self, integer: &[u8]) -> Result<usize, DpeErrorCode> {
        let mut bytes_written = self.encode_tag_field(Self::INTEGER_TAG)?;

        let size = Self::get_integer_bytes_size(integer, false)?;
        bytes_written += self.encode_size_field(size)?;

        // Compute where to start reading from integer (strips leading zeros)
        let integer_offset = integer.len().saturating_sub(size);

        // If size got larger it is because a null byte needs to be prepended
        if size > integer.len() {
            bytes_written += self.encode_byte(0)?;
        }

        bytes_written += self.encode_bytes(&integer[integer_offset..])?;

        Ok(bytes_written)
    }

    /// DER-encodes `integer` as an ASN.1 INTEGER
    fn encode_integer(&mut self, integer: u64) -> Result<usize, DpeErrorCode> {
        self.encode_integer_bytes(&integer.to_be_bytes())
    }

    /// DER-encodes `oid` as an ASN.1 ObjectIdentifier
    fn encode_oid(&mut self, oid: &[u8]) -> Result<usize, DpeErrorCode> {
        let mut bytes_written = self.encode_tag_field(Self::OID_TAG)?;
        bytes_written += self.encode_size_field(oid.len())?;
        bytes_written += self.encode_bytes(oid)?;

        Ok(bytes_written)
    }

    fn encode_printable_string(&mut self, s: &str) -> Result<usize, DpeErrorCode> {
        let mut bytes_written = self.encode_tag_field(Self::PRINTABLE_STRING_TAG)?;
        bytes_written += self.encode_size_field(s.len())?;
        bytes_written += self.encode_bytes(s.as_bytes())?;

        Ok(bytes_written)
    }

    /// DER-encodes a RelativeDistinguishedName with CommonName and SerialNumber
    /// fields.
    ///
    /// RelativeDistinguishedName ::=
    ///     SET SIZE (1..MAX) OF AttributeTypeAndValue
    ///
    /// AttributeTypeAndValue ::= SEQUENCE {
    ///     type     AttributeType,
    ///     value    AttributeValue }
    ///
    /// AttributeType ::= OBJECT IDENTIFIER
    /// AttributeValue ::= ANY -- DEFINED BY AttributeType
    ///
    /// CommonName and SerialNumber ::= CHOICE {
    ///     ...
    ///     printableString   PrintableString (SIZE (1..ub-common-name)),
    ///     ...
    ///     }
    fn encode_rdn(&mut self, name: &Name) -> Result<usize, DpeErrorCode> {
        let cn_size =
            Self::get_structure_size(Self::RDN_COMMON_NAME_OID.len(), /*tagged=*/ true)?
                + Self::get_structure_size(name.cn.len(), /*tagged=*/ true)?;
        let serialnumber_size =
            Self::get_structure_size(Self::RDN_COMMON_NAME_OID.len(), /*tagged=*/ true)?
                + Self::get_structure_size(name.serial.len(), /*tagged=*/ true)?;

        let rdn_set_size = Self::get_structure_size(cn_size, /*tagged=*/ true)?
            + Self::get_structure_size(serialnumber_size, /*tagged=*/ true)?;
        let rdn_seq_size = Self::get_structure_size(rdn_set_size, /*tagged=*/ true)?;

        // Encode RDN SEQUENCE OF
        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_OF_TAG)?;
        bytes_written += self.encode_size_field(rdn_seq_size)?;

        // Encode RDN SET
        bytes_written += self.encode_tag_field(Self::SET_OF_TAG)?;
        bytes_written += self.encode_size_field(rdn_set_size)?;

        // Encode CN SEQUENCE
        bytes_written += self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(cn_size)?;
        bytes_written += self.encode_oid(&Self::RDN_COMMON_NAME_OID)?;
        bytes_written += self.encode_printable_string(name.cn)?;

        // Encode SERIALNUMBER SEQUENCE
        bytes_written += self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(serialnumber_size)?;
        bytes_written += self.encode_oid(&Self::RDN_SERIALNUMBER_OID)?;
        bytes_written += self.encode_printable_string(name.serial)?;

        Ok(bytes_written)
    }

    /// DER-encodes the AlgorithmIdentifier for the signing algorithm used by
    /// the active DPE profile.
    ///
    /// AlgorithmIdentifier  ::=  SEQUENCE  {
    ///     algorithm   OBJECT IDENTIFIER,
    ///     parameters  ECParameters
    ///     }
    ///
    /// ECParameters ::= CHOICE {
    ///       namedCurve         OBJECT IDENTIFIER
    ///       -- implicitCurve   NULL
    ///       -- specifiedCurve  SpecifiedECDomain
    ///     }
    fn encode_ecc_alg_id(&mut self) -> Result<usize, DpeErrorCode> {
        let seq_size = Self::get_ecc_alg_id_size(/*tagged=*/ false)?;

        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(seq_size)?;
        bytes_written += self.encode_oid(Self::ECDSA_OID)?;
        bytes_written += self.encode_oid(Self::CURVE_OID)?;

        Ok(bytes_written)
    }

    // Encode ASN.1 Validity which never expires
    fn encode_validity(&mut self) -> Result<usize, DpeErrorCode> {
        let seq_size = Self::get_validity_size(/*tagged=*/ false)?;

        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(seq_size)?;

        bytes_written += self.encode_tag_field(Self::GENERALIZE_TIME_TAG)?;
        bytes_written += self.encode_size_field(Self::NOT_BEFORE.len())?;
        bytes_written += self.encode_bytes(Self::NOT_BEFORE.as_bytes())?;

        bytes_written += self.encode_tag_field(Self::GENERALIZE_TIME_TAG)?;
        bytes_written += self.encode_size_field(Self::NOT_AFTER.len())?;
        bytes_written += self.encode_bytes(Self::NOT_AFTER.as_bytes())?;

        Ok(bytes_written)
    }

    /// Encode SubjectPublicKeyInfo for an ECDSA public key
    ///
    /// Returns number of bytes written to `remaining_cert`
    ///
    /// SubjectPublicKeyInfo  ::=  SEQUENCE  {
    ///        algorithm            AlgorithmIdentifier,
    ///        subjectPublicKey     BIT STRING  }
    ///
    /// subjectPublicKey is a BIT STRING containing an ECPoint
    /// in uncompressed format.
    ///
    /// ECPoint ::= OCTET STRING
    fn encode_ecdsa_subject_pubkey_info(
        &mut self,
        pubkey: &EcdsaPub,
    ) -> Result<usize, DpeErrorCode> {
        let point_size = 1 + pubkey.x.len() + pubkey.y.len();
        let bitstring_size = 1 + Self::get_structure_size(point_size, /*tagged=*/ true)?;
        let seq_size = Self::get_structure_size(bitstring_size, /*tagged=*/ true)?
            + Self::get_ecc_alg_id_size(/*tagged=*/ true)?;

        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(seq_size)?;
        bytes_written += self.encode_ecc_alg_id()?;

        bytes_written += self.encode_tag_field(Self::BIT_STRING_TAG)?;
        bytes_written += self.encode_size_field(bitstring_size)?;
        // First byte of BIT STRING is the number of unused bits. But all bits
        // are used.
        bytes_written += self.encode_byte(0)?;

        bytes_written += self.encode_tag_field(Self::OCTET_STRING_TAG)?;
        bytes_written += self.encode_size_field(point_size)?;
        bytes_written += self.encode_byte(0x4)?;
        bytes_written += self.encode_bytes(&pubkey.x)?;
        bytes_written += self.encode_bytes(&pubkey.y)?;

        Ok(bytes_written)
    }

    /// BIT STRING containing
    ///
    /// ECDSA-Sig-Value ::= SEQUENCE {
    ///     r  INTEGER,
    ///     s  INTEGER
    ///   }
    fn encode_ecdsa_signature(&mut self, sig: &EcdsaSignature) -> Result<usize, DpeErrorCode> {
        let seq_size = Self::get_integer_bytes_size(&sig.r, /*tagged=*/ true)?
            + Self::get_integer_bytes_size(&sig.s, /*tagged=*/ true)?;

        // Encode BIT STRING
        let mut bytes_written = self.encode_tag_field(Self::BIT_STRING_TAG)?;
        bytes_written += self.encode_size_field(Self::get_structure_size(
            1 + seq_size,
            /*tagged=*/ true,
        )?)?;
        // Unused bits
        bytes_written += self.encode_byte(0)?;

        // Encode SEQUENCE
        bytes_written += self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(seq_size)?;
        bytes_written += self.encode_integer_bytes(&sig.r)?;
        bytes_written += self.encode_integer_bytes(&sig.s)?;

        Ok(bytes_written)
    }

    pub fn encode_version(&mut self) -> Result<usize, DpeErrorCode> {
        // Version is EXPLICIT field number 0
        const EXPLICIT_TAG: u8 = 0xA0;
        let mut bytes_written = self.encode_byte(EXPLICIT_TAG)?;
        bytes_written += self.encode_size_field(Self::get_integer_size(
            Self::X509_V3,
            /*tagged=*/ true,
        )?)?;
        bytes_written += self.encode_integer(Self::X509_V3)?;

        Ok(bytes_written)
    }

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
    pub fn encode_ecdsa_tbs(
        &mut self,
        serial_number: &[u8],
        issuer_name: &Name,
        subject_name: &Name,
        pubkey: &EcdsaPub,
    ) -> Result<usize, DpeErrorCode> {
        let tbs_size = Self::get_tbs_size(
            serial_number,
            issuer_name,
            subject_name,
            pubkey,
            /*tagged=*/ false,
        )?;

        // TBS sequence
        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(tbs_size)?;

        // version
        bytes_written += self.encode_version()?;

        // serialNumber
        bytes_written += self.encode_integer_bytes(serial_number)?;

        // signature
        bytes_written += self.encode_ecc_alg_id()?;

        // issuer
        bytes_written += self.encode_rdn(issuer_name)?;

        // validity
        bytes_written += self.encode_validity()?;

        // subject
        bytes_written += self.encode_rdn(subject_name)?;

        // subjectPublicKeyInfo
        bytes_written += self.encode_ecdsa_subject_pubkey_info(pubkey)?;

        // TODO: extensions
        Ok(bytes_written)
    }

    /// Encode an ECDSA X.509 certificate
    ///
    /// Returns number of bytes written to `scratch`
    ///
    /// Certificate  ::=  SEQUENCE  {
    ///    tbsCertificate       TBSCertificate,
    ///    signatureAlgorithm   AlgorithmIdentifier,
    ///    signatureValue       BIT STRING  }
    pub fn encode_ecdsa_certificate(
        &mut self,
        serial_number: &[u8],
        issuer_name: &Name,
        subject_name: &Name,
        pubkey: &EcdsaPub,
        sig: &EcdsaSignature,
    ) -> Result<usize, DpeErrorCode> {
        let tbs_size = Self::get_tbs_size(
            serial_number,
            issuer_name,
            subject_name,
            pubkey,
            /*tagged=*/ true,
        )?;
        let cert_size = tbs_size
            + Self::get_ecc_alg_id_size(/*tagged=*/ true)?
            + Self::get_ecdsa_signature_size(sig, /*tagged=*/ true)?;

        // Certificate sequence
        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(cert_size)?;

        // TBS
        bytes_written += self.encode_ecdsa_tbs(serial_number, issuer_name, subject_name, pubkey)?;

        // Alg ID
        bytes_written += self.encode_ecc_alg_id()?;

        // Signature
        bytes_written += self.encode_ecdsa_signature(sig)?;

        Ok(bytes_written)
    }
}

#[cfg(test)]
mod tests {
    use crate::x509::{EcdsaPub, EcdsaSignature, Name, X509CertWriter};
    use crate::{DpeProfile, DPE_PROFILE};
    use asn1;
    use x509_parser::certificate::X509CertificateParser;
    use x509_parser::nom::Parser;
    use x509_parser::prelude::*;

    #[test]
    fn test_integers() {
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
            assert_eq!(
                X509CertWriter::get_integer_bytes_size(&c, true).unwrap(),
                byte_count
            );
        }

        let integer_cases = [0xFFFFFFFF00000000, 0x0102030405060708, 0x2];

        for c in integer_cases {
            let mut cert = [0; 128];
            let mut w = X509CertWriter::new(&mut cert);
            let byte_count = w.encode_integer(c).unwrap();
            let n = asn1::parse_single::<u64>(&cert[..byte_count]).unwrap();
            assert_eq!(n, c);
            assert_eq!(
                X509CertWriter::get_integer_size(c, true).unwrap(),
                byte_count
            );
        }
    }

    #[test]
    fn test_rdn() {
        let mut cert = [0u8; 128];
        let test_name = Name {
            cn: "Caliptra Alias",
            serial: "0x00000000",
        };

        let mut w = X509CertWriter::new(&mut cert);
        let bytes_written = w.encode_rdn(&test_name).unwrap();

        let name = match X509Name::from_der(&cert[..bytes_written]) {
            Ok((rem, name)) => name,
            Err(e) => panic!("Name parsing failed: {:?}", e),
        };

        let expected = format!("CN={} + serialNumber={}", test_name.cn, test_name.serial);
        let actual = name.to_string_with_registry(oid_registry()).unwrap();
        assert_eq!(expected, actual);

        assert_eq!(
            X509CertWriter::get_rdn_size(&test_name, true).unwrap(),
            bytes_written
        );
    }

    #[test]
    fn test_subject_pubkey() {
        let mut cert = [0u8; 256];
        let test_key = EcdsaPub {
            x: [0; DPE_PROFILE.get_ecc_int_size()],
            y: [0; DPE_PROFILE.get_ecc_int_size()],
        };

        let mut w = X509CertWriter::new(&mut cert);
        let bytes_written = w.encode_ecdsa_subject_pubkey_info(&test_key).unwrap();

        let name = match SubjectPublicKeyInfo::from_der(&cert[..bytes_written]) {
            Ok((rem, name)) => name,
            Err(e) => panic!("Subject pki parsing failed: {:?}", e),
        };

        assert_eq!(
            X509CertWriter::get_ecdsa_subject_pubkey_info_size(&test_key, true).unwrap(),
            bytes_written
        );
    }

    #[test]
    fn test_tbs() {
        let mut cert = [0u8; 4096];
        let mut w = X509CertWriter::new(&mut cert);

        let test_serial = [0x1F; 20];
        let test_issuer_name = Name {
            cn: "Caliptra Alias",
            serial: "0x00000000",
        };

        let test_subject_name = Name {
            cn: "DPE Leaf",
            serial: "0x00000000",
        };

        let test_pub = EcdsaPub {
            x: [0xAA; DPE_PROFILE.get_ecc_int_size()],
            y: [0xBB; DPE_PROFILE.get_ecc_int_size()],
        };

        let bytes_written = w
            .encode_ecdsa_tbs(
                &test_serial,
                &test_issuer_name,
                &test_subject_name,
                &test_pub,
            )
            .unwrap();

        let mut parser = TbsCertificateParser::new().with_deep_parse_extensions(false);
        let cert = match parser.parse(&cert) {
            Ok((rem, cert)) => {
                assert_eq!(cert.version(), X509Version::V3);
                cert
            }
            Err(e) => panic!("x509 parsing failed: {:?}", e),
        };
    }

    #[test]
    fn test_full_cert() {
        let mut cert = [0u8; 4096];
        let mut w = X509CertWriter::new(&mut cert);

        let test_serial = [0x1F; 20];
        let test_issuer_name = Name {
            cn: "Caliptra Alias",
            serial: "0x00000000",
        };

        let test_subject_name = Name {
            cn: "DPE Leaf",
            serial: "0x00000000",
        };

        let test_pub = EcdsaPub {
            x: [0xAA; DPE_PROFILE.get_ecc_int_size()],
            y: [0xBB; DPE_PROFILE.get_ecc_int_size()],
        };
        let test_sig = EcdsaSignature {
            r: [0xCC; DPE_PROFILE.get_ecc_int_size()],
            s: [0xDD; DPE_PROFILE.get_ecc_int_size()],
        };

        let bytes_written = w
            .encode_ecdsa_certificate(
                &test_serial,
                &test_issuer_name,
                &test_subject_name,
                &test_pub,
                &test_sig,
            )
            .unwrap();

        let mut parser = X509CertificateParser::new().with_deep_parse_extensions(false);
        let cert = match parser.parse(&cert) {
            Ok((rem, cert)) => {
                assert_eq!(cert.version(), X509Version::V3);
                cert
            }
            Err(e) => panic!("x509 parsing failed: {:?}", e),
        };
    }
}
