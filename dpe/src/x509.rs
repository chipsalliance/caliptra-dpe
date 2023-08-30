// Licensed under the Apache-2.0 license

//! Lightweight X.509 encoding routines for DPE
//!
//! DPE requires encoding variable-length certificates. This module provides
//! this functionality for a no_std environment.

use crate::{
    response::DpeErrorCode,
    tci::{TciMeasurement, TciNodeData},
    DpeProfile, DPE_PROFILE,
};
use crypto::{EcdsaPub, EcdsaSig};

/// Type for specifying an X.509 RelativeDistinguisedName
///
/// `serial` is expected to hold a hex string of the hash of the public key
pub struct Name<'a> {
    pub cn: &'a [u8],
    pub serial: [u8; DPE_PROFILE.get_hash_size() * 2],
}

pub struct MeasurementData<'a> {
    pub label: &'a [u8],
    pub tci_nodes: &'a [TciNodeData],
    pub is_ca: bool,
}

pub struct X509CertWriter<'a> {
    certificate: &'a mut [u8],
    offset: usize,
    crit_dice: bool,
}

impl X509CertWriter<'_> {
    const BOOL_TAG: u8 = 0x1;
    const INTEGER_TAG: u8 = 0x2;
    const BIT_STRING_TAG: u8 = 0x3;
    const OCTET_STRING_TAG: u8 = 0x4;
    const OID_TAG: u8 = 0x6;
    const PRINTABLE_STRING_TAG: u8 = 0x13;
    const GENERALIZE_TIME_TAG: u8 = 0x18;
    const SEQUENCE_TAG: u8 = 0x30;
    const SEQUENCE_OF_TAG: u8 = 0x30;
    const SET_OF_TAG: u8 = 0x31;

    const BOOL_SIZE: usize = 1;

    // Constants for setting tag bits
    const CONTEXT_SPECIFIC: u8 = 0x80; // Used for Implicit/Explicit tags
    const CONSTRUCTED: u8 = 0x20; // SET{OF} and SEQUENCE{OF} have this bit set

    const X509_V3: u64 = 2;

    const ECDSA_OID: &[u8] = match DPE_PROFILE {
        // ECDSA with SHA256
        DpeProfile::P256Sha256 => &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02],
        // ECDSA with SHA384
        DpeProfile::P384Sha384 => &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03],
    };

    const EC_PUB_OID: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

    const CURVE_OID: &[u8] = match DPE_PROFILE {
        // P256
        DpeProfile::P256Sha256 => &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
        // P384
        DpeProfile::P384Sha384 => &[0x2B, 0x81, 0x04, 0x00, 0x22],
    };

    const HASH_OID: &[u8] = match DPE_PROFILE {
        // SHA256
        DpeProfile::P256Sha256 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
        // SHA384
        DpeProfile::P384Sha384 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
    };

    const RDN_COMMON_NAME_OID: [u8; 3] = [0x55, 0x04, 0x03];
    const RDN_SERIALNUMBER_OID: [u8; 3] = [0x55, 0x04, 0x05];

    // tcg-dice-MultiTcbInfo 2.23.133.5.4.5
    const MULTI_TCBINFO_OID: &[u8] = &[0x67, 0x81, 0x05, 0x05, 0x04, 0x05];

    // tcg-dice-Ueid 2.23.133.5.4.4
    const UEID_OID: &[u8] = &[0x67, 0x81, 0x05, 0x05, 0x04, 0x04];

    // tcg-dice-kp-identityLoc 2.23.133.5.4.100.7
    const IDENTITY_LOC_OID: &[u8] = &[0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x07];

    // tcg-dice-kp-attestLoc 2.23.133.5.4.100.9
    const ATTEST_LOC_OID: &[u8] = &[0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x09];

    // RFC 5280 2.5.29.19
    const BASIC_CONSTRAINTS_OID: &[u8] = &[0x55, 0x1D, 0x13];

    // RFC 5280 2.5.29.15
    const KEY_USAGE_OID: &[u8] = &[0x55, 0x1D, 0x0F];

    // RFC 5280 2.5.28.37
    const EXTENDED_KEY_USAGE_OID: &[u8] = &[0x55, 0x1D, 0x25];

    // All DPE certs are valid from January 1st, 2023 00:00:00 until
    // December 31st, 9999 23:59:59
    const NOT_BEFORE: &str = "20230227000000Z";
    const NOT_AFTER: &str = "99991231235959Z";

    /// Build new X509CertWriter that writes output to `cert`
    ///
    /// If `crit_dice`, all tcg-dice-* extensions will be marked as critical.
    /// Else they will be marked as non-critical.
    pub fn new(cert: &mut [u8], crit_dice: bool) -> X509CertWriter {
        X509CertWriter {
            certificate: cert,
            offset: 0,
            crit_dice,
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
                + Self::get_bytes_size(name.cn, true)?,
            /*tagged=*/ true,
        )?;
        let serialnumber_seq_size = Self::get_structure_size(
            Self::get_bytes_size(&Self::RDN_COMMON_NAME_OID, /*tagged=*/ true)?
                + Self::get_bytes_size(&name.serial, /*tagged=*/ true)?,
            /*tagged=*/ true,
        )?;

        let cn_set_size = Self::get_structure_size(cn_seq_size, /*tagged=*/ true)?;
        let serialnumber_set_size =
            Self::get_structure_size(serialnumber_seq_size, /*tagged=*/ true)?;

        Self::get_structure_size(cn_set_size + serialnumber_set_size, tagged)
    }

    /// Calculate the number of bytes an ECC Public Key AlgorithmIdentifier
    /// If `tagged`, include the tag and size fields
    fn get_ec_pub_alg_id_size(tagged: bool) -> Result<usize, DpeErrorCode> {
        let len = Self::get_bytes_size(Self::EC_PUB_OID, true)?
            + Self::get_bytes_size(Self::CURVE_OID, true)?;
        Self::get_structure_size(len, tagged)
    }

    /// Calculate the number of bytes an ECDSA signature AlgorithmIdentifier
    /// If `tagged`, include the tag and size fields
    fn get_ecdsa_sig_alg_id_size(tagged: bool) -> Result<usize, DpeErrorCode> {
        let len = Self::get_bytes_size(Self::ECDSA_OID, true)?;
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
        let bitstring_size = 1 + point_size;
        let seq_size = Self::get_structure_size(bitstring_size, /*tagged=*/ true)?
            + Self::get_ec_pub_alg_id_size(/*tagged=*/ true)?;

        Self::get_structure_size(seq_size, tagged)
    }

    /// If `tagged`, include the tag and size fields
    fn get_ecdsa_signature_size(sig: &EcdsaSig, tagged: bool) -> Result<usize, DpeErrorCode> {
        let seq_size = Self::get_structure_size(
            Self::get_integer_bytes_size(sig.r.bytes(), /*tagged=*/ true)?
                + Self::get_integer_bytes_size(sig.s.bytes(), /*tagged=*/ true)?,
            /*tagged=*/ true,
        )?;

        // BITSTRING size
        Self::get_structure_size(1 + seq_size, tagged)
    }

    /// version is marked as EXPLICIT [0]
    /// If `tagged`, include the explicit tag and size fields
    fn get_version_size(tagged: bool) -> Result<usize, DpeErrorCode> {
        let integer_size = Self::get_integer_size(Self::X509_V3, /*tagged=*/ true)?;

        // If tagged, also add explicit wrapping
        Self::get_structure_size(integer_size, tagged)
    }

    /// Get the size of a DICE FWID structure
    fn get_fwid_size(digest: &[u8], tagged: bool) -> Result<usize, DpeErrorCode> {
        let size = Self::get_structure_size(Self::HASH_OID.len(), /*tagged=*/ true)?
            + Self::get_structure_size(digest.len(), /*tagged=*/ true)?;

        Self::get_structure_size(size, tagged)
    }

    /// Get the size of a tcg-dice-TcbInfo structure. For DPE, this is only used
    /// as part of a MultiTcbInfo. For this reason, do not include the standard
    /// extension fields. Only include the size of the structure itself.
    fn get_tcb_info_size(node: &TciNodeData, tagged: bool) -> Result<usize, DpeErrorCode> {
        let size = Self::get_structure_size(
            2 * Self::get_fwid_size(&node.tci_current.0, /*tagged=*/ true)?,
            /*tagged=*/ true,
        )? + (2 * Self::get_structure_size(
            core::mem::size_of::<u32>(),
            /*tagged=*/ true,
        )?); // vendorInfo and type
        Self::get_structure_size(size, tagged)
    }

    /// Get the size of a tcg-dice-MultiTcbInfo extension, including the extension
    /// OID and critical bits.
    fn get_multi_tcb_info_size(
        measurements: &MeasurementData,
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        if measurements.tci_nodes.is_empty() {
            return Err(DpeErrorCode::InternalError);
        }

        // Size of concatenated tcb infos
        let tcb_infos_size = measurements.tci_nodes.len()
            * Self::get_tcb_info_size(&measurements.tci_nodes[0], /*tagged=*/ true)?;

        // Size of tcb infos including SEQUENCE OF tag/size
        let multi_tcb_info_size = Self::get_structure_size(tcb_infos_size, /*tagged=*/ true)?;

        let size = Self::get_structure_size(Self::MULTI_TCBINFO_OID.len(), /*tagged=*/true)? // Extension OID
            + Self::get_structure_size(1, /*tagged=*/true)? // Critical bool
            + Self::get_structure_size(multi_tcb_info_size, /*tagged=*/true)?; // OCTET STRING

        Self::get_structure_size(size, tagged)
    }

    /// Get the size of a tcg-dice-Ueid extension, including the extension
    /// OID and critical bits.
    fn get_ueid_size(measurements: &MeasurementData, tagged: bool) -> Result<usize, DpeErrorCode> {
        // Extension data is sequence -> octet string. To compute size, wrap
        // in tagging twice.
        let ext_size = Self::get_structure_size(
            Self::get_structure_size(measurements.label.len(), /*tagged=*/ true)?,
            /*tagged=*/ true,
        )?;
        let size = Self::get_structure_size(Self::UEID_OID.len(), /*tagged=*/true)? // Extension OID
            + Self::get_structure_size(1, /*tagged=*/true)? // Critical bool
            + Self::get_structure_size(ext_size, /*tagged=*/true)?; // OCTET STRING

        Self::get_structure_size(size, tagged)
    }

    /// Get the size of a basicConstraints extension, including the extension
    /// OID and critical bits.
    fn get_basic_constraints_size(tagged: bool) -> Result<usize, DpeErrorCode> {
        // Extension data is sequence -> octet string. To compute size, wrap
        // in tagging twice.
        let ext_size = Self::get_structure_size(
            Self::get_structure_size(Self::BOOL_SIZE, /*tagged=*/ true)?,
            /*tagged=*/ true,
        )?;
        let size = Self::get_structure_size(Self::BASIC_CONSTRAINTS_OID.len(), /*tagged=*/true)? // Extension OID
            + Self::get_structure_size(Self::BOOL_SIZE, /*tagged=*/true)? // Critical bool
            + Self::get_structure_size(ext_size, /*tagged=*/true)?; // OCTET STRING

        Self::get_structure_size(size, tagged)
    }

    /// Get the size of a keyUsage extension, including the extension
    /// OID and critical bits.
    fn get_key_usage_size(tagged: bool) -> Result<usize, DpeErrorCode> {
        // Extension data is sequence -> octet string. To compute size, wrap
        // in tagging twice.
        let ext_size = Self::get_structure_size(
            Self::get_structure_size(1, /*tagged=*/ true)?,
            /*tagged=*/ true,
        )?;
        let size = Self::get_structure_size(Self::KEY_USAGE_OID.len(), /*tagged=*/true)? // Extension OID
            + Self::get_structure_size(Self::BOOL_SIZE, /*tagged=*/true)? // Critical bool
            + Self::get_structure_size(ext_size, /*tagged=*/true)?; // OCTET STRING

        Self::get_structure_size(size, tagged)
    }

    /// Get the size of an extendedKeyUsage extension, including the extension
    /// OID and critical bits.
    fn get_extended_key_usage_size(
        measurements: &MeasurementData,
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        let policy_oid_size = if measurements.is_ca {
            Self::IDENTITY_LOC_OID.len()
        } else {
            Self::ATTEST_LOC_OID.len()
        };

        // Extension data is sequence -> octet string. To compute size, wrap
        // in tagging twice.
        let ext_size = Self::get_structure_size(
            Self::get_structure_size(policy_oid_size, /*tagged=*/ true)?,
            /*tagged=*/ true,
        )?;
        let size = Self::get_structure_size(Self::EXTENDED_KEY_USAGE_OID.len(), /*tagged=*/true)? // Extension OID
            + Self::get_structure_size(Self::BOOL_SIZE, /*tagged=*/true)? // Critical bool
            + Self::get_structure_size(ext_size, /*tagged=*/true)?; // OCTET STRING

        Self::get_structure_size(size, tagged)
    }

    /// Get the size of the TBS Extensions field.
    fn get_extensions_size(
        measurements: &MeasurementData,
        tagged: bool,
        explicit: bool,
    ) -> Result<usize, DpeErrorCode> {
        let mut size = Self::get_multi_tcb_info_size(measurements, /*tagged=*/ true)?
            + Self::get_ueid_size(measurements, /*tagged=*/ true)?
            + Self::get_basic_constraints_size(/*tagged=*/ true)?
            + Self::get_key_usage_size(/*tagged=*/ true)?
            + Self::get_extended_key_usage_size(measurements, /*tagged=*/ true)?;

        // Determine whether to include the explicit tag wrapping in the size calculation
        size = Self::get_structure_size(size, /*tagged=*/ explicit)?;

        Self::get_structure_size(size, tagged)
    }

    /// Get the size of the ASN.1 TBSCertificate structure
    /// If `tagged`, include the tag and size fields
    fn get_tbs_size(
        serial_number: &[u8],
        issuer_der: &[u8],
        subject_name: &Name,
        pubkey: &EcdsaPub,
        measurements: &MeasurementData,
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        let tbs_size = Self::get_version_size(/*tagged=*/ true)?
            + Self::get_integer_bytes_size(serial_number, /*tagged=*/ true)?
            + Self::get_ecdsa_sig_alg_id_size(/*tagged=*/ true)?
            + issuer_der.len()
            + Self::get_validity_size(/*tagged=*/ true)?
            + Self::get_rdn_size(subject_name, /*tagged=*/ true)?
            + Self::get_ecdsa_subject_pubkey_info_size(pubkey, /*tagged=*/ true)?
            + Self::get_extensions_size(
                measurements,
                /*tagged=*/ true,
                /*explicit=*/ true,
            )?;

        Self::get_structure_size(tbs_size, tagged)
    }

    /// Write all of `bytes` to the certificate buffer
    fn encode_bytes(&mut self, bytes: &[u8]) -> Result<usize, DpeErrorCode> {
        let size = bytes.len();

        if self.offset >= self.certificate.len() || self.offset + size > self.certificate.len() {
            return Err(DpeErrorCode::InternalError);
        }

        self.certificate
            .get_mut(self.offset..self.offset + size)
            .ok_or(DpeErrorCode::InternalError)?
            .copy_from_slice(bytes);
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

        if integer_offset >= integer.len() {
            return Err(DpeErrorCode::InternalError);
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

    fn encode_printable_string(&mut self, s: &[u8]) -> Result<usize, DpeErrorCode> {
        let mut bytes_written = self.encode_tag_field(Self::PRINTABLE_STRING_TAG)?;
        bytes_written += self.encode_size_field(s.len())?;
        bytes_written += self.encode_bytes(s)?;

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
    pub fn encode_rdn(&mut self, name: &Name) -> Result<usize, DpeErrorCode> {
        let cn_size =
            Self::get_structure_size(Self::RDN_COMMON_NAME_OID.len(), /*tagged=*/ true)?
                + Self::get_structure_size(name.cn.len(), /*tagged=*/ true)?;
        let serialnumber_size =
            Self::get_structure_size(Self::RDN_SERIALNUMBER_OID.len(), /*tagged=*/ true)?
                + Self::get_structure_size(name.serial.len(), /*tagged=*/ true)?;

        let rdn_name_set_size = Self::get_structure_size(cn_size, /*tagged=*/ true)?;
        let rnd_serial_set_size =
            Self::get_structure_size(serialnumber_size, /*tagged=*/ true)?;
        let rdn_seq_size = Self::get_structure_size(rdn_name_set_size, /*tagged=*/ true)?
            + Self::get_structure_size(rnd_serial_set_size, /*tagged=*/ true)?;

        // Encode RDN SEQUENCE OF
        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_OF_TAG)?;
        bytes_written += self.encode_size_field(rdn_seq_size)?;

        // Encode RDN SET
        bytes_written += self.encode_tag_field(Self::SET_OF_TAG)?;
        bytes_written += self.encode_size_field(rdn_name_set_size)?;

        // Encode CN SEQUENCE
        bytes_written += self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(cn_size)?;
        bytes_written += self.encode_oid(&Self::RDN_COMMON_NAME_OID)?;
        bytes_written += self.encode_printable_string(name.cn)?;

        // Encode RDN SET
        bytes_written += self.encode_tag_field(Self::SET_OF_TAG)?;
        bytes_written += self.encode_size_field(rnd_serial_set_size)?;

        // Encode SERIALNUMBER SEQUENCE
        bytes_written += self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(serialnumber_size)?;
        bytes_written += self.encode_oid(&Self::RDN_SERIALNUMBER_OID)?;
        bytes_written += self.encode_printable_string(&name.serial)?;

        Ok(bytes_written)
    }

    /// DER-encodes the AlgorithmIdentifier for the EC public key algorithm
    /// used by the active DPE profile.
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
    fn encode_ec_pub_alg_id(&mut self) -> Result<usize, DpeErrorCode> {
        let seq_size = Self::get_ec_pub_alg_id_size(/*tagged=*/ false)?;

        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(seq_size)?;
        bytes_written += self.encode_oid(Self::EC_PUB_OID)?;
        bytes_written += self.encode_oid(Self::CURVE_OID)?;

        Ok(bytes_written)
    }

    /// DER-encodes the AlgorithmIdentifier for the ECDSA signature algorithm
    /// used by the active DPE profile.
    ///
    /// AlgorithmIdentifier  ::=  SEQUENCE  {
    ///     algorithm   OBJECT IDENTIFIER,
    ///     parameters  ECParameters
    ///     }
    fn encode_ecdsa_sig_alg_id(&mut self) -> Result<usize, DpeErrorCode> {
        let seq_size = Self::get_ecdsa_sig_alg_id_size(/*tagged=*/ false)?;

        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(seq_size)?;
        bytes_written += self.encode_oid(Self::ECDSA_OID)?;

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
    ///
    /// The ECPoint OCTET STRING is mapped to the subjectPublicKey BIT STRING
    /// directly, which means the OCTET STRING tag and size fields are omitted.
    fn encode_ecdsa_subject_pubkey_info(
        &mut self,
        pubkey: &EcdsaPub,
    ) -> Result<usize, DpeErrorCode> {
        let point_size = 1 + pubkey.x.len() + pubkey.y.len();
        let bitstring_size = 1 + point_size;
        let seq_size = Self::get_structure_size(bitstring_size, /*tagged=*/ true)?
            + Self::get_ec_pub_alg_id_size(/*tagged=*/ true)?;

        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(seq_size)?;
        bytes_written += self.encode_ec_pub_alg_id()?;

        bytes_written += self.encode_tag_field(Self::BIT_STRING_TAG)?;
        bytes_written += self.encode_size_field(bitstring_size)?;
        // First byte of BIT STRING is the number of unused bits. But all bits
        // are used.
        bytes_written += self.encode_byte(0)?;

        bytes_written += self.encode_byte(0x4)?;
        bytes_written += self.encode_bytes(pubkey.x.bytes())?;
        bytes_written += self.encode_bytes(pubkey.y.bytes())?;

        Ok(bytes_written)
    }

    /// BIT STRING containing
    ///
    /// ECDSA-Sig-Value ::= SEQUENCE {
    ///     r  INTEGER,
    ///     s  INTEGER
    ///   }
    fn encode_ecdsa_signature(&mut self, sig: &EcdsaSig) -> Result<usize, DpeErrorCode> {
        let seq_size = Self::get_integer_bytes_size(sig.r.bytes(), /*tagged=*/ true)?
            + Self::get_integer_bytes_size(sig.s.bytes(), /*tagged=*/ true)?;

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
        bytes_written += self.encode_integer_bytes(sig.r.bytes())?;
        bytes_written += self.encode_integer_bytes(sig.s.bytes())?;

        Ok(bytes_written)
    }

    pub fn encode_version(&mut self) -> Result<usize, DpeErrorCode> {
        // Version is EXPLICIT field number 0
        let mut bytes_written = self.encode_byte(Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED)?;
        bytes_written += self.encode_size_field(Self::get_integer_size(
            Self::X509_V3,
            /*tagged=*/ true,
        )?)?;
        bytes_written += self.encode_integer(Self::X509_V3)?;

        Ok(bytes_written)
    }

    fn encode_fwid(&mut self, tci: &TciMeasurement) -> Result<usize, DpeErrorCode> {
        let mut bytes_written = self.encode_byte(Self::SEQUENCE_TAG)?;
        bytes_written +=
            self.encode_size_field(Self::get_fwid_size(&tci.0, /*tagged=*/ false)?)?;

        // hashAlg OID
        bytes_written += self.encode_byte(Self::OID_TAG)?;
        bytes_written += self.encode_size_field(Self::HASH_OID.len())?;
        bytes_written += self.encode_bytes(Self::HASH_OID)?;

        // digest OCTET STRING
        bytes_written += self.encode_byte(Self::OCTET_STRING_TAG)?;
        bytes_written += self.encode_size_field(tci.0.len())?;
        bytes_written += self.encode_bytes(&tci.0)?;

        Ok(bytes_written)
    }

    /// Encode a tcg-dice-TcbInfo structure
    ///
    /// https://trustedcomputinggroup.org/wp-content/uploads/TCG_DICE_Attestation_Architecture_r22_02dec2020.pdf
    ///
    /// TcbInfo makes use of implicitly encoded types. This means the tag
    /// denotes that the type is implicit (8th bit set) and number of the
    /// field. For example, "Implicit tag number 2" would be encoded with
    /// the tag 0x82 for primitive types.
    ///
    /// For constructed types (SEQUENCE, SEQUENCE OF, SET, SET OF) the 6th
    /// bit is also set. For example, "Implicit tag number 2" would be encoded
    /// with tag 0xA2 for constructed types.
    fn encode_tcb_info(&mut self, node: &TciNodeData) -> Result<usize, DpeErrorCode> {
        let tcb_info_size = Self::get_tcb_info_size(node, /*tagged=*/ false)?;
        // TcbInfo sequence
        let mut bytes_written = self.encode_byte(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(tcb_info_size)?;

        // fwids SEQUENCE OF
        // IMPLICIT [6] Constructed
        let fwid_size = Self::get_fwid_size(&node.tci_current.0, /*tagged=*/ true)?;
        bytes_written += self.encode_byte(Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED | 0x06)?;
        bytes_written += self.encode_size_field(fwid_size * 2)?;

        // fwid[0] current measurement
        bytes_written += self.encode_fwid(&node.tci_current)?;

        // fwid[1] journey measurement
        bytes_written += self.encode_fwid(&node.tci_cumulative)?;

        // vendorInfo OCTET STRING
        // IMPLICIT[8] Primitive
        let vinfo = &node.locality.to_be_bytes();
        bytes_written += self.encode_byte(Self::CONTEXT_SPECIFIC | 0x08)?;
        bytes_written += self.encode_size_field(vinfo.len())?;
        bytes_written += self.encode_bytes(vinfo)?;

        // type OCTET STRING
        // IMPLICIT[9] Primitive
        bytes_written += self.encode_byte(Self::CONTEXT_SPECIFIC | 0x09)?;
        bytes_written += self.encode_size_field(core::mem::size_of::<u32>())?;
        bytes_written += self.encode_bytes(&node.tci_type.to_be_bytes())?;

        Ok(bytes_written)
    }

    /// Encode a tcg-dice-MultiTcbInfo extension
    ///
    /// https://trustedcomputinggroup.org/wp-content/uploads/TCG_DICE_Attestation_Architecture_r22_02dec2020.pdf
    fn encode_multi_tcb_info(
        &mut self,
        measurements: &MeasurementData,
    ) -> Result<usize, DpeErrorCode> {
        let multi_tcb_info_size =
            Self::get_multi_tcb_info_size(measurements, /*tagged=*/ false)?;

        // Encode Extension
        let mut bytes_written = self.encode_byte(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(multi_tcb_info_size)?;
        bytes_written += self.encode_oid(Self::MULTI_TCBINFO_OID)?;

        let crit = if self.crit_dice { 0xFF } else { 0x00 };
        bytes_written += self.encode_byte(Self::BOOL_TAG)?;
        bytes_written += self.encode_size_field(Self::BOOL_SIZE)?;
        bytes_written += self.encode_byte(crit)?;

        let tcb_infos_size = if !measurements.tci_nodes.is_empty() {
            Self::get_tcb_info_size(&measurements.tci_nodes[0], /*tagged=*/ true)?
                * measurements.tci_nodes.len()
        } else {
            0
        };
        bytes_written += self.encode_byte(Self::OCTET_STRING_TAG)?;
        bytes_written += self.encode_size_field(Self::get_structure_size(
            tcb_infos_size,
            /*tagged=*/ true,
        )?)?;

        // Encode MultiTcbInfo
        bytes_written += self.encode_byte(Self::SEQUENCE_OF_TAG)?;
        bytes_written += self.encode_size_field(tcb_infos_size)?;

        // Encode multiple tcg-dice-TcbInfos
        for node in measurements.tci_nodes {
            bytes_written += self.encode_tcb_info(node)?;
        }

        Ok(bytes_written)
    }

    /// Encode a tcg-dice-Ueid extension
    ///
    /// https://trustedcomputinggroup.org/wp-content/uploads/TCG_DICE_Attestation_Architecture_r22_02dec2020.pdf
    fn encode_ueid(&mut self, measurements: &MeasurementData) -> Result<usize, DpeErrorCode> {
        let ueid_size = Self::get_ueid_size(measurements, /*tagged=*/ false)?;

        // Encode Extension
        let mut bytes_written = self.encode_byte(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(ueid_size)?;
        bytes_written += self.encode_oid(Self::UEID_OID)?;

        let crit = if self.crit_dice { 0xFF } else { 0x00 };
        bytes_written += self.encode_byte(Self::BOOL_TAG)?;
        bytes_written += self.encode_size_field(Self::BOOL_SIZE)?;
        bytes_written += self.encode_byte(crit)?;

        // Extension data is sequence -> octet string. To compute size, wrap
        // in tagging twice.
        bytes_written += self.encode_byte(Self::OCTET_STRING_TAG)?;
        bytes_written += self.encode_size_field(Self::get_structure_size(
            Self::get_structure_size(measurements.label.len(), /*tagged=*/ true)?,
            /*tagged=*/ true,
        )?)?;

        // Sequence size to just a tagged OCTET_STRING
        bytes_written += self.encode_byte(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(Self::get_structure_size(
            measurements.label.len(),
            /*tagged=*/ true,
        )?)?;

        bytes_written += self.encode_byte(Self::OCTET_STRING_TAG)?;
        bytes_written += self.encode_size_field(Self::get_structure_size(
            measurements.label.len(),
            /*tagged=*/ false,
        )?)?;

        bytes_written += self.encode_bytes(measurements.label)?;

        Ok(bytes_written)
    }

    /// Encode a BasicConstraints extension
    ///
    /// https://datatracker.ietf.org/doc/html/rfc5280
    fn encode_basic_constraints(
        &mut self,
        measurements: &MeasurementData,
    ) -> Result<usize, DpeErrorCode> {
        let basic_constraints_size = Self::get_basic_constraints_size(/*tagged=*/ false)?;

        // Encode Extension
        let mut bytes_written = self.encode_byte(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(basic_constraints_size)?;
        bytes_written += self.encode_oid(Self::BASIC_CONSTRAINTS_OID)?;

        bytes_written += self.encode_byte(Self::BOOL_TAG)?;
        bytes_written += self.encode_size_field(Self::BOOL_SIZE)?;
        bytes_written += self.encode_byte(0xFF)?;

        // Extension data is sequence -> octet string. To compute size, wrap
        // in tagging twice.
        bytes_written += self.encode_byte(Self::OCTET_STRING_TAG)?;
        bytes_written += self.encode_size_field(Self::get_structure_size(
            Self::get_structure_size(1, /*tagged=*/ true)?,
            /*tagged=*/ true,
        )?)?;

        // Sequence size to just a tagged bool
        bytes_written += self.encode_byte(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(Self::get_structure_size(
            Self::BOOL_SIZE,
            /*tagged=*/ true,
        )?)?;

        bytes_written += self.encode_byte(Self::BOOL_TAG)?;
        bytes_written += self.encode_size_field(Self::BOOL_SIZE)?;
        if measurements.is_ca {
            bytes_written += self.encode_byte(0x01)?;
        } else {
            bytes_written += self.encode_byte(0x00)?;
        }

        Ok(bytes_written)
    }

    /// Encode a KeyUsage extension
    ///
    /// https://datatracker.ietf.org/doc/html/rfc5280
    fn encode_key_usage(&mut self) -> Result<usize, DpeErrorCode> {
        let key_usage_size = Self::get_key_usage_size(/*tagged=*/ false)?;

        // Encode Extension
        let mut bytes_written = self.encode_byte(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(key_usage_size)?;
        bytes_written += self.encode_oid(Self::KEY_USAGE_OID)?;

        bytes_written += self.encode_byte(Self::BOOL_TAG)?;
        bytes_written += self.encode_size_field(Self::BOOL_SIZE)?;
        bytes_written += self.encode_byte(0xFF)?;

        // Extension data is sequence -> octet string. To compute size, wrap
        // in tagging twice.
        bytes_written += self.encode_byte(Self::OCTET_STRING_TAG)?;
        bytes_written += self.encode_size_field(Self::get_structure_size(
            Self::get_structure_size(1, /*tagged=*/ true)?,
            /*tagged=*/ true,
        )?)?;

        bytes_written += self.encode_byte(Self::BIT_STRING_TAG)?;
        bytes_written +=
            self.encode_size_field(Self::get_structure_size(1, /*tagged=*/ true)?)?;
        // First byte of BIT STRING is the number of unused bits. But all bits
        // are used.
        bytes_written += self.encode_byte(0)?;

        // Set digitalSignature bit
        bytes_written += self.encode_byte(0x80)?;
        bytes_written += self.encode_size_field(1)?;

        Ok(bytes_written)
    }

    /// Encode ExtendedKeyUsage extension
    ///
    /// The included EKU OIDs is as follows based on whether or not this certificate is for a CA:
    ///
    /// is_ca = true: id-tcg-kp-identityLoc (2.23.133.8.7)
    /// is_ca = false: id-tcg-kp-attestLoc (2.23.133.8.9)
    ///
    /// https://datatracker.ietf.org/doc/html/rfc5280
    fn encode_extended_key_usage(
        &mut self,
        measurements: &MeasurementData,
    ) -> Result<usize, DpeErrorCode> {
        let policy_oid = if measurements.is_ca {
            Self::IDENTITY_LOC_OID
        } else {
            Self::ATTEST_LOC_OID
        };

        // Assumes only one certificate policy is supported.
        let extended_key_usage_size = Self::get_extended_key_usage_size(measurements, false)?;

        // Encode Extension
        let mut bytes_written = self.encode_byte(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(extended_key_usage_size)?;
        bytes_written += self.encode_oid(Self::EXTENDED_KEY_USAGE_OID)?;

        bytes_written += self.encode_byte(Self::BOOL_TAG)?;
        bytes_written += self.encode_size_field(Self::BOOL_SIZE)?;
        bytes_written += self.encode_byte(0xFF)?;

        // Extension data is sequence -> octet string. To compute size, wrap
        // in tagging twice.
        bytes_written += self.encode_byte(Self::OCTET_STRING_TAG)?;
        bytes_written += self.encode_size_field(Self::get_structure_size(
            Self::get_structure_size(policy_oid.len(), /*tagged=*/ true)?,
            /*tagged=*/ true,
        )?)?;

        // Sequence size is the size of all the EKU OIDs.
        bytes_written += self.encode_byte(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(Self::get_structure_size(
            policy_oid.len(),
            /*tagged=*/ true,
        )?)?;

        bytes_written += self.encode_oid(policy_oid)?;

        Ok(bytes_written)
    }

    fn encode_extensions(&mut self, measurements: &MeasurementData) -> Result<usize, DpeErrorCode> {
        // Extensions is EXPLICIT field number 3
        let mut bytes_written =
            self.encode_byte(Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED | 0x03)?;
        bytes_written += self.encode_size_field(Self::get_extensions_size(
            measurements,
            /*tagged=*/ true,
            /*explicit=*/ false,
        )?)?;

        // SEQUENCE OF Extension
        bytes_written += self.encode_byte(Self::SEQUENCE_OF_TAG)?;
        bytes_written += self.encode_size_field(Self::get_extensions_size(
            measurements,
            /*tagged=*/ false,
            /*explicit=*/ false,
        )?)?;

        bytes_written += self.encode_multi_tcb_info(measurements)?;
        bytes_written += self.encode_ueid(measurements)?;
        bytes_written += self.encode_basic_constraints(measurements)?;
        bytes_written += self.encode_key_usage()?;
        bytes_written += self.encode_extended_key_usage(measurements)?;

        Ok(bytes_written)
    }

    /// Encodes a TBS Certificate with the following ASN.1 encoding:
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
    ///
    /// # Arguments
    ///
    /// * `serial_number` - A byte slice holding the serial number.
    /// * `issuer_name` - A DER encoded issuer RDN.
    /// * `subject_name` - The subject name RDN struct to encode.
    /// * `pubkey` - ECDSA Public key.
    /// * `measurements` - DPE measurement data.
    pub fn encode_ecdsa_tbs(
        &mut self,
        serial_number: &[u8],
        issuer_name: &[u8],
        subject_name: &Name,
        pubkey: &EcdsaPub,
        measurements: &MeasurementData,
    ) -> Result<usize, DpeErrorCode> {
        let tbs_size = Self::get_tbs_size(
            serial_number,
            issuer_name,
            subject_name,
            pubkey,
            measurements,
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
        bytes_written += self.encode_ecdsa_sig_alg_id()?;

        // issuer
        bytes_written += self.encode_bytes(issuer_name)?;

        // validity
        bytes_written += self.encode_validity()?;

        // subject
        bytes_written += self.encode_rdn(subject_name)?;

        // subjectPublicKeyInfo
        bytes_written += self.encode_ecdsa_subject_pubkey_info(pubkey)?;

        // extensions
        bytes_written += self.encode_extensions(measurements)?;

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
        tbs: &[u8],
        sig: &EcdsaSig,
    ) -> Result<usize, DpeErrorCode> {
        let cert_size = tbs.len()
            + Self::get_ecdsa_sig_alg_id_size(/*tagged=*/ true)?
            + Self::get_ecdsa_signature_size(sig, /*tagged=*/ true)?;

        // Certificate sequence
        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(cert_size)?;

        // TBS
        bytes_written += self.encode_bytes(tbs)?;

        // Alg ID
        bytes_written += self.encode_ecdsa_sig_alg_id()?;

        // Signature
        bytes_written += self.encode_ecdsa_signature(sig)?;

        Ok(bytes_written)
    }
}

#[cfg(test)]
mod tests {
    use crate::tci::{TciMeasurement, TciNodeData};
    use crate::x509::{MeasurementData, Name, X509CertWriter};
    use crate::DPE_PROFILE;
    use crypto::{AlgLen, CryptoBuf, EcdsaPub, EcdsaSig};
    use std::str;
    use x509_parser::certificate::X509CertificateParser;
    use x509_parser::nom::Parser;
    use x509_parser::oid_registry::asn1_rs::oid;
    use x509_parser::prelude::*;

    #[derive(asn1::Asn1Read)]
    pub struct Fwid<'a> {
        pub(crate) _hash_alg: asn1::ObjectIdentifier,
        pub(crate) digest: &'a [u8],
    }

    #[derive(asn1::Asn1Read)]
    struct TcbInfo<'a> {
        #[implicit(0)]
        _vendor: Option<asn1::Utf8String<'a>>,
        #[implicit(1)]
        _model: Option<asn1::Utf8String<'a>>,
        #[implicit(2)]
        _version: Option<asn1::Utf8String<'a>>,
        #[implicit(3)]
        _svn: Option<u64>,
        #[implicit(4)]
        _layer: Option<u64>,
        #[implicit(5)]
        _index: Option<u64>,
        #[implicit(6)]
        fwids: Option<asn1::SequenceOf<'a, Fwid<'a>>>,
        #[implicit(7)]
        _flags: Option<asn1::BitString<'a>>,
        #[implicit(8)]
        vendor_info: Option<&'a [u8]>,
        #[implicit(9)]
        tci_type: Option<&'a [u8]>,
    }

    #[derive(asn1::Asn1Read)]
    struct Ueid<'a> {
        pub(crate) ueid: &'a [u8],
    }

    const TEST_ISSUER: Name = Name {
        cn: b"Caliptra Alias",
        serial: [0x00; DPE_PROFILE.get_hash_size() * 2],
    };

    fn encode_test_issuer() -> Vec<u8> {
        let mut issuer_der = vec![0u8; 256];
        let mut issuer_writer = X509CertWriter::new(&mut issuer_der, true);
        let issuer_len = issuer_writer.encode_rdn(&TEST_ISSUER).unwrap();
        issuer_der.resize(issuer_len, 0);
        issuer_der
    }

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
            let mut w = X509CertWriter::new(&mut cert, true);
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
            let mut w = X509CertWriter::new(&mut cert, true);
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
        let mut cert = [0u8; 256];
        let test_name = Name {
            cn: b"Caliptra Alias",
            serial: [0x0u8; DPE_PROFILE.get_hash_size() * 2],
        };

        let mut w = X509CertWriter::new(&mut cert, true);
        let bytes_written = w.encode_rdn(&test_name).unwrap();

        let name = match X509Name::from_der(&cert[..bytes_written]) {
            Ok((_, name)) => name,
            Err(e) => panic!("Name parsing failed: {:?}", e),
        };

        let expected = format!(
            "CN={}, serialNumber={}",
            str::from_utf8(test_name.cn).unwrap(),
            str::from_utf8(&test_name.serial).unwrap()
        );
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
        let test_key = EcdsaPub::default(DPE_PROFILE.alg_len());

        let mut w = X509CertWriter::new(&mut cert, true);
        let bytes_written = w.encode_ecdsa_subject_pubkey_info(&test_key).unwrap();

        SubjectPublicKeyInfo::from_der(&cert[..bytes_written]).unwrap();

        assert_eq!(
            X509CertWriter::get_ecdsa_subject_pubkey_info_size(&test_key, true).unwrap(),
            bytes_written
        );
    }

    #[test]
    fn test_tcb_info() {
        let mut node = TciNodeData::new();

        node.tci_type = 0x11223344;
        node.tci_cumulative = TciMeasurement([0xaau8; DPE_PROFILE.get_hash_size()]);
        node.tci_current = TciMeasurement([0xbbu8; DPE_PROFILE.get_hash_size()]);
        node.locality = 0xFFFFFFFF;

        let mut cert = [0u8; 256];
        let mut w = X509CertWriter::new(&mut cert, true);
        let bytes_written = w.encode_tcb_info(&node).unwrap();

        let parsed_tcb_info = asn1::parse_single::<TcbInfo>(&cert[..bytes_written]).unwrap();

        assert_eq!(
            bytes_written,
            X509CertWriter::get_tcb_info_size(&node, true).unwrap()
        );

        // FWIDs
        let mut fwid_itr = parsed_tcb_info.fwids.unwrap();
        let expected_current = fwid_itr.next().unwrap().digest;
        let expected_cumulative = fwid_itr.next().unwrap().digest;
        assert_eq!(expected_current, node.tci_current.0);
        assert_eq!(expected_cumulative, node.tci_cumulative.0);

        assert_eq!(
            parsed_tcb_info.tci_type.unwrap(),
            node.tci_type.to_be_bytes()
        );
        assert_eq!(
            parsed_tcb_info.vendor_info.unwrap(),
            node.locality.to_be_bytes()
        );
    }

    #[test]
    fn test_tbs() {
        let mut cert = [0u8; 4096];
        let mut w = X509CertWriter::new(&mut cert, true);

        let test_serial = [0x1F; 20];
        let issuer_der = encode_test_issuer();

        let test_subject_name = Name {
            cn: b"DPE Leaf",
            serial: [0x00; DPE_PROFILE.get_hash_size() * 2],
        };

        const ECC_INT_SIZE: usize = DPE_PROFILE.get_ecc_int_size();
        const ALG_LEN: AlgLen = DPE_PROFILE.alg_len();
        let test_pub = EcdsaPub {
            x: CryptoBuf::new(&[0xAA; ECC_INT_SIZE], ALG_LEN).unwrap(),
            y: CryptoBuf::new(&[0xBB; ECC_INT_SIZE], ALG_LEN).unwrap(),
        };

        let node = TciNodeData::new();

        let measurements = MeasurementData {
            label: &[0xCC; DPE_PROFILE.get_hash_size()],
            tci_nodes: &[node],
            is_ca: false,
        };

        let bytes_written = w
            .encode_ecdsa_tbs(
                &test_serial,
                &issuer_der,
                &test_subject_name,
                &test_pub,
                &measurements,
            )
            .unwrap();

        let mut parser = TbsCertificateParser::new().with_deep_parse_extensions(false);
        let cert = match parser.parse(&cert) {
            Ok((rem, parsed_cert)) => {
                assert_eq!(parsed_cert.version(), X509Version::V3);
                assert_eq!(rem.len(), cert.len() - bytes_written);
                parsed_cert
            }
            Err(e) => panic!("x509 parsing failed: {:?}", e),
        };

        let ueid = cert
            .get_extension_unique(&oid!(2.23.133 .5 .4 .4))
            .unwrap()
            .unwrap();
        assert!(ueid.critical);
        let parsed_ueid = asn1::parse_single::<Ueid>(ueid.value).unwrap();
        assert_eq!(parsed_ueid.ueid, measurements.label);
    }

    #[test]
    fn test_full_cert() {
        let test_serial = [0x1F; 20];
        let test_issuer_name = Name {
            cn: b"Caliptra Alias",
            serial: [0x00; DPE_PROFILE.get_hash_size() * 2],
        };
        let mut issuer_der = [0u8; 1024];
        let mut issuer_writer = X509CertWriter::new(&mut issuer_der, true);
        let issuer_len = issuer_writer.encode_rdn(&test_issuer_name).unwrap();

        let test_subject_name = Name {
            cn: b"DPE Leaf",
            serial: [0x00; DPE_PROFILE.get_hash_size() * 2],
        };

        const ECC_INT_SIZE: usize = DPE_PROFILE.get_ecc_int_size();
        const ALG_LEN: AlgLen = DPE_PROFILE.alg_len();
        let test_pub = EcdsaPub {
            x: CryptoBuf::new(&[0xAA; ECC_INT_SIZE], ALG_LEN).unwrap(),
            y: CryptoBuf::new(&[0xBB; ECC_INT_SIZE], ALG_LEN).unwrap(),
        };
        let test_sig = EcdsaSig {
            r: CryptoBuf::new(&[0xCC; ECC_INT_SIZE], ALG_LEN).unwrap(),
            s: CryptoBuf::new(&[0xDD; ECC_INT_SIZE], ALG_LEN).unwrap(),
        };

        let node = TciNodeData::new();

        let measurements = MeasurementData {
            label: &[0; DPE_PROFILE.get_hash_size()],
            tci_nodes: &[node],
            is_ca: true,
        };

        let mut tbs = [0u8; 1024];
        let mut tbs_writer = X509CertWriter::new(&mut tbs, true);
        let mut bytes_written = tbs_writer
            .encode_ecdsa_tbs(
                &test_serial,
                &issuer_der[..issuer_len],
                &test_subject_name,
                &test_pub,
                &measurements,
            )
            .unwrap();

        let mut cert = [0u8; 1024];
        let mut w = X509CertWriter::new(&mut cert, true);
        bytes_written = w
            .encode_ecdsa_certificate(&tbs[..bytes_written], &test_sig)
            .unwrap();

        let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
        let cert = match parser.parse(&cert) {
            Ok((rem, parsed_cert)) => {
                assert_eq!(parsed_cert.version(), X509Version::V3);
                assert_eq!(rem.len(), cert.len() - bytes_written);
                parsed_cert
            }
            Err(e) => panic!("x509 parsing failed: {:?}", e),
        };

        match cert.basic_constraints() {
            Ok(Some(basic_constraints)) => {
                assert!(basic_constraints.critical);
                assert!(basic_constraints.value.ca);
                assert!(basic_constraints.value.path_len_constraint.is_none());
            }
            Ok(None) => panic!("basic constraints extension not found"),
            Err(_) => panic!("multiple basic constraints extensions found"),
        }

        match cert.key_usage() {
            Ok(Some(key_usage)) => {
                assert!(key_usage.critical);
                assert!(key_usage.value.digital_signature());
            }
            Ok(None) => panic!("key usage extension not found"),
            Err(_) => panic!("multiple key usage extensions found"),
        }

        match cert.extended_key_usage() {
            Ok(Some(ext_key_usage)) => {
                assert!(ext_key_usage.critical);
                // Expect tcg-dice-kp-identityLoc OID (2.23.133.5.4.100.7)
                assert_eq!(ext_key_usage.value.other, [oid!(2.23.133 .5 .4 .100 .7)]);
            }
            Ok(None) => panic!("extended key usage extension not found"),
            Err(_) => panic!("multiple extended key usage extensions found"),
        };
    }
}
