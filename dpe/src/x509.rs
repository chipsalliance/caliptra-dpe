// Licensed under the Apache-2.0 license

//! Lightweight X.509 encoding routines for DPE
//!
//! DPE requires encoding variable-length certificates. This module provides
//! this functionality for a no_std environment.

use crate::{
    context::ContextHandle,
    dpe_instance::{DpeEnv, DpeTypes},
    response::DpeErrorCode,
    tci::{TciMeasurement, TciNodeData},
    DpeInstance, DpeProfile, State, MAX_HANDLES,
};
use bitflags::bitflags;
use caliptra_cfi_lib_git::cfi_launder;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq};
use crypto::{
    ecdsa::{EcdsaPubKey, EcdsaSignature},
    Crypto, CryptoError, CryptoSuite, Digest, Hasher, PubKey, Signature, MAX_EXPORTED_CDI_SIZE,
};
#[cfg(not(feature = "disable_x509"))]
use platform::CertValidity;
#[cfg(not(feature = "disable_csr"))]
use platform::SignerIdentifier;
use platform::{
    ArrayVec, OtherName, Platform, PlatformError, SubjectAltName, MAX_ISSUER_NAME_SIZE,
    MAX_KEY_IDENTIFIER_SIZE,
};
use zerocopy::IntoBytes;

#[cfg(feature = "ml-dsa")]
use crypto::ml_dsa::{MldsaPublicKey, MldsaSignature};

/// Max amount of backtracks during encoding.
/// Currently the deepest backtrack path is 7.
const MAX_BACKTRACKS: usize = 10;

/// We save 3 bytes to record the size.
/// Currently all size skips are always 255 < size < 65535 since we only skip signatures
/// and large objects, e.g. CSR or TBS.
const SIZE_TAG_OFFSET: usize = 3;

/// This is the maximum size of a digest. The only profiles supported use SHA256 and SHA384.
/// This is the size of a SHA384 digest.
const MAX_HASH_SIZE: usize = 48;

#[cfg(feature = "p256")]
mod profile_oids {
    pub const ECDSA_WITH_SHA256_OID: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
    pub const CURVE_P256_OID: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    pub const HASH_SHA256_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
}

#[cfg(feature = "p384")]
mod profile_oids {
    pub const ECDSA_WITH_SHA384_OID: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
    pub const CURVE_P384_OID: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
}

pub enum DirectoryString<'a> {
    PrintableString(&'a [u8]),
    Utf8String(&'a [u8]),
}

impl DirectoryString<'_> {
    pub fn len(&self) -> usize {
        self.bytes().len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes().is_empty()
    }

    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::PrintableString(val) => val,
            Self::Utf8String(val) => val,
        }
    }
}

/// Type for specifying an X.509 RelativeDistinguisedName
///
/// `serial` is expected to hold a hex string of the hash of the public key
pub struct Name<'a> {
    pub cn: DirectoryString<'a>,
    pub serial: DirectoryString<'a>,
}

pub struct MeasurementData<'a> {
    pub label: &'a [u8],
    pub tci_nodes: &'a [TciNodeData],
    pub is_ca: bool,
    pub supports_recursive: bool,
    pub subject_key_identifier: [u8; MAX_KEY_IDENTIFIER_SIZE],
    pub authority_key_identifier: [u8; MAX_KEY_IDENTIFIER_SIZE],
    pub subject_alt_name: Option<SubjectAltName>,
}

pub struct CertWriter<'a> {
    certificate: &'a mut [u8],
    profile: DpeProfile,
    offset: usize,
    crit_dice: bool,
    csr_range: Option<(usize, usize)>,
    backtracks: ArrayVec<(usize, usize), MAX_BACKTRACKS>,
    saved_offset: Option<usize>,
}

pub struct KeyUsageFlags(u8);

bitflags! {
    impl KeyUsageFlags: u8 {
        const DIGITAL_SIGNATURE = 0b1000_0000;
        const KEY_CERT_SIGN = 0b0000_0100;
    }
}

impl CertWriter<'_> {
    const BOOL_TAG: u8 = 0x1;
    const INTEGER_TAG: u8 = 0x2;
    const BIT_STRING_TAG: u8 = 0x3;
    const OCTET_STRING_TAG: u8 = 0x4;
    const OID_TAG: u8 = 0x6;
    const UTF8_STRING_TAG: u8 = 0xC;
    const PRINTABLE_STRING_TAG: u8 = 0x13;
    #[cfg(not(feature = "disable_x509"))]
    const GENERALIZE_TIME_TAG: u8 = 0x18;
    const SEQUENCE_TAG: u8 = 0x30;
    const SEQUENCE_OF_TAG: u8 = 0x30;
    const SET_OF_TAG: u8 = 0x31;

    const BOOL_SIZE: usize = 1;

    // Constants for setting tag bits
    const CONTEXT_SPECIFIC: u8 = 0x80; // Used for Implicit/Explicit tags
    const CONSTRUCTED: u8 = 0x20; // SET{OF} and SEQUENCE{OF} have this bit set

    const X509_V3: u64 = 2;
    #[cfg(not(feature = "disable_csr"))]
    const CMS_V1: u64 = 1;
    #[cfg(not(feature = "disable_csr"))]
    const CMS_V3: u64 = 3;
    #[cfg(not(feature = "disable_csr"))]
    const CSR_V0: u64 = 0;

    /// ASN.1 encoding with length stripped of the following OID.
    /// id-ml-dnsa-87 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2)
    ///     country(16) us(840) organization(1) gov(101) csor(3)
    ///     nistAlgorithm(4) sigAlgs(3) id-ml-dsa-87(19) }
    /// Source: https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates/
    #[cfg(feature = "ml-dsa")]
    const MLDSA_OID: &'static [u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13];

    const EC_PUB_OID: &'static [u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

    // SHA384
    #[cfg(any(feature = "p384", feature = "ml-dsa"))]
    const HASH_SHA384_OID: &'static [u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];

    const RDN_COMMON_NAME_OID: [u8; 3] = [0x55, 0x04, 0x03];
    const RDN_SERIALNUMBER_OID: [u8; 3] = [0x55, 0x04, 0x05];

    // tcg-dice-MultiTcbInfo 2.23.133.5.4.5
    const MULTI_TCBINFO_OID: &'static [u8] = &[0x67, 0x81, 0x05, 0x05, 0x04, 0x05];

    // tcg-dice-Ueid 2.23.133.5.4.4
    const UEID_OID: &'static [u8] = &[0x67, 0x81, 0x05, 0x05, 0x04, 0x04];

    // tcg-dice-kp-eca 2.23.133.5.4.100.12
    const ECA_OID: &'static [u8] = &[0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x0C];

    // tcg-dice-kp-attestLoc 2.23.133.5.4.100.9
    const ATTEST_LOC_OID: &'static [u8] = &[0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x09];

    // RFC 5280 2.5.29.19
    const BASIC_CONSTRAINTS_OID: &'static [u8] = &[0x55, 0x1D, 0x13];

    // RFC 5280 2.5.29.15
    const KEY_USAGE_OID: &'static [u8] = &[0x55, 0x1D, 0x0F];

    // RFC 5280 2.5.29.37
    const EXTENDED_KEY_USAGE_OID: &'static [u8] = &[0x55, 0x1D, 0x25];

    // RFC 5280 2.5.29.14
    const SUBJECT_KEY_IDENTIFIER_OID: &'static [u8] = &[0x55, 0x1D, 0x0E];

    // RFC 5280 2.5.29.35
    const AUTHORITY_KEY_IDENTIFIER_OID: &'static [u8] = &[0x55, 0x1D, 0x23];

    // RFC 5280 2.5.29.17
    const SUBJECT_ALTERNATIVE_NAME_OID: &'static [u8] = &[0x55, 0x1D, 0x11];

    // RFC 5652 1.2.840.113549.1.7.2
    #[cfg(not(feature = "disable_csr"))]
    const ID_SIGNED_DATA_OID: &'static [u8] =
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];

    // RFC 5652 1.2.840.113549.1.7.1
    #[cfg(not(feature = "disable_csr"))]
    const ID_DATA_OID: &'static [u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];

    // RFC 2985 1.2.840.113549.1.9.14
    #[cfg(not(feature = "disable_csr"))]
    const EXTENSION_REQUEST_OID: &'static [u8] =
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E];

    /// Build new CertWriter that writes output to `cert`
    ///
    /// If `crit_dice`, all tcg-dice-* extensions will be marked as critical.
    /// Else they will be marked as non-critical.
    pub fn new(cert: &mut [u8], profile: DpeProfile, crit_dice: bool) -> CertWriter {
        CertWriter {
            certificate: cert,
            profile,
            offset: 0,
            crit_dice,
            csr_range: None,
            backtracks: ArrayVec::new(),
            saved_offset: None,
        }
    }

    /// Moves certificate offset forward by `skip` bytes.
    ///
    /// Pushes current offset and the skipped offset to a stack. This is useful when a size
    /// field needs to be written but the size is not yet known. The writer can skip ahead, write
    /// the content, and then pop the offsets to go back and write the size.
    ///
    /// # Arguments
    ///
    /// * `skip` - The number of bytes to skip ahead.
    ///
    /// # Returns
    ///
    /// The new offset.
    fn push_backtrack(&mut self, skip: usize) -> Result<usize, DpeErrorCode> {
        self.backtracks
            .try_push((self.offset, self.offset + skip))
            .map_err(|_| DpeErrorCode::X509SkipsExhausted)?;
        self.offset += skip;
        Ok(self.offset)
    }

    /// Pops the last offset pushed by `push_backtrack`.
    ///
    /// NOTE: `start_backtrack` MUST be called before `pop_backtrack`.
    ///
    /// # Arguments
    ///
    /// * `expected_width` - The expected number of bytes reserved by the backtrack.
    fn pop_backtrack(&mut self, expected_width: usize) -> Result<(), DpeErrorCode> {
        if self.saved_offset.is_none() {
            return Err(DpeErrorCode::X509InvalidState);
        }
        let Some(range) = self.backtracks.pop() else {
            return Err(DpeErrorCode::X509InvalidState);
        };
        if (range.1 - range.0) != expected_width {
            return Err(DpeErrorCode::X509InvalidWidth);
        }
        self.offset = range.0;
        Ok(())
    }

    /// Saves the current offset to begin a backtrack sequence.
    ///
    /// NOTE: `start_backtrack` MUST be called before `pop_backtrack`.
    fn start_backtrack(&mut self) -> Result<(), DpeErrorCode> {
        if self.saved_offset.is_some() {
            return Err(DpeErrorCode::X509InvalidState);
        }
        self.saved_offset = Some(self.offset);
        Ok(())
    }

    /// Restores the offset to where it was before the pop sequence began.
    fn end_backtrack(&mut self) -> Result<(), DpeErrorCode> {
        let Some(offset) = self.saved_offset else {
            Err(DpeErrorCode::X509InvalidState)?
        };
        self.offset = offset;
        self.saved_offset = None;
        Ok(())
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
                + Self::get_bytes_size(name.cn.bytes(), true)?,
            /*tagged=*/ true,
        )?;
        let serialnumber_seq_size = Self::get_structure_size(
            Self::get_bytes_size(&Self::RDN_COMMON_NAME_OID, /*tagged=*/ true)?
                + Self::get_bytes_size(name.serial.bytes(), /*tagged=*/ true)?,
            /*tagged=*/ true,
        )?;

        let cn_set_size = Self::get_structure_size(cn_seq_size, /*tagged=*/ true)?;
        let serialnumber_set_size =
            Self::get_structure_size(serialnumber_seq_size, /*tagged=*/ true)?;

        Self::get_structure_size(cn_set_size + serialnumber_set_size, tagged)
    }

    fn sig_oid(&self) -> Result<&'static [u8], DpeErrorCode> {
        match self.profile {
            #[cfg(feature = "p256")]
            DpeProfile::P256Sha256 => Ok(profile_oids::ECDSA_WITH_SHA256_OID),
            #[cfg(feature = "p384")]
            DpeProfile::P384Sha384 => Ok(profile_oids::ECDSA_WITH_SHA384_OID),
            #[cfg(feature = "ml-dsa")]
            DpeProfile::Mldsa87ExternalMu => Ok(Self::MLDSA_OID),
            _ => Err(DpeErrorCode::X509AlgorithmMismatch),
        }
    }

    fn hash_oid(&self) -> Result<&'static [u8], DpeErrorCode> {
        match self.profile {
            #[cfg(feature = "p256")]
            DpeProfile::P256Sha256 => Ok(profile_oids::HASH_SHA256_OID),
            #[cfg(feature = "p384")]
            DpeProfile::P384Sha384 => Ok(Self::HASH_SHA384_OID),
            #[cfg(feature = "ml-dsa")]
            DpeProfile::Mldsa87ExternalMu => Ok(Self::HASH_SHA384_OID),
            _ => Err(DpeErrorCode::X509AlgorithmMismatch),
        }
    }

    fn curve_oid(&self) -> Result<&'static [u8], DpeErrorCode> {
        match self.profile {
            #[cfg(feature = "p256")]
            DpeProfile::P256Sha256 => Ok(profile_oids::CURVE_P256_OID),
            #[cfg(feature = "p384")]
            DpeProfile::P384Sha384 => Ok(profile_oids::CURVE_P384_OID),
            _ => Err(DpeErrorCode::X509AlgorithmMismatch),
        }
    }

    /// Calculate the number of bytes for an ECC Public Key AlgorithmIdentifier
    /// If `tagged`, include the tag and size fields
    fn get_ec_pub_alg_id_size(&self, tagged: bool) -> Result<usize, DpeErrorCode> {
        let len = Self::get_bytes_size(Self::EC_PUB_OID, true)?
            + Self::get_bytes_size(self.curve_oid()?, true)?;
        Self::get_structure_size(len, tagged)
    }

    /// Calculate the number of bytes for an ECDSA signature AlgorithmIdentifier
    /// If `tagged`, include the tag and size fields
    fn get_ecdsa_sig_alg_id_size(&self, tagged: bool) -> Result<usize, DpeErrorCode> {
        let len = Self::get_bytes_size(self.sig_oid()?, true)?;
        Self::get_structure_size(len, tagged)
    }

    /// Calculate the number of bytes for an MLDSA-87 signature AlgorithmIdentifier
    /// If `tagged`, include the tag and size fields
    #[cfg(feature = "ml-dsa")]
    fn get_mldsa_sig_alg_id_size(&self, tagged: bool) -> Result<usize, DpeErrorCode> {
        let len = Self::get_bytes_size(self.sig_oid()?, true)?;
        Self::get_structure_size(len, tagged)
    }

    /// Calculate the number of bytes for a Hash AlgorithmIdentifier
    /// If `tagged`, include the tag and size fields
    #[cfg(not(feature = "disable_csr"))]
    fn get_hash_alg_id_size(&self, tagged: bool) -> Result<usize, DpeErrorCode> {
        let len = Self::get_bytes_size(self.hash_oid()?, true)?;
        Self::get_structure_size(len, tagged)
    }

    /// If `tagged`, include the tag and size fields
    #[cfg(not(feature = "disable_x509"))]
    fn get_validity_size(validity: &CertValidity, tagged: bool) -> Result<usize, DpeErrorCode> {
        let len = Self::get_bytes_size(validity.not_before.as_slice(), true)?
            + Self::get_bytes_size(validity.not_after.as_slice(), true)?;
        Self::get_structure_size(len, tagged)
    }

    /// Calculate the number of bytes an MLDSA-87 SubjectPublicKeyInfo will be
    /// If `tagged`, include the tag and size fields
    #[cfg(feature = "ml-dsa")]
    fn get_mldsa_subject_pubkey_info_size(
        &self,
        pubkey: &MldsaPublicKey,
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        let bitstring_size = Self::get_structure_size(1 + pubkey.0.len(), true)?;
        let seq_size = bitstring_size + self.get_mldsa_sig_alg_id_size(true)?;

        Self::get_structure_size(seq_size, tagged)
    }

    /// Calculate the number of bytes an ECC SubjectPublicKeyInfo will be
    /// If `tagged`, include the tag and size fields
    fn get_ecdsa_subject_pubkey_info_size(
        &self,
        pubkey: &EcdsaPubKey,
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        let point_size = 1 + pubkey.curve_size() + pubkey.curve_size();
        let bitstring_size = 1 + point_size;
        let seq_size = Self::get_structure_size(bitstring_size, /*tagged=*/ true)?
            + self.get_ec_pub_alg_id_size(/*tagged=*/ true)?;

        Self::get_structure_size(seq_size, tagged)
    }

    /// Calculate the number of bytes an SubjectPublicKeyInfo will be
    /// If `tagged`, include the tag and size fields
    fn get_subject_pubkey_info_size(
        &self,
        pubkey: &PubKey,
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        let size = match pubkey {
            PubKey::Ecdsa(pubkey) => {
                self.get_ecdsa_sig_alg_id_size(tagged)?
                    + self.get_ecdsa_subject_pubkey_info_size(pubkey, tagged)?
            }
            #[cfg(feature = "ml-dsa")]
            PubKey::MlDsa(pubkey) => {
                self.get_mldsa_sig_alg_id_size(tagged)?
                    + self.get_mldsa_subject_pubkey_info_size(pubkey, tagged)?
            }
        };
        Ok(size)
    }

    /// If `tagged`, include the tag and size fields
    #[cfg(not(feature = "disable_csr"))]
    fn get_signature_octet_string_size(
        &self,
        sig: &Signature,
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        let signature_size = match sig {
            Signature::Ecdsa(sig) => {
                self.get_ecdsa_sig_alg_id_size(tagged)?
                    + Self::get_ecdsa_signature_octet_string_size(sig, tagged)?
            }
            #[cfg(feature = "ml-dsa")]
            Signature::MlDsa(sig) => {
                self.get_mldsa_sig_alg_id_size(tagged)?
                    + Self::get_mldsa_signature_octet_string_size(sig, tagged)?
            }
        };
        Ok(signature_size)
    }

    /// If `tagged`, include the tag and size fields
    #[cfg(all(not(feature = "disable_csr"), feature = "ml-dsa"))]
    fn get_mldsa_signature_octet_string_size(
        sig: &MldsaSignature,
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        let seq_size =
            Self::get_structure_size(Self::get_integer_bytes_size(sig.as_slice(), true)?, true)?;

        // Wrapping structure size
        Self::get_structure_size(seq_size, tagged)
    }

    /// If `tagged`, include the tag and size fields
    #[cfg(not(feature = "disable_csr"))]
    fn get_ecdsa_signature_octet_string_size(
        sig: &EcdsaSignature,
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        let (r, s) = sig.as_slice();
        let seq_size = Self::get_structure_size(
            Self::get_integer_bytes_size(r, /*tagged=*/ true)?
                + Self::get_integer_bytes_size(s, /*tagged=*/ true)?,
            /*tagged=*/ true,
        )?;

        // Wrapping structure size
        Self::get_structure_size(seq_size, tagged)
    }

    /// version is marked as EXPLICIT [0]
    /// If `tagged`, include the explicit tag and size fields
    #[cfg(not(feature = "disable_x509"))]
    fn get_version_size(tagged: bool) -> Result<usize, DpeErrorCode> {
        let integer_size = Self::get_integer_size(Self::X509_V3, /*tagged=*/ true)?;

        // If tagged, also add explicit wrapping
        Self::get_structure_size(integer_size, tagged)
    }

    /// Get the size of a DICE FWID structure
    fn get_fwid_size(&self, digest: &[u8], tagged: bool) -> Result<usize, DpeErrorCode> {
        let size = Self::get_structure_size(self.hash_oid()?.len(), /*tagged=*/ true)?
            + Self::get_structure_size(digest.len(), /*tagged=*/ true)?;

        Self::get_structure_size(size, tagged)
    }

    /// Get the size of a tcg-dice-TcbInfo structure. For DPE, this is only used
    /// as part of a MultiTcbInfo. For this reason, do not include the standard
    /// extension fields. Only include the size of the structure itself.
    fn get_tcb_info_size(
        &self,
        node: &TciNodeData,
        supports_recursive: bool,
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        let fwid_size = self.get_fwid_size(&node.tci_current.0, /*tagged=*/ true)?;
        let svn_size = Self::get_integer_size(node.svn.into(), true)?;
        let integrity_registers_size = if supports_recursive {
            let fwid_size = self.get_fwid_size(&node.tci_cumulative.0, /*tagged=*/ true)?;
            let fwid_list_size = Self::get_structure_size(fwid_size, /*tagged=*/ true)?;
            let integrity_register_size =
                Self::get_structure_size(fwid_list_size, /*tagged=*/ true)?;
            Self::get_structure_size(integrity_register_size, /*tagged=*/ true)?
        } else {
            0
        };
        let fwids_size = Self::get_structure_size(fwid_size, /*tagged=*/ true)?;

        let size = fwids_size
            + (2 * Self::get_structure_size(core::mem::size_of::<u32>(), /*tagged=*/ true)?) // vendorInfo and type
            + integrity_registers_size
            + svn_size;

        Self::get_structure_size(size, tagged)
    }

    /// Get the size of a tcg-dice-MultiTcbInfo extension, including the extension
    /// OID and critical bits.
    fn get_multi_tcb_info_size(
        &self,
        measurements: &MeasurementData,
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        if measurements.tci_nodes.is_empty() {
            return Err(DpeErrorCode::InternalError);
        }

        // Size of concatenated tcb infos
        let tcb_infos_size = measurements.tci_nodes.len()
            * self.get_tcb_info_size(
                &measurements.tci_nodes[0],
                measurements.supports_recursive,
                /*tagged=*/ true,
            )?;

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
        // Extension data is a 2-byte BIT STRING
        let ext_size = Self::get_structure_size(2, /*tagged=*/ true)?;
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
            Self::ECA_OID.len()
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

    /// Get the size of an subjectKeyIdentifier extension, including the extension
    /// OID and critical bits.
    fn get_subject_key_identifier_extension_size(
        measurements: &MeasurementData,
        tagged: bool,
        is_x509: bool,
    ) -> Result<usize, DpeErrorCode> {
        if !measurements.is_ca || !is_x509 {
            return Ok(0);
        }
        let ski_size = measurements.subject_key_identifier.len();

        // Extension data is sequence -> octet string. To compute size, wrap
        // in tagging twice.
        let ext_size = Self::get_structure_size(ski_size, /*tagged=*/ true)?;
        let size = Self::get_structure_size(Self::SUBJECT_KEY_IDENTIFIER_OID.len(), /*tagged=*/true)? // Extension OID
            + Self::get_structure_size(Self::BOOL_SIZE, /*tagged=*/true)? // Critical bool
            + Self::get_structure_size(ext_size, /*tagged=*/true)?; // OCTET STRING

        Self::get_structure_size(size, tagged)
    }

    /// Get the size of an authorityKeyIdentifier extension, including the extension
    /// OID and critical bits.
    fn get_authority_key_identifier_extension_size(
        measurements: &MeasurementData,
        tagged: bool,
        is_x509: bool,
    ) -> Result<usize, DpeErrorCode> {
        if !is_x509 {
            return Ok(0);
        }
        let aki_size = Self::get_key_identifier_size(
            &measurements.authority_key_identifier,
            true,
            /*explicit=*/ false,
        )?;

        // Extension data is sequence -> octet string. To compute size, wrap
        // in tagging twice.
        let ext_size = Self::get_structure_size(aki_size, /*tagged=*/ true)?;
        let size = Self::get_structure_size(Self::AUTHORITY_KEY_IDENTIFIER_OID.len(), /*tagged=*/true)? // Extension OID
            + Self::get_structure_size(Self::BOOL_SIZE, /*tagged=*/true)? // Critical bool
            + Self::get_structure_size(ext_size, /*tagged=*/true)?; // OCTET STRING

        Self::get_structure_size(size, tagged)
    }

    fn get_subject_alt_name_extension_size(
        measurements: &MeasurementData,
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        match &measurements.subject_alt_name {
            None => Ok(0),
            Some(SubjectAltName::OtherName(other_name)) => {
                let san_size = Self::get_other_name_size(other_name, /*tagged=*/ true)?;

                // Extension data is sequence -> octet string. To compute size, wrap
                // in tagging twice.
                let ext_size = Self::get_structure_size(san_size, /*tagged=*/ true)?;
                let size = Self::get_structure_size(Self::SUBJECT_ALTERNATIVE_NAME_OID.len(), /*tagged=*/true)? // Extension OID
                    + Self::get_structure_size(Self::BOOL_SIZE, /*tagged=*/true)? // Critical bool
                    + Self::get_structure_size(ext_size, /*tagged=*/true)?; // OCTET STRING

                Self::get_structure_size(size, tagged)
            }
        }
    }

    fn get_other_name_size(other_name: &OtherName, tagged: bool) -> Result<usize, DpeErrorCode> {
        let size = Self::get_structure_size(other_name.oid.len(), /*tagged=*/ true)?
            + Self::get_other_name_value_size(
                other_name.other_name.as_slice(),
                /*tagged=*/ true,
                /*explicit=*/ true,
            )?;

        Self::get_structure_size(size, tagged)
    }

    fn get_other_name_value_size(
        other_name_value: &[u8],
        tagged: bool,
        explicit: bool,
    ) -> Result<usize, DpeErrorCode> {
        // Determine whether to include the explicit tag wrapping in the size calculation
        let size = Self::get_structure_size(other_name_value.len(), explicit)?;

        Self::get_structure_size(size, tagged)
    }

    /// Get the size of the TBS Extensions field.
    fn get_extensions_size(
        &self,
        measurements: &MeasurementData,
        tagged: bool,
        explicit: bool,
        is_x509: bool,
    ) -> Result<usize, DpeErrorCode> {
        let mut size = self.get_multi_tcb_info_size(measurements, /*tagged=*/ true)?
            + Self::get_ueid_size(measurements, /*tagged=*/ true)?
            + Self::get_basic_constraints_size(/*tagged=*/ true)?
            + Self::get_key_usage_size(/*tagged=*/ true)?
            + Self::get_extended_key_usage_size(measurements, /*tagged=*/ true)?
            + Self::get_subject_key_identifier_extension_size(
                measurements,
                /*tagged=*/ true,
                is_x509,
            )?
            + Self::get_authority_key_identifier_extension_size(
                measurements,
                /*tagged=*/ true,
                is_x509,
            )?
            + Self::get_subject_alt_name_extension_size(measurements, /*tagged=*/ true)?;

        // Determine whether to include the explicit tag wrapping in the size calculation
        size = Self::get_structure_size(size, /*tagged=*/ explicit)?;

        Self::get_structure_size(size, tagged)
    }

    /// Get the size of the ASN.1 TBSCertificate structure
    /// If `tagged`, include the tag and size fields
    #[allow(clippy::too_many_arguments)]
    #[cfg(not(feature = "disable_x509"))]
    fn get_tbs_size(
        &self,
        serial_number: &[u8],
        issuer_der: &[u8],
        subject_name: &Name,
        pubkey: &PubKey,
        measurements: &MeasurementData,
        validity: &CertValidity,
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        let tbs_size = Self::get_version_size(/*tagged=*/ true)?
            + Self::get_integer_bytes_size(serial_number, /*tagged=*/ true)?
            + self.get_subject_pubkey_info_size(pubkey, true)?
            + issuer_der.len()
            + Self::get_validity_size(validity, /*tagged=*/ true)?
            + Self::get_rdn_size(subject_name, /*tagged=*/ true)?
            + self.get_extensions_size(
                measurements,
                /*tagged=*/ true,
                /*explicit=*/ true,
                /*is_x509=*/ true,
            )?;

        Self::get_structure_size(tbs_size, tagged)
    }

    /// Get the size of the ASN.1 CertificationRequestInfo structure
    /// If `tagged`, include the tag and size fields
    #[cfg(not(feature = "disable_csr"))]
    fn get_certification_request_info_size(
        &self,
        subject_name: &Name,
        pubkey: &PubKey,
        measurements: &MeasurementData,
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        let pubkey_size = match pubkey {
            PubKey::Ecdsa(pubkey) => self.get_ecdsa_subject_pubkey_info_size(pubkey, true)?,
            #[cfg(feature = "ml-dsa")]
            PubKey::MlDsa(pubkey) => self.get_mldsa_subject_pubkey_info_size(pubkey, true)?,
        };
        let cert_req_info_size = Self::get_integer_size(Self::CSR_V0, true)?
            + Self::get_rdn_size(subject_name, /*tagged=*/ true)?
            + self.get_attributes_size(measurements, /*tagged=*/ true)?
            + pubkey_size;

        Self::get_structure_size(cert_req_info_size, tagged)
    }

    /// Get the size of the CMS version which differs based on the SignerIdentifier
    #[cfg(not(feature = "disable_csr"))]
    fn get_cms_version_size(sid: &SignerIdentifier) -> Result<usize, DpeErrorCode> {
        match sid {
            SignerIdentifier::IssuerAndSerialNumber {
                issuer_name: _,
                serial_number: _,
            } => Self::get_integer_size(Self::CMS_V1, true),
            SignerIdentifier::SubjectKeyIdentifier(_) => Self::get_integer_size(Self::CMS_V3, true),
        }
    }

    /// Get the size of the ASN.1 SignerInfo structure
    /// If `tagged`, include the tag and size fields
    #[cfg(not(feature = "disable_csr"))]
    fn get_signer_info_size(
        &self,
        sig: &Signature,
        sid: &SignerIdentifier,
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        let signer_info_size = Self::get_cms_version_size(sid)?
            + Self::get_signer_identifier_size(sid, /*tagged=*/ true)?
            + self.get_hash_alg_id_size(/*tagged=*/ true)?
            + self.get_signature_octet_string_size(sig, true)?;

        Self::get_structure_size(signer_info_size, tagged)
    }

    /// Get the size of the ASN.1 SignedData structure
    /// If `tagged`, include the tag and size fields
    #[cfg(not(feature = "disable_csr"))]
    fn get_signed_data_size(
        &self,
        csr: &[u8],
        sig: &Signature,
        sid: &SignerIdentifier,
        tagged: bool,
        explicit: bool,
    ) -> Result<usize, DpeErrorCode> {
        let signed_data_size = Self::get_cms_version_size(sid)?
            + Self::get_structure_size(
                self.get_hash_alg_id_size(/*tagged=*/ true)?,
                /*tagged=*/ true,
            )?
            + Self::get_encap_content_info_size(csr.len(), /*tagged=*/ true)?
            + Self::get_structure_size(
                self.get_signer_info_size(sig, sid, /*tagged=*/ true)?,
                /*tagged=*/ true,
            )?;

        // Determine whether to include the explicit tag wrapping in the size calculation
        let explicit_signed_data_size = Self::get_structure_size(signed_data_size, explicit)?;

        Self::get_structure_size(explicit_signed_data_size, tagged)
    }

    /// Get the size of the ASN.1 SignerIdentifier structure
    /// If `tagged`, include the tag and size fields
    #[cfg(not(feature = "disable_csr"))]
    fn get_signer_identifier_size(
        sid: &SignerIdentifier,
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        match sid {
            SignerIdentifier::IssuerAndSerialNumber {
                issuer_name,
                serial_number,
            } => Self::get_issuer_and_serial_number_size(
                serial_number,
                issuer_name,
                /*tagged=*/ tagged,
            ),
            SignerIdentifier::SubjectKeyIdentifier(subject_key_identifier) => {
                Ok(Self::get_subject_key_identifier_size(
                    subject_key_identifier,
                    /*tagged=*/ tagged,
                    /*explicit=*/ true,
                )?)
            }
        }
    }

    /// Get the size of the ASN.1 IssuerAndSerialNumber structure
    /// If `tagged`, include the tag and size fields
    #[cfg(not(feature = "disable_csr"))]
    fn get_issuer_and_serial_number_size(
        serial_number: &[u8],
        issuer_der: &[u8],
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        let issuer_and_serial_number_size =
            Self::get_integer_bytes_size(serial_number, /*tagged=*/ true)? + issuer_der.len();

        Self::get_structure_size(issuer_and_serial_number_size, tagged)
    }

    /// Get the size of the ASN.1 SubjectKeyIdentifier structure
    /// If `tagged`, include the tag and size fields
    #[cfg(not(feature = "disable_csr"))]
    fn get_subject_key_identifier_size(
        subject_key_identifier: &[u8],
        tagged: bool,
        explicit: bool,
    ) -> Result<usize, DpeErrorCode> {
        let subject_key_identifier_size = subject_key_identifier.len();

        // Determine whether to include the explicit tag wrapping in the size calculation
        let explicit_bytes_size = Self::get_structure_size(subject_key_identifier_size, explicit)?;

        Self::get_structure_size(explicit_bytes_size, tagged)
    }

    /// Get the size of the ASN.1 KeyIdentifier structure
    /// If `tagged`, include the tag and size fields
    fn get_key_identifier_size(
        key_identifier: &[u8],
        tagged: bool,
        explicit: bool,
    ) -> Result<usize, DpeErrorCode> {
        let key_identifier_size = key_identifier.len();

        // Determine whether to include the explicit tag wrapping in the size calculation
        let explicit_bytes_size = Self::get_structure_size(key_identifier_size, explicit)?;

        Self::get_structure_size(explicit_bytes_size, tagged)
    }

    #[cfg(not(feature = "disable_csr"))]
    fn get_econtent_size(
        bytes_size: usize,
        tagged: bool,
        explicit: bool,
    ) -> Result<usize, DpeErrorCode> {
        // Determine whether to include the explicit tag wrapping in the size calculation
        let explicit_bytes_size = Self::get_structure_size(bytes_size, explicit)?;

        Self::get_structure_size(explicit_bytes_size, tagged)
    }

    /// Get the size of the ASN.1 EncapsulatedContentInfo structure
    /// If `tagged`, include the tag and size fields
    #[cfg(not(feature = "disable_csr"))]
    fn get_encap_content_info_size(
        csr_bytes_written: usize,
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        let encap_content_info_size =
            Self::get_structure_size(Self::ID_DATA_OID.len(), /*tagged=*/ true)?
                + Self::get_econtent_size(
                    csr_bytes_written,
                    /*tagged=*/ true,
                    /*explicit=*/ true,
                )?;

        Self::get_structure_size(encap_content_info_size, tagged)
    }

    /// Get the size of the ASN.1 Attribute structure
    /// If `tagged`, include the tag and size fields
    #[cfg(not(feature = "disable_csr"))]
    fn get_attribute_size(
        &self,
        measurements: &MeasurementData,
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        let attribute_size =
            Self::get_structure_size(Self::ID_DATA_OID.len(), /*tagged=*/ true)?
                + Self::get_structure_size(
                    self.get_extensions_size(
                        measurements,
                        /*tagged=*/ true,
                        /*explicit=*/ false,
                        /*is_x509=*/ false,
                    )?,
                    /*tagged=*/ true,
                )?;

        Self::get_structure_size(attribute_size, tagged)
    }

    /// Get the size of the ASN.1 Attributes structure
    /// If `tagged`, include the tag and size fields
    #[cfg(not(feature = "disable_csr"))]
    fn get_attributes_size(
        &self,
        measurements: &MeasurementData,
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        let attribute_size = self.get_attribute_size(measurements, /*tagged=*/ true)?;

        Self::get_structure_size(attribute_size, tagged)
    }

    /// Write all of `bytes` to the certificate buffer
    fn encode_bytes(&mut self, bytes: &[u8]) -> Result<usize, DpeErrorCode> {
        let size = bytes.len();

        self.certificate
            .get_mut(self.offset..self.offset + size)
            .ok_or(DpeErrorCode::InternalError)?
            .copy_from_slice(bytes);
        self.offset += size;

        Ok(size)
    }

    /// Write a single `byte` to the certificate buffer
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
    fn encode_integer_bytes(
        &mut self,
        integer: &[u8],
        tagged: bool,
    ) -> Result<usize, DpeErrorCode> {
        let mut bytes_written = if tagged {
            self.encode_tag_field(Self::INTEGER_TAG)?
        } else {
            0
        };

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
    fn encode_integer(&mut self, integer: u64, tagged: bool) -> Result<usize, DpeErrorCode> {
        self.encode_integer_bytes(&integer.to_be_bytes(), tagged)
    }

    /// DER-encodes `oid` as an ASN.1 ObjectIdentifier
    fn encode_oid(&mut self, oid: &[u8]) -> Result<usize, DpeErrorCode> {
        let mut bytes_written = self.encode_tag_field(Self::OID_TAG)?;
        bytes_written += self.encode_size_field(oid.len())?;
        bytes_written += self.encode_bytes(oid)?;

        Ok(bytes_written)
    }

    /// Encode a DirectoryString for an RDN. Multiple string types are allowed, so
    /// this function accepts a `tag`. This is important because some verifiers
    /// will do an exact DER comparison when building cert chains.
    fn encode_rdn_string(&mut self, s: &DirectoryString) -> Result<usize, DpeErrorCode> {
        let (val, tag) = match s {
            DirectoryString::PrintableString(val) => (val, Self::PRINTABLE_STRING_TAG),
            DirectoryString::Utf8String(val) => (val, Self::UTF8_STRING_TAG),
        };
        let mut bytes_written = self.encode_tag_field(tag)?;
        bytes_written += self.encode_size_field(val.len())?;
        bytes_written += self.encode_bytes(val)?;

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
        bytes_written += self.encode_rdn_string(&name.cn)?;

        // Encode RDN SET
        bytes_written += self.encode_tag_field(Self::SET_OF_TAG)?;
        bytes_written += self.encode_size_field(rnd_serial_set_size)?;

        // Encode SERIALNUMBER SEQUENCE
        bytes_written += self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(serialnumber_size)?;
        bytes_written += self.encode_oid(&Self::RDN_SERIALNUMBER_OID)?;
        bytes_written += self.encode_rdn_string(&name.serial)?;

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
        let seq_size = self.get_ec_pub_alg_id_size(/*tagged=*/ false)?;

        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(seq_size)?;
        bytes_written += self.encode_oid(Self::EC_PUB_OID)?;
        bytes_written += self.encode_oid(self.curve_oid()?)?;

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
        let seq_size = self.get_ecdsa_sig_alg_id_size(/*tagged=*/ false)?;

        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(seq_size)?;
        bytes_written += self.encode_oid(self.sig_oid()?)?;

        Ok(bytes_written)
    }

    /// DER-encodes the AlgorithmIdentifier for the hash algorithm
    /// used by the active DPE profile.
    ///
    /// AlgorithmIdentifier  ::=  SEQUENCE  {
    ///     algorithm   OBJECT IDENTIFIER,
    ///     parameters  ECParameters
    ///     }
    #[cfg(not(feature = "disable_csr"))]
    fn encode_hash_alg_id(&mut self) -> Result<usize, DpeErrorCode> {
        let seq_size = self.get_hash_alg_id_size(/*tagged=*/ false)?;

        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(seq_size)?;
        bytes_written += self.encode_oid(self.hash_oid()?)?;

        Ok(bytes_written)
    }

    // Encode ASN.1 Validity according to Platform
    #[cfg(not(feature = "disable_x509"))]
    fn encode_validity(&mut self, validity: &CertValidity) -> Result<usize, DpeErrorCode> {
        let seq_size = Self::get_validity_size(validity, /*tagged=*/ false)?;

        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(seq_size)?;

        bytes_written += self.encode_tag_field(Self::GENERALIZE_TIME_TAG)?;
        bytes_written += self.encode_size_field(validity.not_before.len())?;
        bytes_written += self.encode_bytes(validity.not_before.as_slice())?;

        bytes_written += self.encode_tag_field(Self::GENERALIZE_TIME_TAG)?;
        bytes_written += self.encode_size_field(validity.not_after.len())?;
        bytes_written += self.encode_bytes(validity.not_after.as_slice())?;

        Ok(bytes_written)
    }

    /// Encode SubjectPublicKeyInfo for an ECDSA public key
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
    ///
    /// Returns number of bytes written to `certificate`
    fn encode_ecdsa_subject_pubkey_info(
        &mut self,
        pub_key: &EcdsaPubKey,
    ) -> Result<usize, DpeErrorCode> {
        let point_size = 1 + pub_key.curve_size() + pub_key.curve_size();
        let bitstring_size = 1 + point_size;
        let seq_size = Self::get_structure_size(bitstring_size, /*tagged=*/ true)?
            + self.get_ec_pub_alg_id_size(/*tagged=*/ true)?;

        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(seq_size)?;
        bytes_written += self.encode_ec_pub_alg_id()?;

        bytes_written += self.encode_tag_field(Self::BIT_STRING_TAG)?;
        bytes_written += self.encode_size_field(bitstring_size)?;
        // First byte of BIT STRING is the number of unused bits. But all bits
        // are used.
        bytes_written += self.encode_byte(0)?;

        bytes_written += self.encode_byte(0x4)?;
        let (x, y) = pub_key.as_slice();
        bytes_written += self.encode_bytes(x)?;
        bytes_written += self.encode_bytes(y)?;

        Ok(bytes_written)
    }

    /// BIT STRING containing
    ///
    /// ECDSA-Sig-Value ::= SEQUENCE {
    ///     r  INTEGER,
    ///     s  INTEGER
    ///   }
    fn encode_ecdsa_signature_bit_string(
        &mut self,
        sig: &EcdsaSignature,
    ) -> Result<usize, DpeErrorCode> {
        let (r, s) = sig.as_slice();
        let seq_size = Self::get_integer_bytes_size(r, /*tagged=*/ true)?
            + Self::get_integer_bytes_size(s, /*tagged=*/ true)?;

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
        bytes_written += self.encode_integer_bytes(r, true)?;
        bytes_written += self.encode_integer_bytes(s, true)?;

        Ok(bytes_written)
    }

    /// Encode Signature into BIT STRING
    #[cfg(not(feature = "disable_csr"))]
    fn encode_signature_bit_string(&mut self, sig: &Signature) -> Result<usize, DpeErrorCode> {
        let bytes_written = match sig {
            Signature::Ecdsa(sig) => {
                // Alg ID
                self.encode_ecdsa_sig_alg_id()? +
                // Signature
                self.encode_ecdsa_signature_bit_string(sig)?
            }
            #[cfg(feature = "ml-dsa")]
            Signature::MlDsa(sig) => {
                // Alg ID
                self.encode_mldsa_sig_alg_id()? +
                // Signature
                self.encode_mldsa_signature_bit_string(sig)?
            }
        };
        Ok(bytes_written)
    }

    /// Encode Signature into OCTET STRING
    #[cfg(not(feature = "disable_csr"))]
    fn encode_signature_octet_string(&mut self, sig: &Signature) -> Result<usize, DpeErrorCode> {
        let bytes_written = match sig {
            Signature::Ecdsa(sig) => {
                // Alg ID
                self.encode_ecdsa_sig_alg_id()? +
                // Signature
                self.encode_ecdsa_signature_octet_string(sig)?
            }
            #[cfg(feature = "ml-dsa")]
            Signature::MlDsa(sig) => {
                // Alg ID
                self.encode_mldsa_sig_alg_id()? +
                // Signature
                self.encode_mldsa_signature_octet_string(sig)?
            }
        };
        Ok(bytes_written)
    }

    /// OCTET STRING containing
    ///
    /// ECDSA-Sig-Value ::= SEQUENCE {
    ///     r  INTEGER,
    ///     s  INTEGER
    ///   }
    #[cfg(not(feature = "disable_csr"))]
    fn encode_ecdsa_signature_octet_string(
        &mut self,
        sig: &EcdsaSignature,
    ) -> Result<usize, DpeErrorCode> {
        let (r, s) = sig.as_slice();
        let seq_size = Self::get_integer_bytes_size(r, /*tagged=*/ true)?
            + Self::get_integer_bytes_size(s, /*tagged=*/ true)?;

        // Encode OCTET STRING
        let mut bytes_written = self.encode_tag_field(Self::OCTET_STRING_TAG)?;
        bytes_written +=
            self.encode_size_field(Self::get_structure_size(seq_size, /*tagged=*/ true)?)?;

        // Encode SEQUENCE
        bytes_written += self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(seq_size)?;
        bytes_written += self.encode_integer_bytes(r, true)?;
        bytes_written += self.encode_integer_bytes(s, true)?;

        Ok(bytes_written)
    }

    /// OCTET STRING containing
    ///
    /// MLDSA-87 Signature
    #[cfg(all(not(feature = "disable_csr"), feature = "ml-dsa"))]
    fn encode_mldsa_signature_octet_string(
        &mut self,
        sig: &MldsaSignature,
    ) -> Result<usize, DpeErrorCode> {
        let sig = sig.as_bytes();
        let seq_size = Self::get_integer_bytes_size(sig, true)?;

        // Encode OCTET STRING
        let mut bytes_written = self.encode_tag_field(Self::OCTET_STRING_TAG)?;
        bytes_written += self.encode_size_field(Self::get_structure_size(seq_size, true)?)?;

        // Encode SEQUENCE
        bytes_written += self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(seq_size)?;
        bytes_written += self.encode_integer_bytes(sig, true)?;

        Ok(bytes_written)
    }

    /// DER-encodes the AlgorithmIdentifier for the MLDSA-87 signature algorithm
    #[cfg(feature = "ml-dsa")]
    fn encode_mldsa_sig_alg_id(&mut self) -> Result<usize, DpeErrorCode> {
        let seq_size = self.get_mldsa_sig_alg_id_size(false)?;

        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(seq_size)?;
        bytes_written += self.encode_oid(self.sig_oid()?)?;

        Ok(bytes_written)
    }

    /// Encode SubjectPublicKeyInfo for an MLDSA-87 public key
    #[cfg(feature = "ml-dsa")]
    fn encode_mldsa_subject_pubkey_info(
        &mut self,
        pub_key: &MldsaPublicKey,
    ) -> Result<usize, DpeErrorCode> {
        let seq_size = self.get_mldsa_subject_pubkey_info_size(pub_key, false)?;

        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(seq_size)?;
        bytes_written += self.encode_mldsa_sig_alg_id()?;

        bytes_written += self.encode_tag_field(Self::BIT_STRING_TAG)?;
        bytes_written += self.encode_size_field(1 + pub_key.0.len())?;
        // First byte of BIT STRING is the number of unused bits.
        bytes_written += self.encode_byte(0)?;
        bytes_written += self.encode_bytes(&pub_key.0)?;

        Ok(bytes_written)
    }

    /// BIT STRING containing signature
    #[cfg(feature = "ml-dsa")]
    fn encode_mldsa_signature_bit_string(
        &mut self,
        sig: &MldsaSignature,
    ) -> Result<usize, DpeErrorCode> {
        // Encode BIT STRING
        let mut bytes_written = self.encode_tag_field(Self::BIT_STRING_TAG)?;
        bytes_written += self.encode_size_field(1 + sig.0.len())?;
        // Unused bits
        bytes_written += self.encode_byte(0)?;
        bytes_written += self.encode_bytes(&sig.0)?;

        Ok(bytes_written)
    }

    pub fn encode_version(&mut self) -> Result<usize, DpeErrorCode> {
        // Version is EXPLICIT field number 0
        let mut bytes_written = self.encode_byte(Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED)?;
        bytes_written += self.encode_size_field(Self::get_integer_size(
            Self::X509_V3,
            /*tagged=*/ true,
        )?)?;
        bytes_written += self.encode_integer(Self::X509_V3, true)?;

        Ok(bytes_written)
    }

    fn encode_fwid(&mut self, tci: &TciMeasurement) -> Result<usize, DpeErrorCode> {
        let mut bytes_written = self.encode_byte(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(self.get_fwid_size(&tci.0, /*tagged=*/ false)?)?;

        // hashAlg OID
        let oid = self.hash_oid()?;
        bytes_written += self.encode_byte(Self::OID_TAG)?;
        bytes_written += self.encode_size_field(oid.len())?;
        bytes_written += self.encode_bytes(oid)?;

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
    fn encode_tcb_info(
        &mut self,
        node: &TciNodeData,
        supports_recursive: bool,
    ) -> Result<usize, DpeErrorCode> {
        let tcb_info_size =
            self.get_tcb_info_size(node, supports_recursive, /*tagged=*/ false)?;
        // TcbInfo sequence
        let mut bytes_written = self.encode_byte(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(tcb_info_size)?;

        // svn INTEGER
        // IMPLICIT [3] Primitive
        bytes_written += self.encode_byte(Self::CONTEXT_SPECIFIC | 0x03)?;
        bytes_written += self.encode_integer(node.svn.into(), false)?;

        // fwids SEQUENCE OF
        // IMPLICIT [6] Constructed
        let fwid_size = self.get_fwid_size(&node.tci_current.0, /*tagged=*/ true)?;
        bytes_written += self.encode_byte(Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED | 0x06)?;
        bytes_written += self.encode_size_field(fwid_size)?;

        // fwid[0] current measurement
        bytes_written += self.encode_fwid(&node.tci_current)?;

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
        bytes_written += self.encode_bytes(node.tci_type.as_bytes())?;

        // Omit integrityRegisters from tcb_info if the profile does not support recursive
        if supports_recursive {
            // integrityRegisters SEQUENCE OF
            // IMPLICIT [10] Constructed
            let fwid_size = self.get_fwid_size(&node.tci_cumulative.0, /*tagged=*/ true)?;
            let fwid_list_size = Self::get_structure_size(fwid_size, /*tagged=*/ true)?;
            let integrity_register_size =
                Self::get_structure_size(fwid_list_size, /*tagged=*/ true)?;

            bytes_written += self.encode_byte(Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED | 0xa)?;
            bytes_written += self.encode_size_field(integrity_register_size)?;

            // integrityRegusters[0] SEQUENCE
            bytes_written += self.encode_byte(Self::SEQUENCE_TAG)?;
            bytes_written += self.encode_size_field(fwid_list_size)?;

            // IMPLICIT [2] Constructed
            // registerDigests SEQUENCE OF FWID
            // cumulative measurement
            // Note: registerName and registerNum are omitted because DPE only
            // supports a single register.
            bytes_written += self.encode_byte(Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED | 0x02)?;
            bytes_written += self.encode_size_field(fwid_size)?;
            bytes_written += self.encode_fwid(&node.tci_cumulative)?;
        }

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
            self.get_multi_tcb_info_size(measurements, /*tagged=*/ false)?;

        // Encode Extension
        let mut bytes_written = self.encode_byte(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(multi_tcb_info_size)?;
        bytes_written += self.encode_oid(Self::MULTI_TCBINFO_OID)?;

        let crit = if self.crit_dice { 0xFF } else { 0x00 };
        bytes_written += self.encode_byte(Self::BOOL_TAG)?;
        bytes_written += self.encode_size_field(Self::BOOL_SIZE)?;
        bytes_written += self.encode_byte(crit)?;

        let tcb_infos_size = if !measurements.tci_nodes.is_empty() {
            self.get_tcb_info_size(
                &measurements.tci_nodes[0],
                measurements.supports_recursive,
                /*tagged=*/ true,
            )? * measurements.tci_nodes.len()
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
            bytes_written += self.encode_tcb_info(node, measurements.supports_recursive)?;
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
            bytes_written += self.encode_byte(0xFF)?;
        } else {
            bytes_written += self.encode_byte(0x00)?;
        }

        Ok(bytes_written)
    }

    /// Encode a KeyUsage extension
    ///
    /// https://datatracker.ietf.org/doc/html/rfc5280
    fn encode_key_usage(&mut self, is_ca: bool) -> Result<usize, DpeErrorCode> {
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
        bytes_written +=
            self.encode_size_field(Self::get_structure_size(2, /*tagged=*/ true)?)?;

        bytes_written += self.encode_byte(Self::BIT_STRING_TAG)?;

        // Bit string is 2 bytes:
        // * Unused bits
        // * KeyUsage bits
        bytes_written += self.encode_size_field(2)?;

        // Count trailing bits in KeyUsage byte as unused
        let (key_usage, unused_bits) = if is_ca {
            (
                KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::KEY_CERT_SIGN,
                2,
            )
        } else {
            (KeyUsageFlags::DIGITAL_SIGNATURE, 7)
        };

        // Unused bits
        bytes_written += self.encode_byte(unused_bits)?;

        bytes_written += self.encode_byte(key_usage.0)?;

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
            Self::ECA_OID
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

    #[allow(clippy::identity_op)]
    fn encode_other_name_value(&mut self, other_name_value: &[u8]) -> Result<usize, DpeErrorCode> {
        // value is EXPLICIT field number 0
        let mut bytes_written =
            self.encode_byte(Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED | 0x0)?;
        bytes_written += self.encode_size_field(Self::get_other_name_value_size(
            other_name_value,
            /*tagged=*/ true,
            /*explicit=*/ false,
        )?)?;

        // value := UTF8STRING
        bytes_written += self.encode_tag_field(Self::UTF8_STRING_TAG)?;
        bytes_written += self.encode_size_field(Self::get_other_name_value_size(
            other_name_value,
            /*tagged=*/ false,
            /*explicit=*/ false,
        )?)?;
        bytes_written += self.encode_bytes(other_name_value)?;

        Ok(bytes_written)
    }

    /// OtherName ::= SEQUENCE {
    ///    type-id    OBJECT IDENTIFIER,
    ///    value      [0] EXPLICIT ANY DEFINED BY type-id
    /// }
    #[allow(clippy::identity_op)]
    fn encode_other_name(&mut self, other_name: &OtherName) -> Result<usize, DpeErrorCode> {
        // otherName is EXPLICIT field number 0
        let mut bytes_written =
            self.encode_byte(Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED | 0x0)?;

        bytes_written += self.encode_size_field(Self::get_other_name_size(
            other_name, /*tagged=*/ false,
        )?)?;
        bytes_written += self.encode_oid(other_name.oid)?;
        bytes_written += self.encode_other_name_value(other_name.other_name.as_slice())?;

        Ok(bytes_written)
    }

    /// SubjectAltName ::= GeneralNames
    ///
    /// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
    ///
    /// GeneralName ::= CHOICE {
    ///    otherName                       [0]     OtherName,
    ///    rfc822Name                      [1]     IA5String,
    ///    dNSName                         [2]     IA5String,
    ///    x400Address                     [3]     ORAddress,
    ///    directoryName                   [4]     Name,
    ///    ediPartyName                    [5]     EDIPartyName,
    ///    uniformResourceIdentifier       [6]     IA5String,
    ///    iPAddress                       [7]     OCTET STRING,
    ///    registeredID                    [8]     OBJECT IDENTIFIER
    /// }
    ///
    /// Currently, only otherName is supported.
    fn encode_subject_alt_name_extension(
        &mut self,
        measurements: &MeasurementData,
    ) -> Result<usize, DpeErrorCode> {
        match &measurements.subject_alt_name {
            None => Ok(0),
            Some(SubjectAltName::OtherName(other_name)) => {
                // Encode Extension
                let san_extension_size = Self::get_subject_alt_name_extension_size(
                    measurements,
                    /*tagged=*/ false,
                )?;
                let mut bytes_written = self.encode_byte(Self::SEQUENCE_TAG)?;
                bytes_written += self.encode_size_field(san_extension_size)?;
                bytes_written += self.encode_oid(Self::SUBJECT_ALTERNATIVE_NAME_OID)?;

                bytes_written += self.encode_byte(Self::BOOL_TAG)?;
                bytes_written += self.encode_size_field(Self::BOOL_SIZE)?;
                // authority key identifier extension must NOT be marked critical
                bytes_written += self.encode_byte(0x00)?;

                // Extension data is sequence -> octet string. To compute size, wrap
                // in tagging once.
                let other_name_size = Self::get_other_name_size(other_name, /*tagged=*/ true)?;
                bytes_written += self.encode_byte(Self::OCTET_STRING_TAG)?;
                bytes_written += self.encode_size_field(Self::get_structure_size(
                    other_name_size,
                    /*tagged=*/ true,
                )?)?;

                bytes_written += self.encode_byte(Self::SEQUENCE_TAG)?;
                bytes_written += self.encode_size_field(other_name_size)?;
                bytes_written += self.encode_other_name(other_name)?;

                Ok(bytes_written)
            }
        }
    }

    /// AuthorityKeyIdentifier ::= SEQUENCE {
    ///     keyIdentifier             [0] KeyIdentifier           OPTIONAL,
    ///     authorityCertIssuer       [1] GeneralNames            OPTIONAL,
    ///     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL
    /// }
    fn encode_authority_key_identifier_extension(
        &mut self,
        measurements: &MeasurementData,
        is_x509: bool,
    ) -> Result<usize, DpeErrorCode> {
        if !is_x509 {
            return Ok(0);
        }

        let aki_extension_size = Self::get_authority_key_identifier_extension_size(
            measurements,
            /*tagged=*/ false,
            is_x509,
        )?;

        // Encode Extension
        let mut bytes_written = self.encode_byte(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(aki_extension_size)?;
        bytes_written += self.encode_oid(Self::AUTHORITY_KEY_IDENTIFIER_OID)?;

        bytes_written += self.encode_byte(Self::BOOL_TAG)?;
        bytes_written += self.encode_size_field(Self::BOOL_SIZE)?;
        // authority key identifier extension must NOT be marked critical
        bytes_written += self.encode_byte(0x00)?;

        // Extension data is sequence -> octet string. To compute size, wrap
        // in tagging once.
        let key_identifier_size = Self::get_key_identifier_size(
            &measurements.authority_key_identifier,
            /*tagged=*/ true,
            /*explicit=*/ false,
        )?;
        bytes_written += self.encode_byte(Self::OCTET_STRING_TAG)?;
        bytes_written += self.encode_size_field(Self::get_structure_size(
            key_identifier_size,
            /*tagged=*/ true,
        )?)?;

        // Encode extension data sequence
        bytes_written += self.encode_byte(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(key_identifier_size)?;
        bytes_written += self.encode_key_identifier(&measurements.authority_key_identifier)?;

        Ok(bytes_written)
    }

    fn encode_subject_key_identifier_extension(
        &mut self,
        measurements: &MeasurementData,
        is_x509: bool,
    ) -> Result<usize, DpeErrorCode> {
        if !measurements.is_ca || !is_x509 {
            return Ok(0);
        }
        let ski_extension_size = Self::get_subject_key_identifier_extension_size(
            measurements,
            /*tagged=*/ false,
            is_x509,
        )?;

        // Encode Extension
        let mut bytes_written = self.encode_byte(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(ski_extension_size)?;
        bytes_written += self.encode_oid(Self::SUBJECT_KEY_IDENTIFIER_OID)?;

        bytes_written += self.encode_byte(Self::BOOL_TAG)?;
        bytes_written += self.encode_size_field(Self::BOOL_SIZE)?;
        // subject key identifier extension must NOT be marked critical
        bytes_written += self.encode_byte(0x00)?;

        // Extension data is sequence -> octet string. To compute size, wrap
        // in tagging once.
        bytes_written += self.encode_byte(Self::OCTET_STRING_TAG)?;
        bytes_written += self.encode_size_field(Self::get_structure_size(
            measurements.subject_key_identifier.len(),
            /*tagged=*/ true,
        )?)?;

        // SubjectKeyIdentifier := OCTET STRING
        bytes_written += self.encode_byte(Self::OCTET_STRING_TAG)?;
        bytes_written += self.encode_size_field(measurements.subject_key_identifier.len())?;
        bytes_written += self.encode_bytes(&measurements.subject_key_identifier)?;

        Ok(bytes_written)
    }

    fn encode_extensions(
        &mut self,
        measurements: &MeasurementData,
        is_x509: bool,
    ) -> Result<usize, DpeErrorCode> {
        let mut bytes_written = 0;
        if is_x509 {
            // Extensions is EXPLICIT field number 3
            bytes_written += self.encode_byte(Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED | 0x03)?;
            bytes_written += self.encode_size_field(self.get_extensions_size(
                measurements,
                /*tagged=*/ true,
                /*explicit=*/ false,
                is_x509,
            )?)?;
        }

        // SEQUENCE OF Extension
        bytes_written += self.encode_byte(Self::SEQUENCE_OF_TAG)?;
        bytes_written += self.encode_size_field(self.get_extensions_size(
            measurements,
            /*tagged=*/ false,
            /*explicit=*/ false,
            is_x509,
        )?)?;

        bytes_written += self.encode_multi_tcb_info(measurements)?;
        bytes_written += self.encode_ueid(measurements)?;
        bytes_written += self.encode_basic_constraints(measurements)?;
        bytes_written += self.encode_key_usage(measurements.is_ca)?;
        bytes_written += self.encode_extended_key_usage(measurements)?;
        bytes_written += self.encode_subject_key_identifier_extension(measurements, is_x509)?;
        bytes_written += self.encode_authority_key_identifier_extension(measurements, is_x509)?;
        bytes_written += self.encode_subject_alt_name_extension(measurements)?;

        Ok(bytes_written)
    }

    /// Encodes an integer representing the CMS version which is dependent on the SignerIdentifier
    ///
    /// If the SignerIdentifier is IssuerAndSerialNumber the version is 1, otherwise it is 3.
    #[cfg(not(feature = "disable_csr"))]
    fn encode_cms_version(&mut self, sid: &SignerIdentifier) -> Result<usize, DpeErrorCode> {
        match sid {
            SignerIdentifier::IssuerAndSerialNumber {
                issuer_name: _,
                serial_number: _,
            } => self.encode_integer(Self::CMS_V1, true),
            SignerIdentifier::SubjectKeyIdentifier(_) => self.encode_integer(Self::CMS_V3, true),
        }
    }

    /// Encode an attributes structure
    ///
    /// Attributes ::= SET OF Attribute
    ///
    /// Attribute ::= SEQUENCE {
    ///    attrType OBJECT IDENTIFIER,
    ///    attrValues SET OF AttributeValue
    /// }
    ///
    /// AttributeValue ::= ANY -- Defined by attribute type
    #[allow(clippy::identity_op)]
    #[cfg(not(feature = "disable_csr"))]
    fn encode_attributes(&mut self, measurements: &MeasurementData) -> Result<usize, DpeErrorCode> {
        // Attributes is EXPLICIT field number 0
        let mut bytes_written =
            self.encode_byte(Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED | 0x0)?;
        bytes_written +=
            self.encode_size_field(self.get_attributes_size(measurements, /*tagged=*/ false)?)?;

        // Attribute Sequence
        bytes_written += self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written +=
            self.encode_size_field(self.get_attribute_size(measurements, /*tagged=*/ false)?)?;
        bytes_written += self.encode_oid(Self::EXTENSION_REQUEST_OID)?;

        // attrValues SET OF
        bytes_written += self.encode_tag_field(Self::SET_OF_TAG)?;
        bytes_written += self.encode_size_field(self.get_extensions_size(
            measurements,
            /*tagged=*/ true,
            /*explicit=*/ false,
            /*is_x509=*/ false,
        )?)?;

        // extensions
        bytes_written += self.encode_extensions(measurements, /*is_x509=*/ false)?;

        Ok(bytes_written)
    }

    /// Encode a SignerInfo
    ///
    /// SignerInfo  ::=  SEQUENCE  {
    ///    version CMSVersion,
    ///    sid SignerIdentifier,
    ///    digestAlgorithm DigestAlgorithmIdentifier,
    ///    signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
    ///    signatureAlgorithm SignatureAlgorithmIdentifier,
    ///    signature SignatureValue,
    ///    unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL
    /// }
    #[cfg(not(feature = "disable_csr"))]
    pub fn encode_signer_info(
        &mut self,
        sig: &Signature,
        sid: &SignerIdentifier,
    ) -> Result<usize, DpeErrorCode> {
        let signer_info_size = self.get_signer_info_size(sig, sid, /*tagged=*/ false)?;

        // SignerInfo Sequence
        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(signer_info_size)?;

        // CMS version
        bytes_written += self.encode_cms_version(sid)?;

        // SignerIdentifier
        bytes_written += self.encode_signer_identifier(sid)?;

        // digestAlgorithm
        bytes_written += self.encode_hash_alg_id()?;

        bytes_written += self.encode_signature_octet_string(sig)?;

        Ok(bytes_written)
    }

    /// Encode a SignerIdentifier
    ///
    /// SignerIdentifier ::= CHOICE {
    ///     issuerAndSerialNumber IssuerAndSerialNumber,
    ///     subjectKeyIdentifier [0] SubjectKeyIdentifier
    /// }
    #[cfg(not(feature = "disable_csr"))]
    fn encode_signer_identifier(&mut self, sid: &SignerIdentifier) -> Result<usize, DpeErrorCode> {
        match sid {
            SignerIdentifier::IssuerAndSerialNumber {
                issuer_name,
                serial_number,
            } => self.encode_issuer_and_serial_number(serial_number, issuer_name),
            SignerIdentifier::SubjectKeyIdentifier(subject_key_identifier) => {
                self.encode_subject_key_identifier(subject_key_identifier)
            }
        }
    }

    /// Encode an IssuerAndSerialNumber
    ///
    /// IssuerAndSerialNumber  ::=  SEQUENCE  {
    ///    issuer Name,
    ///    serialNumber CertificateSerialNumber
    /// }
    #[cfg(not(feature = "disable_csr"))]
    fn encode_issuer_and_serial_number(
        &mut self,
        serial_number: &[u8],
        issuer_name: &[u8],
    ) -> Result<usize, DpeErrorCode> {
        let issuer_and_serial_number_size = Self::get_issuer_and_serial_number_size(
            serial_number,
            issuer_name,
            /*tagged=*/ false,
        )?;

        // IssuerAndSerialNumber sequence
        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(issuer_and_serial_number_size)?;

        // issuer
        bytes_written += self.encode_bytes(issuer_name)?;

        // serialNumber
        bytes_written += self.encode_integer_bytes(serial_number, true)?;

        Ok(bytes_written)
    }

    /// Encode a SubjectKeyIdentifier
    ///
    /// SubjectKeyIdentifier ::= OCTET STRING
    #[allow(clippy::identity_op)]
    #[cfg(not(feature = "disable_csr"))]
    fn encode_subject_key_identifier(
        &mut self,
        subject_key_identifier: &[u8],
    ) -> Result<usize, DpeErrorCode> {
        // SubjectKeyIdentifier is IMPLICIT field number 0
        let mut bytes_written = self.encode_byte(Self::CONTEXT_SPECIFIC | 0x0)?;
        bytes_written += self.encode_size_field(Self::get_subject_key_identifier_size(
            subject_key_identifier,
            /*tagged=*/ true,
            /*explicit=*/ false,
        )?)?;

        // SubjectKeyIdentifier OCTET STRING
        bytes_written += self.encode_tag_field(Self::OCTET_STRING_TAG)?;
        bytes_written += self.encode_size_field(Self::get_subject_key_identifier_size(
            subject_key_identifier,
            /*tagged=*/ false,
            /*explicit=*/ false,
        )?)?;
        bytes_written += self.encode_bytes(subject_key_identifier)?;

        Ok(bytes_written)
    }

    /// Encode a KeyIdentifier
    ///
    /// KeyIdentifier ::= OCTET STRING
    #[allow(clippy::identity_op)]
    fn encode_key_identifier(&mut self, key_identifier: &[u8]) -> Result<usize, DpeErrorCode> {
        // KeyIdentifier is IMPLICIT field number 0
        let mut bytes_written = self.encode_byte(Self::CONTEXT_SPECIFIC | 0x0)?;
        bytes_written += self.encode_size_field(Self::get_key_identifier_size(
            key_identifier,
            /*tagged=*/ false,
            /*explicit=*/ false,
        )?)?;

        bytes_written += self.encode_bytes(key_identifier)?;

        Ok(bytes_written)
    }

    /// Encode an EncapsulatedContentInfo
    ///
    /// EncapsulatedContentInfo  ::=  SEQUENCE  {
    ///    eContentType ContentType,
    ///    eContent [0] EXPLICIT OCTET STRING OPTIONAL
    /// }
    #[cfg(not(feature = "disable_csr"))]
    #[allow(clippy::identity_op)]
    fn encode_encapsulated_content_info(
        &mut self,
        sign_cb: &mut impl FnMut(&[u8], bool) -> Result<Signature, CryptoError>,
        pub_key: &PubKey,
        subject_name: &Name,
        measurements: &MeasurementData,
    ) -> Result<usize, DpeErrorCode> {
        let mut size_bytes_written = self.encode_byte(Self::SEQUENCE_TAG)?;
        self.push_backtrack(SIZE_TAG_OFFSET)?;

        // EncapsulatedContentInfo Sequence
        let mut bytes_written = self.encode_oid(Self::ID_DATA_OID)?;

        // eContent is EXPLICIT field number 0
        bytes_written += self.encode_byte(Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED | 0x0)?;
        self.push_backtrack(SIZE_TAG_OFFSET)?;

        // eContent OCTET STRING
        bytes_written += self.encode_byte(Self::OCTET_STRING_TAG)?;
        let offset = self.push_backtrack(SIZE_TAG_OFFSET)?;

        let csr_bytes_written = self.encode_csr(sign_cb, pub_key, subject_name, measurements)?;
        self.csr_range = Some((offset, offset + csr_bytes_written));

        let econtent_1_size = Self::get_econtent_size(
            csr_bytes_written,
            /*tagged=*/ false,
            /*explicit=*/ false,
        )?;

        let econtent_0_size = Self::get_econtent_size(
            csr_bytes_written,
            /*tagged=*/ true,
            /*explicit=*/ false,
        )?;

        {
            self.start_backtrack()?;
            self.pop_backtrack(Self::get_size_width(econtent_1_size)?)?;
            bytes_written += self.encode_size_field(econtent_1_size)?;

            self.pop_backtrack(Self::get_size_width(econtent_0_size)?)?;
            bytes_written += self.encode_size_field(econtent_0_size)?;

            self.pop_backtrack(Self::get_size_width(bytes_written + csr_bytes_written)?)?;

            size_bytes_written += self.encode_size_field(bytes_written + csr_bytes_written)?;
            self.end_backtrack()?;
        }

        Ok(bytes_written + csr_bytes_written + size_bytes_written)
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
    /// * `pubkey` - Public key.
    /// * `measurements` - DPE measurement data.
    /// * `validity` - Time period in which certificate is valid.
    #[cfg(not(feature = "disable_x509"))]
    pub fn encode_tbs(
        &mut self,
        serial_number: &[u8],
        issuer_name: &[u8],
        subject_name: &Name,
        pubkey: &PubKey,
        measurements: &MeasurementData,
        validity: &CertValidity,
    ) -> Result<usize, DpeErrorCode> {
        let tbs_size = self.get_tbs_size(
            serial_number,
            issuer_name,
            subject_name,
            pubkey,
            measurements,
            validity,
            /*tagged=*/ false,
        )?;

        // TBS sequence
        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(tbs_size)?;

        // version
        bytes_written += self.encode_version()?;

        // serialNumber
        bytes_written += self.encode_integer_bytes(serial_number, true)?;

        // signature
        bytes_written += match pubkey {
            PubKey::Ecdsa(_) => self.encode_ecdsa_sig_alg_id()?,
            #[cfg(feature = "ml-dsa")]
            PubKey::MlDsa(_) => self.encode_mldsa_sig_alg_id()?,
        };

        // issuer
        bytes_written += self.encode_bytes(issuer_name)?;

        // validity
        bytes_written += self.encode_validity(validity)?;

        // subject
        bytes_written += self.encode_rdn(subject_name)?;

        // subjectPublicKeyInfo
        bytes_written += match pubkey {
            PubKey::Ecdsa(pub_key) => self.encode_ecdsa_subject_pubkey_info(pub_key)?,
            #[cfg(feature = "ml-dsa")]
            PubKey::MlDsa(pub_key) => self.encode_mldsa_subject_pubkey_info(pub_key)?,
        };

        // extensions
        bytes_written += self.encode_extensions(measurements, /*is_x509=*/ true)?;

        Ok(bytes_written)
    }

    /// Encode an ECDSA X.509 certificate
    ///
    /// Certificate  ::=  SEQUENCE  {
    ///    tbsCertificate       TBSCertificate,
    ///    signatureAlgorithm   AlgorithmIdentifier,
    ///    signatureValue       BIT STRING  }
    ///
    /// Returns number of bytes written to `certificate`
    #[cfg(not(feature = "disable_x509"))]
    #[allow(clippy::too_many_arguments)]
    pub fn encode_certificate(
        &mut self,
        sign_cb: &mut impl FnMut(&[u8], bool) -> Result<Signature, CryptoError>,
        serial_number: &[u8],
        issuer_name: &[u8],
        subject_name: &Name,
        pubkey: &PubKey,
        measurements: &MeasurementData,
        validity: &CertValidity,
    ) -> Result<usize, DpeErrorCode> {
        let mut prefix_bytes_written = self.encode_tag_field(Self::SEQUENCE_TAG)?;
        let offset = self.push_backtrack(SIZE_TAG_OFFSET)?;

        let tbs_bytes_written = self.encode_tbs(
            serial_number,
            issuer_name,
            subject_name,
            pubkey,
            measurements,
            validity,
        )?;

        let sig = {
            let tbs = &self.certificate[offset..tbs_bytes_written + offset];
            sign_cb(tbs, false)?
        };

        let sig_bytes_written = self.encode_signature_bit_string(&sig)?;

        let cert_size = tbs_bytes_written + sig_bytes_written;

        {
            self.start_backtrack()?;
            self.pop_backtrack(Self::get_size_width(cert_size)?)?;

            prefix_bytes_written += self.encode_size_field(cert_size)?;

            self.end_backtrack()?;
        }

        let total_size = cert_size + prefix_bytes_written;

        if !self.backtracks.is_empty() {
            return Err(DpeErrorCode::X509InvalidState);
        }

        Ok(total_size)
    }

    /// Encode a certification request info
    ///
    /// CertificationRequestInfo  ::=  SEQUENCE  {
    ///    version       INTEGER { v1(0) } (v1,...),
    ///    subject       Name,
    ///    subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
    ///    attributes    [0] Attributes{{ CRIAttributes }}}
    /// }
    ///
    /// # Arguments
    ///
    /// * `pubkey` - ECDSA Public key.
    /// * `subject_name` - The subject name RDN struct to encode.
    /// * `measurements` - DPE measurement data.
    ///
    /// Returns number of bytes written to `certificate`
    #[cfg(not(feature = "disable_csr"))]
    pub fn encode_certification_request_info(
        &mut self,
        pub_key: &PubKey,
        subject_name: &Name,
        measurements: &MeasurementData,
    ) -> Result<usize, DpeErrorCode> {
        let cert_req_info_size = self.get_certification_request_info_size(
            subject_name,
            pub_key,
            measurements,
            /*tagged=*/ false,
        )?;

        // CertificationRequestInfo Sequence
        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_TAG)?;
        bytes_written += self.encode_size_field(cert_req_info_size)?;

        // version
        bytes_written += self.encode_integer(Self::CSR_V0, true)?;

        // subject
        bytes_written += self.encode_rdn(subject_name)?;

        // subjectPublicKeyInfo
        match pub_key {
            PubKey::Ecdsa(pub_key) => {
                bytes_written += self.encode_ecdsa_subject_pubkey_info(pub_key)?;
            }
            #[cfg(feature = "ml-dsa")]
            PubKey::MlDsa(pub_key) => {
                bytes_written += self.encode_mldsa_subject_pubkey_info(pub_key)?;
            }
        }

        // attributes
        bytes_written += self.encode_attributes(measurements)?;

        Ok(bytes_written)
    }

    /// Encode an PKCS #10 CSR
    ///
    /// CertificateRequest  ::=  SEQUENCE  {
    ///    certificationRequestInfo       CertificationRequestInfo,
    ///    signatureAlgorithm             AlgorithmIdentifier,
    ///    signatureValue                 BIT STRING
    /// }
    ///
    /// Returns number of bytes written to `certificate`
    #[cfg(not(feature = "disable_csr"))]
    pub fn encode_csr(
        &mut self,
        sign_cb: &mut impl FnMut(&[u8], bool) -> Result<Signature, CryptoError>,
        pub_key: &PubKey,
        subject_name: &Name,
        measurements: &MeasurementData,
    ) -> Result<usize, DpeErrorCode> {
        let mut bytes_written = self.encode_tag_field(Self::SEQUENCE_TAG)?;
        let offset = self.push_backtrack(SIZE_TAG_OFFSET)?;

        // CertificateRequest sequence
        // CertificationRequestInfo
        let cert_req_size =
            self.encode_certification_request_info(pub_key, subject_name, measurements)?;

        let sig = {
            let tbs = &self.certificate[offset..cert_req_size + offset];
            sign_cb(tbs, true)?
        };

        // Signature
        let sig_bytes_written = self.encode_signature_bit_string(&sig)?;

        let csr_size = cert_req_size + sig_bytes_written;

        {
            self.start_backtrack()?;
            self.pop_backtrack(Self::get_size_width(csr_size)?)?;

            bytes_written += self.encode_size_field(csr_size)?;

            self.end_backtrack()?;
        }

        let total_size = csr_size + bytes_written;

        Ok(total_size)
    }

    /// Encode a CMS ContentInfo message
    ///
    /// ContentInfo  ::=  SEQUENCE  {
    ///    contentType ContentType,
    ///    content [0] EXPLICIT ANY DEFINED BY contentType
    /// }
    #[cfg(not(feature = "disable_csr"))]
    #[allow(clippy::identity_op)]
    pub fn encode_cms(
        &mut self,
        sign_cb: &mut impl FnMut(&[u8], bool) -> Result<Signature, CryptoError>,
        pub_key: &PubKey,
        subject_name: &Name,
        measurements: &MeasurementData,
        sid: &SignerIdentifier,
    ) -> Result<usize, DpeErrorCode> {
        let mut size_bytes_written = self.encode_byte(Self::SEQUENCE_TAG)?;
        let _ = self.push_backtrack(SIZE_TAG_OFFSET)?;

        let mut bytes_written = self.encode_oid(Self::ID_SIGNED_DATA_OID)?;

        // Encode a SignedData
        //
        // SignedData  ::=  SEQUENCE  {
        //    version CMSVersion,
        //    digestAlgorithms DigestAlgorithmIdentifiers,
        //    encapContentInfo EncapsulatedContentInfo,
        //    certificates [0] IMPLICIT CertificateSet OPTIONAL,
        //    crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
        //    signerInfos SignerInfos
        // }

        // SignedData is EXPLICIT field number 0
        bytes_written += self.encode_byte(Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED | 0x0)?;
        let _ = self.push_backtrack(SIZE_TAG_OFFSET)?;

        // SignedData sequence
        bytes_written += self.encode_tag_field(Self::SEQUENCE_TAG)?;
        let _ = self.push_backtrack(SIZE_TAG_OFFSET)?;

        // CMS version
        bytes_written += self.encode_cms_version(sid)?;

        // digestAlgorithms
        bytes_written += self.encode_tag_field(Self::SET_OF_TAG)?;
        bytes_written += self.encode_size_field(self.get_hash_alg_id_size(/*tagged=*/ true)?)?;
        bytes_written += self.encode_hash_alg_id()?;

        // encapContentInfo
        bytes_written +=
            self.encode_encapsulated_content_info(sign_cb, pub_key, subject_name, measurements)?;

        let csr = {
            let Some(csr_range) = self.csr_range else {
                Err(DpeErrorCode::X509CsrUnset)?
            };
            &self.certificate[csr_range.0..csr_range.1]
        };

        let sig = sign_cb(csr, false)?;

        let signed_data_field_0 = self.get_signed_data_size(
            csr, &sig, sid, /*tagged=*/ true, /*explicit=*/ false,
        )?;

        let signed_data_field_1 = self.get_signed_data_size(
            csr, &sig, sid, /*tagged=*/ false, /*explicit=*/ false,
        )?;

        // signerInfos
        bytes_written += self.encode_tag_field(Self::SET_OF_TAG)?;
        bytes_written +=
            self.encode_size_field(self.get_signer_info_size(&sig, sid, /*tagged=*/ true)?)?;
        bytes_written += self.encode_signer_info(&sig, sid)?;

        {
            self.start_backtrack()?;
            self.pop_backtrack(Self::get_size_width(signed_data_field_1)?)?;
            bytes_written += self.encode_size_field(signed_data_field_1)?;

            self.pop_backtrack(Self::get_size_width(signed_data_field_0)?)?;
            bytes_written += self.encode_size_field(signed_data_field_0)?;

            self.pop_backtrack(Self::get_size_width(bytes_written)?)?;
            size_bytes_written += self.encode_size_field(bytes_written)?;

            self.end_backtrack()?;
        }

        if !self.backtracks.is_empty() {
            return Err(DpeErrorCode::X509InvalidState);
        }

        Ok(bytes_written + size_bytes_written)
    }
}

enum CertificateFormat {
    X509,
    #[cfg(not(feature = "disable_csr"))]
    Csr,
}

enum CertificateType {
    Leaf,
    Exported,
}

/// Arguments for DPE cert or CSR creation.
pub(crate) struct CreateDpeCertArgs<'a> {
    /// Used by DPE to compute measurement digest
    pub handle: &'a ContextHandle,
    /// The locality of the caller
    pub locality: u32,
    /// Info string used in the CDI derivation
    pub cdi_label: &'a [u8],
    /// Label string used in the key derivation
    pub key_label: &'a [u8],
    /// Additional info string used in the key derivation
    pub context: &'a [u8],
    /// Ueid extension value
    pub ueid: &'a [u8],
    /// DICE extensions are marked as critical
    pub dice_extensions_are_critical: bool,
}

/// Results for DPE cert or CSR creation.
pub(crate) struct CreateDpeCertResult {
    /// Size of certificate or CSR in bytes.
    pub cert_size: u32,
    /// Public key embedded in Cert or CSR.
    pub pub_key: PubKey,
    /// If the cert_type is `CertificateType::Exported` the CDI is exchanged for a handle, and
    /// returned via `exported_cdi_handle`.
    pub exported_cdi_handle: [u8; MAX_EXPORTED_CDI_SIZE],
}

fn get_dpe_measurement_digest(
    dpe: &mut DpeInstance,
    env: &mut DpeEnv<impl DpeTypes>,
    handle: &ContextHandle,
    locality: u32,
) -> Result<Digest, DpeErrorCode> {
    let parent_idx = env.state.get_active_context_pos(handle, locality)?;
    let digest = dpe.compute_measurement_hash(env, parent_idx)?;
    Ok(digest)
}

fn get_subject_name<'a>(
    env: &mut DpeEnv<impl DpeTypes>,
    pub_key: &'a PubKey,
    subj_serial: &'a mut [u8],
) -> Result<Name<'a>, DpeErrorCode> {
    env.crypto.get_pubkey_serial(pub_key, subj_serial)?;

    // The serial number of the subject can be at most 64 bytes
    let truncated_subj_serial = &subj_serial[..64];

    let subject_name = Name {
        cn: DirectoryString::PrintableString(b"DPE Leaf"),
        serial: DirectoryString::PrintableString(truncated_subj_serial),
    };
    Ok(subject_name)
}

fn get_tci_nodes<'a>(
    state: &State,
    handle: &ContextHandle,
    locality: u32,
    nodes: &'a mut [TciNodeData],
) -> Result<&'a mut [TciNodeData], DpeErrorCode> {
    let parent_idx = state.get_active_context_pos(handle, locality)?;
    let tcb_count = state.get_tcb_nodes(parent_idx, nodes)?;
    if tcb_count > MAX_HANDLES {
        return Err(DpeErrorCode::InternalError);
    }
    Ok(&mut nodes[..tcb_count])
}

fn get_subject_key_identifier(
    env: &mut DpeEnv<impl DpeTypes>,
    pub_key: &PubKey,
    subject_key_identifier: &mut [u8],
) -> Result<(), DpeErrorCode> {
    // compute key identifier as SHA hash of the DER encoded subject public key
    let mut hasher = env.crypto.hash_initialize()?;
    match pub_key {
        PubKey::Ecdsa(pub_key) => {
            let (x, y) = pub_key.as_slice();
            hasher.update(&[0x04])?;
            hasher.update(x)?;
            hasher.update(y)?;
        }
        #[cfg(feature = "ml-dsa")]
        PubKey::MlDsa(pub_key) => {
            hasher.update(pub_key.as_slice())?;
        }
    }

    let hashed_pub_key = hasher.finish()?;
    if hashed_pub_key.size() < MAX_KEY_IDENTIFIER_SIZE {
        return Err(DpeErrorCode::InternalError);
    }
    // truncate key identifier to 20 bytes
    subject_key_identifier.copy_from_slice(&hashed_pub_key.as_slice()[..MAX_KEY_IDENTIFIER_SIZE]);
    Ok(())
}

pub(crate) fn create_exported_dpe_cert(
    args: &CreateDpeCertArgs,
    dpe: &mut DpeInstance,
    env: &mut DpeEnv<impl DpeTypes>,
    cert: &mut [u8],
) -> Result<CreateDpeCertResult, DpeErrorCode> {
    create_dpe_cert_or_csr(
        args,
        dpe,
        env,
        CertificateFormat::X509,
        CertificateType::Exported,
        cert,
    )
}

pub(crate) fn create_dpe_cert(
    args: &CreateDpeCertArgs,
    dpe: &mut DpeInstance,
    env: &mut DpeEnv<impl DpeTypes>,
    cert: &mut [u8],
) -> Result<CreateDpeCertResult, DpeErrorCode> {
    create_dpe_cert_or_csr(
        args,
        dpe,
        env,
        CertificateFormat::X509,
        CertificateType::Leaf,
        cert,
    )
}

#[cfg(not(feature = "disable_csr"))]
pub(crate) fn create_dpe_csr(
    args: &CreateDpeCertArgs,
    dpe: &mut DpeInstance,
    env: &mut DpeEnv<impl DpeTypes>,
    csr: &mut [u8],
) -> Result<CreateDpeCertResult, DpeErrorCode> {
    create_dpe_cert_or_csr(
        args,
        dpe,
        env,
        CertificateFormat::Csr,
        CertificateType::Leaf,
        csr,
    )
}

fn create_dpe_cert_or_csr(
    args: &CreateDpeCertArgs,
    dpe: &mut DpeInstance,
    env: &mut DpeEnv<impl DpeTypes>,
    cert_format: CertificateFormat,
    cert_type: CertificateType,
    output_cert_or_csr: &mut [u8],
) -> Result<CreateDpeCertResult, DpeErrorCode> {
    let digest = get_dpe_measurement_digest(dpe, env, args.handle, args.locality)?;

    let mut exported_cdi_handle = None;

    let key_pair = match cert_type {
        CertificateType::Exported => {
            let exported_handle = env.crypto.derive_exported_cdi(&digest, args.cdi_label)?;
            exported_cdi_handle = Some(exported_handle);
            env.crypto
                .derive_key_pair_exported(&exported_handle, args.key_label, args.context)
        }
        CertificateType::Leaf => {
            let cdi = env.crypto.derive_cdi(&digest, args.cdi_label)?;
            env.crypto
                .derive_key_pair(&cdi, args.key_label, args.context)
        }
    };
    if cfi_launder(key_pair.is_ok()) {
        #[cfg(not(feature = "no-cfi"))]
        cfi_assert!(key_pair.is_ok());
    } else {
        #[cfg(not(feature = "no-cfi"))]
        cfi_assert!(key_pair.is_err());
    }
    let (priv_key, pub_key) = key_pair?;
    let mut subj_serial = [0u8; MAX_HASH_SIZE * 2];
    let subject_name = get_subject_name(env, &pub_key, &mut subj_serial)?;

    const INITIALIZER: TciNodeData = TciNodeData::new();
    let mut nodes = [INITIALIZER; MAX_HANDLES];
    let tci_nodes = get_tci_nodes(env.state, args.handle, args.locality, &mut nodes)?;

    let mut subject_key_identifier = [0u8; MAX_KEY_IDENTIFIER_SIZE];
    get_subject_key_identifier(env, &pub_key, &mut subject_key_identifier)?;

    let mut authority_key_identifier = [0u8; MAX_KEY_IDENTIFIER_SIZE];
    env.platform
        .get_issuer_key_identifier(&mut authority_key_identifier)?;

    let subject_alt_name = match env.platform.get_subject_alternative_name() {
        Ok(subject_alt_name) => Some(subject_alt_name),
        Err(PlatformError::NotImplemented) => None,
        Err(e) => Err(DpeErrorCode::Platform(e))?,
    };

    let is_ca = match cert_type {
        CertificateType::Leaf => false,
        CertificateType::Exported => true,
    };

    let supports_recursive = match cert_type {
        CertificateType::Leaf => env.state.support.recursive(),
        CertificateType::Exported => false,
    };

    let measurements = MeasurementData {
        label: args.ueid,
        tci_nodes,
        is_ca,
        supports_recursive,
        subject_key_identifier,
        authority_key_identifier,
        subject_alt_name,
    };

    let mut sign_cb = |data: &[u8], use_derived: bool| {
        let hash = env.crypto.hash(data)?;
        if use_derived {
            env.crypto.sign_with_derived(&hash, &priv_key, &pub_key)
        } else {
            env.crypto.sign_with_alias(&hash)
        }
    };

    let cert_size = match cert_format {
        CertificateFormat::X509 => {
            let mut issuer_name = [0u8; MAX_ISSUER_NAME_SIZE];
            let issuer_len = env.platform.get_issuer_name(&mut issuer_name)?;
            if issuer_len > MAX_ISSUER_NAME_SIZE {
                return Err(DpeErrorCode::InternalError);
            }
            let cert_validity = env.platform.get_cert_validity()?;

            let mut cert_writer = CertWriter::new(
                output_cert_or_csr,
                dpe.profile,
                args.dice_extensions_are_critical,
            );
            let bytes_written = cert_writer.encode_certificate(
                &mut sign_cb,
                &subject_name.serial.bytes()[..20], // Serial number must be truncated to 20 bytes
                &issuer_name[..issuer_len],
                &subject_name,
                &pub_key,
                &measurements,
                &cert_validity,
            )?;
            u32::try_from(bytes_written).map_err(|_| DpeErrorCode::InternalError)?
        }
        #[cfg(not(feature = "disable_csr"))]
        CertificateFormat::Csr => {
            let sid = env.platform.get_signer_identifier()?;
            let mut cms_writer = CertWriter::new(
                output_cert_or_csr,
                dpe.profile,
                args.dice_extensions_are_critical,
            );
            let bytes_written = cms_writer.encode_cms(
                &mut sign_cb,
                &pub_key,
                &subject_name,
                &measurements,
                &sid,
            )?;
            u32::try_from(bytes_written).map_err(|_| DpeErrorCode::InternalError)?
        }
    };

    let exported_cdi_handle = match cert_type {
        // If the `CertificateType::Exported` is set then we should have a valid exported_cdi_handle at this point.
        CertificateType::Exported => exported_cdi_handle.ok_or(DpeErrorCode::InternalError)?,
        _ => [0; MAX_EXPORTED_CDI_SIZE],
    };

    Ok(CreateDpeCertResult {
        cert_size,
        pub_key,
        exported_cdi_handle,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::dpe_instance::tests::DPE_PROFILE;
    use crate::tci::{TciMeasurement, TciNodeData};
    use crate::x509::{CertWriter, DirectoryString, MeasurementData, Name};
    use crate::DpeProfile;
    use crypto::ecdsa::{EcdsaAlgorithm, EcdsaSig};
    use crypto::ecdsa::{EcdsaPub, EcdsaPubKey};
    #[cfg(feature = "ml-dsa")]
    use crypto::ml_dsa::MldsaPublicKey;
    #[cfg(feature = "ml-dsa")]
    use crypto::ml_dsa::{MldsaAlgorithm, MldsaSignature};
    use crypto::{PubKey, Signature, SignatureAlgorithm};
    use openssl::hash::{Hasher, MessageDigest};
    use platform::{ArrayVec, CertValidity, OtherName, SubjectAltName, MAX_KEY_IDENTIFIER_SIZE};
    use std::str;
    use x509_parser::certificate::X509CertificateParser;
    use x509_parser::nom::Parser;
    use x509_parser::oid_registry::asn1_rs::oid;
    use x509_parser::prelude::*;
    use zerocopy::IntoBytes;

    #[derive(asn1::Asn1Read)]
    pub struct Fwid<'a> {
        pub(crate) _hash_alg: asn1::ObjectIdentifier,
        pub(crate) digest: &'a [u8],
    }

    #[derive(asn1::Asn1Read)]
    pub struct IntegrityRegister<'a> {
        #[implicit(0)]
        _register_name: Option<asn1::IA5String<'a>>,
        #[implicit(1)]
        _register_num: Option<u64>,
        #[implicit(2)]
        pub register_digests: Option<asn1::SequenceOf<'a, Fwid<'a>>>,
    }

    #[derive(asn1::Asn1Read)]
    pub struct TcbInfo<'a> {
        #[implicit(0)]
        _vendor: Option<asn1::Utf8String<'a>>,
        #[implicit(1)]
        _model: Option<asn1::Utf8String<'a>>,
        #[implicit(2)]
        _version: Option<asn1::Utf8String<'a>>,
        #[implicit(3)]
        svn: Option<u64>,
        #[implicit(4)]
        _layer: Option<u64>,
        #[implicit(5)]
        _index: Option<u64>,
        #[implicit(6)]
        pub fwids: Option<asn1::SequenceOf<'a, Fwid<'a>>>,
        #[implicit(7)]
        _flags: Option<asn1::BitString<'a>>,
        #[implicit(8)]
        pub vendor_info: Option<&'a [u8]>,
        #[implicit(9)]
        pub tci_type: Option<&'a [u8]>,
        #[implicit(10)]
        pub integrity_registers: Option<asn1::SequenceOf<'a, IntegrityRegister<'a>>>,
    }

    #[derive(asn1::Asn1Read)]
    struct Ueid<'a> {
        pub(crate) ueid: &'a [u8],
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
            let mut w = CertWriter::new(&mut cert, DPE_PROFILE, true);
            let byte_count = w.encode_integer_bytes(&c, true).unwrap();
            let n = asn1::parse_single::<u64>(&cert[..byte_count]).unwrap();
            assert_eq!(n, u64::from_be_bytes(c));
            assert_eq!(
                CertWriter::get_integer_bytes_size(&c, true).unwrap(),
                byte_count
            );
        }

        let integer_cases = [0xFFFFFFFF00000000, 0x0102030405060708, 0x2];

        for c in integer_cases {
            let mut cert = [0; 128];
            let mut w = CertWriter::new(&mut cert, DPE_PROFILE, true);
            let byte_count = w.encode_integer(c, true).unwrap();
            let n = asn1::parse_single::<u64>(&cert[..byte_count]).unwrap();
            assert_eq!(n, c);
            assert_eq!(CertWriter::get_integer_size(c, true).unwrap(), byte_count);
        }
    }

    #[test]
    fn test_rdn() {
        let mut cert = [0u8; 256];
        let test_name = Name {
            cn: DirectoryString::PrintableString(b"Caliptra Alias"),
            serial: DirectoryString::PrintableString(&[0x0u8; DPE_PROFILE.hash_size() * 2]),
        };

        let mut w = CertWriter::new(&mut cert, DPE_PROFILE, true);
        let bytes_written = w.encode_rdn(&test_name).unwrap();

        let name = match X509Name::from_der(&cert[..bytes_written]) {
            Ok((_, name)) => name,
            Err(e) => panic!("Name parsing failed: {:?}", e),
        };

        let expected = format!(
            "CN={}, serialNumber={}",
            str::from_utf8(test_name.cn.bytes()).unwrap(),
            str::from_utf8(test_name.serial.bytes()).unwrap()
        );
        let actual = name.to_string_with_registry(oid_registry()).unwrap();
        assert_eq!(expected, actual);

        assert_eq!(
            CertWriter::get_rdn_size(&test_name, true).unwrap(),
            bytes_written
        );
    }

    #[cfg(not(feature = "ml-dsa"))]
    #[test]
    fn test_subject_pubkey() {
        let mut cert = [0u8; 384];
        let test_key = EcdsaPubKey::Ecdsa384(EcdsaPub::default());

        let mut w = CertWriter::new(&mut cert, DPE_PROFILE, true);
        let bytes_written = w.encode_ecdsa_subject_pubkey_info(&test_key).unwrap();

        SubjectPublicKeyInfo::from_der(&cert[..bytes_written]).unwrap();

        assert_eq!(
            CertWriter::new(&mut [], DPE_PROFILE, true)
                .get_ecdsa_subject_pubkey_info_size(&test_key, true)
                .unwrap(),
            bytes_written
        );
    }

    #[cfg(feature = "ml-dsa")]
    #[test]
    fn test_subject_pubkey() {
        let mut cert = [0u8; 4096];
        let test_key = MldsaPublicKey([0; MldsaAlgorithm::ExternalMu87.public_key_size()]);

        let mut w = CertWriter::new(&mut cert, DPE_PROFILE, true);
        let bytes_written = w.encode_mldsa_subject_pubkey_info(&test_key).unwrap();

        SubjectPublicKeyInfo::from_der(&cert[..bytes_written]).unwrap();

        assert_eq!(
            CertWriter::new(&mut [], DPE_PROFILE, true)
                .get_mldsa_subject_pubkey_info_size(&test_key, true)
                .unwrap(),
            bytes_written
        );
    }

    #[test]
    fn test_tcb_info() {
        let mut node = TciNodeData::new();

        node.tci_type = 0x11223344;
        node.tci_cumulative = TciMeasurement([0xaau8; DPE_PROFILE.hash_size()]);
        node.tci_current = TciMeasurement([0xbbu8; DPE_PROFILE.hash_size()]);
        node.locality = 0xFFFFFFFF;
        node.svn = 0xFFFFFFFF;

        let mut cert = [0u8; 256];
        let mut w = CertWriter::new(&mut cert, DPE_PROFILE, true);
        let mut supports_recursive = true;
        let mut bytes_written = w.encode_tcb_info(&node, supports_recursive).unwrap();

        let checker = CertWriter::new(&mut [], DPE_PROFILE, true);
        let mut parsed_tcb_info = asn1::parse_single::<TcbInfo>(&cert[..bytes_written]).unwrap();

        assert_eq!(
            bytes_written,
            checker
                .get_tcb_info_size(&node, supports_recursive, true)
                .unwrap()
        );

        // FWIDs
        let mut fwid_itr = parsed_tcb_info.fwids.unwrap();
        let expected_current = fwid_itr.next().unwrap().digest;
        assert_eq!(expected_current, node.tci_current.0);

        assert_eq!(parsed_tcb_info.tci_type.unwrap(), node.tci_type.as_bytes());
        assert_eq!(
            parsed_tcb_info.vendor_info.unwrap(),
            node.locality.to_be_bytes()
        );
        assert_eq!(parsed_tcb_info.svn.unwrap(), node.svn.into());

        // Integrity registers
        let mut ir_itr = parsed_tcb_info.integrity_registers.unwrap();
        let mut fwid_itr = ir_itr.next().unwrap().register_digests.unwrap();
        let expected_cumulative = fwid_itr.next().unwrap().digest;
        assert_eq!(expected_cumulative, node.tci_cumulative.0);

        // test tbs_info with supports_recursive = false
        supports_recursive = false;
        w = CertWriter::new(&mut cert, DPE_PROFILE, true);
        bytes_written = w.encode_tcb_info(&node, supports_recursive).unwrap();

        parsed_tcb_info = asn1::parse_single::<TcbInfo>(&cert[..bytes_written]).unwrap();

        assert_eq!(
            bytes_written,
            checker
                .get_tcb_info_size(&node, supports_recursive, true)
                .unwrap()
        );

        // Check that only FWID[0] is present
        let mut fwid_itr = parsed_tcb_info.fwids.unwrap();
        let expected_current = fwid_itr.next().unwrap().digest;
        assert!(fwid_itr.next().is_none());
        assert_eq!(expected_current, node.tci_current.0);
    }

    fn get_key_usage(is_ca: bool) -> KeyUsage {
        let mut cert = [0u8; 32];
        let mut w = CertWriter::new(&mut cert, DPE_PROFILE, true);
        let bytes_written = w.encode_key_usage(is_ca).unwrap();
        assert_eq!(
            bytes_written,
            CertWriter::get_key_usage_size(/*tagged=*/ true).unwrap()
        );

        let mut parser = X509ExtensionParser::new().with_deep_parse_extensions(false);
        let ext = parser.parse(&cert[..bytes_written]).unwrap().1;
        KeyUsage::from_der(ext.value).unwrap().1
    }

    #[test]
    fn test_key_usage() {
        // Make sure leaf keyUsage is only digitalSignature
        let leaf_key_usage = get_key_usage(/*is_ca=*/ false);
        let expected = 1u16;
        assert!(leaf_key_usage.flags | expected == expected);

        // Make sure leaf keyUsage is digitalSignature | keyCertSign
        let ca_key_usage = get_key_usage(/*is_ca=*/ true);
        let expected = (1u16 << 5) | 1u16;
        assert!(ca_key_usage.flags | expected == expected);
    }

    const TEST_SERIAL: &[u8] = &[0x1F; 20];
    const TEST_ISSUER_NAME: Name = Name {
        cn: DirectoryString::PrintableString(b"Caliptra Alias"),
        serial: DirectoryString::PrintableString(&[0x00; DPE_PROFILE.hash_size() * 2]),
    };
    const TEST_SUBJECT_NAME: Name = Name {
        cn: DirectoryString::PrintableString(b"DPE Leaf"),
        serial: DirectoryString::PrintableString(&[0x00; DPE_PROFILE.hash_size() * 2]),
    };

    const ECC_INT_SIZE: usize = DPE_PROFILE.ecc_int_size();

    const DEFAULT_OTHER_NAME_OID: &[u8] = &[0, 0, 0];
    const DEFAULT_OTHER_NAME_VALUE: &str = "default-other-name";

    fn build_test_cert_ecdsa(is_ca: bool, cert_buf: &mut [u8]) -> (usize, X509Certificate<'_>) {
        let mut issuer_der = [0u8; 1024];
        let mut issuer_writer = CertWriter::new(&mut issuer_der, DPE_PROFILE, true);
        let issuer_len = issuer_writer.encode_rdn(&TEST_ISSUER_NAME).unwrap();

        let test_pub = EcdsaPub::from_slice(&[0xAA; ECC_INT_SIZE], &[0xBB; ECC_INT_SIZE]);

        let node = TciNodeData::new();

        let mut hasher = match DPE_PROFILE {
            DpeProfile::P256Sha256 => Hasher::new(MessageDigest::sha256()).unwrap(),
            DpeProfile::P384Sha384 => Hasher::new(MessageDigest::sha384()).unwrap(),
            #[cfg(feature = "ml-dsa")]
            DpeProfile::Mldsa87ExternalMu => {
                unreachable!("tried to build ecdsa test cert for ml-dsa profile!")
            }
        };
        let (x, y) = test_pub.as_slice();
        hasher.update(&[0x04]).unwrap();
        hasher.update(x).unwrap();
        hasher.update(y).unwrap();
        let mut subject_key_identifier = [0u8; MAX_KEY_IDENTIFIER_SIZE];
        let digest = &hasher.finish().unwrap();
        subject_key_identifier.copy_from_slice(&digest[..MAX_KEY_IDENTIFIER_SIZE]);
        let mut other_name = ArrayVec::new();
        other_name
            .try_extend_from_slice(DEFAULT_OTHER_NAME_VALUE.as_bytes())
            .unwrap();
        let subject_alt_name = SubjectAltName::OtherName(OtherName {
            oid: DEFAULT_OTHER_NAME_OID,
            other_name,
        });
        let measurements = MeasurementData {
            label: &[0; DPE_PROFILE.hash_size()],
            tci_nodes: &[node],
            is_ca,
            supports_recursive: true,
            subject_key_identifier,
            authority_key_identifier: subject_key_identifier,
            subject_alt_name: Some(subject_alt_name),
        };

        let mut not_before = ArrayVec::new();
        not_before
            .try_extend_from_slice("20230227000000Z".as_bytes())
            .unwrap();
        let mut not_after = ArrayVec::new();
        not_after
            .try_extend_from_slice("99991231235959Z".as_bytes())
            .unwrap();
        let validity = CertValidity {
            not_before,
            not_after,
        };

        let pub_key = match DPE_PROFILE.alg() {
            #[cfg(feature = "p256")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
                PubKey::Ecdsa(EcdsaPubKey::Ecdsa256(test_pub))
            }
            #[cfg(feature = "p384")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
                PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(test_pub))
            }
            _ => panic!("Missing signature"),
        };

        let test_sig: Signature = match DPE_PROFILE.alg() {
            #[cfg(feature = "p256")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => Signature::Ecdsa(
                EcdsaSig::from_slice(&[0xCC; ECC_INT_SIZE], &[0xDD; ECC_INT_SIZE]).into(),
            ),
            #[cfg(feature = "p384")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => Signature::Ecdsa(
                EcdsaSig::from_slice(&[0xCC; ECC_INT_SIZE], &[0xDD; ECC_INT_SIZE]).into(),
            ),
            _ => panic!("Missing signature"),
        };

        let mut sign_cb = |_data: &[u8], _use_derived: bool| Ok(test_sig.clone());

        let mut w = CertWriter::new(cert_buf, DPE_PROFILE, true);
        let bytes_written = w
            .encode_certificate(
                &mut sign_cb,
                TEST_SERIAL,
                &issuer_der[..issuer_len],
                &TEST_SUBJECT_NAME,
                &pub_key,
                &measurements,
                &validity,
            )
            .unwrap();

        let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
        let cert = match parser.parse(&cert_buf[..bytes_written]) {
            Ok((_, parsed_cert)) => {
                assert_eq!(parsed_cert.version(), X509Version::V3);
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

        (bytes_written, cert)
    }

    #[cfg(feature = "ml-dsa")]
    fn build_test_cert_mldsa(is_ca: bool, cert_buf: &mut [u8]) -> (usize, X509Certificate<'_>) {
        let mut issuer_der = [0u8; 1024];
        let mut issuer_writer = CertWriter::new(&mut issuer_der, DPE_PROFILE, true);
        let issuer_len = issuer_writer.encode_rdn(&TEST_ISSUER_NAME).unwrap();

        const ALGORITHM: MldsaAlgorithm = match DPE_PROFILE.alg() {
            SignatureAlgorithm::MlDsa(mldsa_algorithm) => mldsa_algorithm,
            _ => panic!("tried to build ml-dsa test cert for non ml-dsa profile!"),
        };

        let test_pub = MldsaPublicKey::from_slice(&[0xAA; ALGORITHM.public_key_size()]);

        let node = TciNodeData::new();

        let mut hasher = match DPE_PROFILE {
            DpeProfile::Mldsa87ExternalMu => Hasher::new(MessageDigest::sha384()).unwrap(),
            _ => unreachable!("tried to build ml-dsa test cert for non ml-dsa profile!"),
        };
        hasher.update(test_pub.as_slice()).unwrap();
        let mut subject_key_identifier = [0u8; MAX_KEY_IDENTIFIER_SIZE];
        let digest = &hasher.finish().unwrap();
        subject_key_identifier.copy_from_slice(&digest[..MAX_KEY_IDENTIFIER_SIZE]);
        let mut other_name = ArrayVec::new();
        other_name
            .try_extend_from_slice(DEFAULT_OTHER_NAME_VALUE.as_bytes())
            .unwrap();
        let subject_alt_name = SubjectAltName::OtherName(OtherName {
            oid: DEFAULT_OTHER_NAME_OID,
            other_name,
        });
        let measurements = MeasurementData {
            label: &[0; DPE_PROFILE.hash_size()],
            tci_nodes: &[node],
            is_ca,
            supports_recursive: true,
            subject_key_identifier,
            authority_key_identifier: subject_key_identifier,
            subject_alt_name: Some(subject_alt_name),
        };

        let mut not_before = ArrayVec::new();
        not_before
            .try_extend_from_slice("20230227000000Z".as_bytes())
            .unwrap();
        let mut not_after = ArrayVec::new();
        not_after
            .try_extend_from_slice("99991231235959Z".as_bytes())
            .unwrap();
        let validity = CertValidity {
            not_before,
            not_after,
        };

        let pub_key = match DPE_PROFILE.alg() {
            #[cfg(feature = "dpe_profile_p256_sha256")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
                PubKey::Ecdsa(EcdsaPubKey::Ecdsa256(test_pub))
            }
            #[cfg(feature = "dpe_profile_p384_sha384")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
                PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(test_pub))
            }
            #[cfg(feature = "ml-dsa")]
            SignatureAlgorithm::MlDsa(MldsaAlgorithm::ExternalMu87) => PubKey::MlDsa(test_pub),
            _ => panic!("Missing signature"),
        };

        let test_sig: Signature = match DPE_PROFILE.alg() {
            #[cfg(feature = "dpe_profile_p256_sha256")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => Signature::Ecdsa(
                EcdsaSig::from_slice(&[0xCC; ECC_INT_SIZE], &[0xDD; ECC_INT_SIZE]).into(),
            ),
            #[cfg(feature = "dpe_profile_p384_sha384")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => Signature::Ecdsa(
                EcdsaSig::from_slice(&[0xCC; ECC_INT_SIZE], &[0xDD; ECC_INT_SIZE]).into(),
            ),
            #[cfg(feature = "ml-dsa")]
            SignatureAlgorithm::MlDsa(MldsaAlgorithm::ExternalMu87) => {
                Signature::MlDsa(MldsaSignature([0xBB; ALGORITHM.signature_size()]))
            }
            _ => panic!("Missing signature"),
        };

        let mut sign_cb = |_data: &[u8], _use_derived: bool| Ok(test_sig.clone());

        let mut w = CertWriter::new(cert_buf, DPE_PROFILE, true);
        let bytes_written = w
            .encode_certificate(
                &mut sign_cb,
                TEST_SERIAL,
                &issuer_der[..issuer_len],
                &TEST_SUBJECT_NAME,
                &pub_key,
                &measurements,
                &validity,
            )
            .unwrap();

        let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
        let cert = match parser.parse(&cert_buf[..bytes_written]) {
            Ok((_, parsed_cert)) => {
                assert_eq!(parsed_cert.version(), X509Version::V3);
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

        (bytes_written, cert)
    }

    #[test]
    fn test_full_leaf() {
        #[cfg(feature = "dpe_profile_p256_sha256")]
        let mut cert_buf = [0u8; 1024];
        #[cfg(feature = "dpe_profile_p256_sha256")]
        let (_, cert) = build_test_cert_ecdsa(false, &mut cert_buf);
        #[cfg(feature = "ml-dsa")]
        let mut cert_buf = [0u8; 8192];
        #[cfg(feature = "ml-dsa")]
        let (_, cert) = build_test_cert_mldsa(false, &mut cert_buf);

        match cert.basic_constraints() {
            Ok(Some(basic_constraints)) => {
                assert!(basic_constraints.critical);
                assert!(!basic_constraints.value.ca);
            }
            Ok(None) => panic!("basic constraints extension not found"),
            Err(_) => panic!("multiple basic constraints extensions found"),
        }

        match cert.key_usage() {
            Ok(Some(key_usage)) => {
                assert!(key_usage.critical);
                assert!(key_usage.value.digital_signature());
                assert!(!key_usage.value.key_cert_sign());
            }
            Ok(None) => panic!("key usage extension not found"),
            Err(_) => panic!("multiple key usage extensions found"),
        }

        match cert.extended_key_usage() {
            Ok(Some(ext_key_usage)) => {
                assert!(ext_key_usage.critical);
                // Expect tcg-dice-kp-eca OID (2.23.133.5.4.100.9)
                assert_eq!(ext_key_usage.value.other, [oid!(2.23.133 .5 .4 .100 .9)]);
            }
            Ok(None) => panic!("extended key usage extension not found"),
            Err(_) => panic!("multiple extended key usage extensions found"),
        };

        match cert.get_extension_unique(&oid!(2.5.29 .14)) {
            Ok(Some(_)) => panic!("subject key identifier extensions found for non CA certificate"),
            Err(_) => panic!("multiple subject key identifier extensions found"),
            _ => (),
        }

        if let Err(_) = cert.get_extension_unique(&oid!(2.5.29 .35)) {
            panic!("multiple authority key identifier extensions found")
        }

        match cert.subject_alternative_name() {
            Ok(Some(ext)) => {
                assert!(!ext.critical);
                let san = ext.value;
                assert_eq!(san.general_names.len(), 1);
                let general_name = san.general_names.first().unwrap();
                match general_name {
                    GeneralName::OtherName(oid, other_name_value) => {
                        assert_eq!(oid.as_bytes(), DEFAULT_OTHER_NAME_OID);
                        // skip first 4 der encoding bytes
                        assert_eq!(&other_name_value[4..], DEFAULT_OTHER_NAME_VALUE.as_bytes());
                    }
                    _ => panic!("Wrong SubjectAlternativeName"),
                };
            }
            Ok(None) => panic!("No SubjectAltName extension found!"),
            Err(e) => panic!("Error {} parsing SubjectAltName extension", e),
        }
    }

    #[test]
    fn test_full_ca() {
        #[cfg(feature = "dpe_profile_p256_sha256")]
        let mut cert_buf = [0u8; 1024];
        #[cfg(feature = "dpe_profile_p256_sha256")]
        let (_, cert) = build_test_cert_ecdsa(true, &mut cert_buf);
        #[cfg(feature = "ml-dsa")]
        let mut cert_buf = [0u8; 8192];
        #[cfg(feature = "ml-dsa")]
        let (_, cert) = build_test_cert_mldsa(true, &mut cert_buf);

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
                assert!(key_usage.value.key_cert_sign());
            }
            Ok(None) => panic!("key usage extension not found"),
            Err(_) => panic!("multiple key usage extensions found"),
        }

        match cert.extended_key_usage() {
            Ok(Some(ext_key_usage)) => {
                assert!(ext_key_usage.critical);
                // Expect tcg-dice-kp-eca OID (2.23.133.5.4.100.12)
                assert_eq!(ext_key_usage.value.other, [oid!(2.23.133 .5 .4 .100 .12)]);
            }
            Ok(None) => panic!("extended key usage extension not found"),
            Err(_) => panic!("multiple extended key usage extensions found"),
        };

        let pub_key = &cert.tbs_certificate.subject_pki.subject_public_key.data;
        let mut hasher = match DPE_PROFILE {
            DpeProfile::P256Sha256 => Hasher::new(MessageDigest::sha256()).unwrap(),
            DpeProfile::P384Sha384 => Hasher::new(MessageDigest::sha384()).unwrap(),
            #[cfg(feature = "ml-dsa")]
            DpeProfile::Mldsa87ExternalMu => Hasher::new(MessageDigest::sha384()).unwrap(),
        };
        hasher.update(pub_key).unwrap();
        let expected_key_identifier: &[u8] = &hasher.finish().unwrap();

        match cert.get_extension_unique(&oid!(2.5.29 .14)) {
            Ok(Some(subject_key_identifier_ext)) => {
                assert!(!subject_key_identifier_ext.critical);
                if let ParsedExtension::SubjectKeyIdentifier(key_identifier) =
                    subject_key_identifier_ext.parsed_extension()
                {
                    assert_eq!(
                        key_identifier.0,
                        &expected_key_identifier[..MAX_KEY_IDENTIFIER_SIZE]
                    );
                } else {
                    panic!("Extension has wrong type");
                }
            }
            Ok(None) => panic!("subject key identifier extension not found"),
            Err(_) => panic!("multiple subject key identifier extensions found"),
        }

        match cert.get_extension_unique(&oid!(2.5.29 .35)) {
            Ok(Some(extension)) => {
                assert!(!extension.critical);
                if let ParsedExtension::AuthorityKeyIdentifier(aki) = extension.parsed_extension() {
                    let key_identifier = aki.key_identifier.clone().unwrap();
                    // cert is self signed so authority_key_id == subject_key_id
                    assert_eq!(
                        key_identifier.0,
                        &expected_key_identifier[..MAX_KEY_IDENTIFIER_SIZE]
                    );
                    assert!(aki.authority_cert_issuer.is_none());
                    assert!(aki.authority_cert_serial.is_none());
                } else {
                    panic!("Extension has wrong type");
                }
            }
            Ok(None) => panic!("authority key identifier extension not found"),
            Err(_) => panic!("multiple authority key identifier extensions found"),
        }
    }
}
