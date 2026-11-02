// Licensed under the Apache-2.0 license

//! Lightweight X.509 encoding routines for DPE
//!
//! DPE requires encoding variable-length certificates. This module provides
//! this functionality for a no_std environment.

use crate::{
    context::{Context, ContextHandle, RootToChildIter},
    dpe_instance::DpeEnv,
    error::{DpeErrorCode, InternalErrorCode},
    tci::{TciMeasurement, TciNodeData},
    DpeInstance, DpeProfile,
};
use bitflags::bitflags;
#[cfg(feature = "cfi")]
use caliptra_cfi_lib::{cfi_assert, cfi_assert_bool, cfi_launder};
#[cfg(feature = "p256")]
use caliptra_dpe_crypto::ecdsa::curve_256::{self, EcdsaPub256};
#[cfg(feature = "p384")]
use caliptra_dpe_crypto::ecdsa::curve_384::{self, EcdsaPub384};
#[cfg(any(feature = "p256", feature = "p384"))]
use caliptra_dpe_crypto::ecdsa::EcdsaPubKey;
use caliptra_dpe_crypto::{
    ecdsa::EcdsaSignature, CryptoError, CryptoSuite, PubKey, SignData, Signature,
    MAX_EXPORTED_CDI_SIZE,
};
#[cfg(not(feature = "disable_x509"))]
use caliptra_dpe_platform::CertValidity;
#[cfg(not(feature = "disable_csr"))]
use caliptra_dpe_platform::SignerIdentifier;
use caliptra_dpe_platform::{
    OtherName, PlatformError, SubjectAltName, MAX_ISSUER_NAME_SIZE, MAX_KEY_IDENTIFIER_SIZE,
};
use caliptra_dpe_response_buffer::ResponseBuffer;
use zerocopy::IntoBytes;
use zeroize::Zeroize;

#[cfg(feature = "ml-dsa")]
use caliptra_dpe_crypto::ml_dsa::{MldsaAlgorithm, MldsaPublicKey};

/// Signing callback passed to cert and CSR encoding functions.
///
/// Arguments: `(buf, range, use_derived)` where `range` is the byte span of
/// the payload to sign within `buf`, and `use_derived` selects the derived key
/// (`true`) or the alias key (`false`).  The `Signature` is the out buffer
/// where the signature is placed.  The caller is responsible for ensuring it
/// is cleared between any sequential calls.
pub trait SignCallback:
    FnMut(&dyn ResponseBuffer, core::ops::Range<usize>, bool, &mut Signature) -> Result<(), CryptoError>
{
}

impl<F> SignCallback for F where
    F: FnMut(
        &dyn ResponseBuffer,
        core::ops::Range<usize>,
        bool,
        &mut Signature,
    ) -> Result<(), CryptoError>
{
}

/// This is the maximum size of a digest. The only profiles supported use SHA256 and SHA384.
/// This is the size of a SHA384 digest.
const MAX_HASH_SIZE: usize = 48;

mod profile_oids {
    #[cfg(feature = "p256")]
    pub const ECDSA_WITH_SHA256_OID: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
    #[cfg(feature = "p256")]
    pub const CURVE_P256_OID: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    #[cfg(feature = "p256")]
    pub const HASH_SHA256_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

    #[cfg(feature = "p384")]
    pub const ECDSA_WITH_SHA384_OID: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
    #[cfg(feature = "p384")]
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

struct TciNodes<'a> {
    start_idx: usize,
    contexts: &'a [Context],
}

impl<'a> TciNodes<'a> {
    pub fn new(start_idx: usize, contexts: &'a [Context]) -> Result<Self, DpeErrorCode> {
        Ok(Self {
            start_idx,
            contexts,
        })
    }

    fn iter(&self) -> Result<RootToChildIter<'_>, DpeErrorCode> {
        RootToChildIter::new(self.start_idx, self.contexts)
    }
}

pub struct MeasurementData<'a> {
    tci_nodes: TciNodes<'a>,
    pub label: &'a [u8],
    pub is_ca: bool,
    pub supports_recursive: bool,
    pub subject_key_identifier: [u8; MAX_KEY_IDENTIFIER_SIZE],
    pub authority_key_identifier: [u8; MAX_KEY_IDENTIFIER_SIZE],
    pub subject_alt_name: Option<SubjectAltName>,
}

pub struct CertWriter<'a> {
    certificate: &'a mut dyn ResponseBuffer,
    profile: DpeProfile,
    offset: usize,
    crit_dice: bool,
}

/// Encapsulates low-level deferred-length TLV and X.509 extension framing so
/// that [`CertWriter::begin_tlv`], [`CertWriter::end_tlv`],
/// [`CertWriter::begin_extension`], and [`CertWriter::end_extension`] (along
/// with their linear [`TlvSpan`] and [`ExtensionSpan`] tokens) are private to
/// this module. The rest of the `x509` module can only invoke the high-level
/// closure wrappers ([`CertWriter::encode_constructed`],
/// [`CertWriter::encode_deferred_tlv`], and [`CertWriter::encode_extension`]).
mod tlv {
    use super::*;

    /// Linear token returned by [`CertWriter::begin_tlv`] and consumed by
    /// [`CertWriter::end_tlv`].
    #[must_use]
    struct TlvSpan(usize);

    /// Linear token returned by [`CertWriter::begin_extension`] and consumed by
    /// [`CertWriter::end_extension`].
    #[must_use]
    struct ExtensionSpan {
        seq: TlvSpan,
        oct: TlvSpan,
    }

    impl CertWriter<'_> {
        /// Write `tag` and reserve 1 byte for the DER length field, returning a
        /// [`TlvSpan`] token to be consumed by [`Self::end_tlv`].
        #[inline(never)]
        fn begin_tlv(&mut self, tag: u8) -> TlvSpan {
            self.encode_tag_field(tag);
            let size_offset = self.offset;
            self.offset += 1;
            TlvSpan(size_offset)
        }

        /// Finalize a TLV started by [`Self::begin_tlv`]: compute the content byte
        /// count from `self.offset`, shift the content forward if the DER length
        /// field requires more than 1 byte, and backfill the length field.
        ///
        /// Returns the total number of bytes in this TLV (tag + length + content).
        fn end_tlv(&mut self, TlvSpan(size_offset): TlvSpan) -> usize {
            let content_range = (size_offset + 1)..self.offset;
            let content_size = content_range.len();
            let size_width = Self::get_size_width(content_size);

            self.shift_bytes_right(content_range, size_width - 1);

            self.offset = size_offset;
            self.encode_size_field(content_size);
            self.offset += content_size;

            1 + size_width + content_size
        }

        /// Shift the already-written bytes in `range` forward by `shift` bytes.
        fn shift_bytes_right(&mut self, range: core::ops::Range<usize>, shift: usize) {
            if shift == 0 {
                return;
            }
            for i in range.rev() {
                let mut byte = 0u8;
                let _ = self.certificate.read_range(i..i + 1, &mut |data| {
                    if let Some(&b) = data.first() {
                        byte = b;
                    }
                    Ok(())
                });
                let _ = self.certificate.write_at(i + shift, &[byte]);
            }
        }

        #[inline(always)]
        pub(super) fn encode_constructed(
            &mut self,
            tag: u8,
            content: impl FnOnce(&mut Self),
        ) -> usize {
            let span = self.begin_tlv(tag);
            content(self);
            self.end_tlv(span)
        }

        #[inline(always)]
        pub(super) fn encode_deferred_tlv(
            &mut self,
            tag: u8,
            content: impl FnOnce(&mut Self) -> Result<(), DpeErrorCode>,
        ) -> Result<usize, DpeErrorCode> {
            let span = self.begin_tlv(tag);
            content(self)?;
            Ok(self.end_tlv(span))
        }

        fn begin_extension(&mut self, oid: &[u8], critical: bool) -> ExtensionSpan {
            let seq = self.begin_tlv(Self::SEQUENCE_TAG);
            self.encode_oid(oid);
            if critical {
                self.encode_tlv(Self::BOOL_TAG, &[0xFF]);
            }
            let oct = self.begin_tlv(Self::OCTET_STRING_TAG);
            ExtensionSpan { seq, oct }
        }

        fn end_extension(&mut self, ext: ExtensionSpan) -> usize {
            self.end_tlv(ext.oct);
            self.end_tlv(ext.seq)
        }

        #[inline(always)]
        pub(super) fn encode_extension(
            &mut self,
            oid: &[u8],
            critical: bool,
            content: impl FnOnce(&mut Self),
        ) -> usize {
            let ext = self.begin_extension(oid, critical);
            content(self);
            self.end_extension(ext)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::dpe_instance::tests::DPE_PROFILE;
        use caliptra_dpe_response_buffer::SliceResponseBuffer;

        #[test]
        fn test_shift_bytes_right() {
            let initial: [u8; 10] = [0xAA, 1, 2, 3, 4, 5, 0xBB, 0xCC, 0xDD, 0xEE];

            // shift == 0 is a no-op.
            let mut buf = initial;
            let mut sbuf = SliceResponseBuffer::new(&mut buf);
            let mut w = CertWriter::new(&mut sbuf, DPE_PROFILE, true);
            w.shift_bytes_right(1..6, 0);
            assert_eq!(buf, initial);

            // Empty range is a no-op even when shift > 0.
            let mut buf = initial;
            let mut sbuf = SliceResponseBuffer::new(&mut buf);
            let mut w = CertWriter::new(&mut sbuf, DPE_PROFILE, true);
            w.shift_bytes_right(3..3, 2);
            assert_eq!(buf, initial);

            // Overlapping shift by 1 (1..6 -> 2..7): verifies reverse iteration
            // does not clobber source bytes before they are read, and leaves
            // surrounding bytes (index 0, vacated index 1, and indices 7..) intact.
            let mut buf = initial;
            let mut sbuf = SliceResponseBuffer::new(&mut buf);
            let mut w = CertWriter::new(&mut sbuf, DPE_PROFILE, true);
            w.shift_bytes_right(1..6, 1);
            assert_eq!(buf, [0xAA, 1, 1, 2, 3, 4, 5, 0xCC, 0xDD, 0xEE]);

            // Overlapping shift by 2 (1..6 -> 3..8), matching the 3-byte DER
            // length backfill case (size_width - 1 == 2).
            let mut buf = initial;
            let mut sbuf = SliceResponseBuffer::new(&mut buf);
            let mut w = CertWriter::new(&mut sbuf, DPE_PROFILE, true);
            w.shift_bytes_right(1..6, 2);
            assert_eq!(buf, [0xAA, 1, 2, 1, 2, 3, 4, 5, 0xDD, 0xEE]);

            // Shift that reaches past the end of the buffer: in-bounds bytes
            // are shifted and out-of-bounds writes are ignored without panicking.
            let mut buf = initial;
            let mut sbuf = SliceResponseBuffer::new(&mut buf);
            let mut w = CertWriter::new(&mut sbuf, DPE_PROFILE, true);
            w.shift_bytes_right(6..10, 2);
            assert_eq!(buf, [0xAA, 1, 2, 3, 4, 5, 0xBB, 0xCC, 0xBB, 0xCC]);
        }
    }
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
    const UTC_TIME_TAG: u8 = 0x17;
    #[cfg(not(feature = "disable_x509"))]
    const GENERALIZE_TIME_TAG: u8 = 0x18;
    const SEQUENCE_TAG: u8 = 0x30;
    const SEQUENCE_OF_TAG: u8 = 0x30;
    const SET_OF_TAG: u8 = 0x31;

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

    /// registerNum and registerName are listed as optional fields, but the spec
    /// says one of those values must be set. Because there is only ever one
    /// integrity register per TCB info, the registerNum is hardcoded to 0.
    const INTEGRITY_REGISTER_NUM: u64 = 0;

    /// ASN.1 encoding with length stripped of the following OID.
    /// id-ml-dnsa-87 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2)
    ///     country(16) us(840) organization(1) gov(101) csor(3)
    ///     nistAlgorithm(4) sigAlgs(3) id-ml-dsa-87(19) }
    /// Source: https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates/
    #[cfg(feature = "ml-dsa")]
    const MLDSA_OID: &'static [u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13];

    #[cfg(any(feature = "p256", feature = "p384"))]
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
    pub fn new(
        cert: &mut dyn ResponseBuffer,
        profile: DpeProfile,
        crit_dice: bool,
    ) -> CertWriter<'_> {
        CertWriter {
            certificate: cert,
            profile,
            offset: 0,
            crit_dice,
        }
    }

    /// Calculate the number of bytes the ASN.1 size field will be
    fn get_size_width(size: usize) -> usize {
        // The ASN.1 field is 1 byte if less than 128, and for every size larger is 1 byte
        // for the sentinal value, and then the number of bytes required to represent the size.
        //
        // Since usize on target platforms is only 32 bits, the max representation is 5 bytes.
        match size {
            ..128 => 1,
            128..256 => 2,
            256..65536 => 3,
            65536..16777216 => 4,
            _ => 5,
        }
    }

    /// Calculate the number of content bytes the ASN.1 INTEGER will be
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

    fn sig_oid(&self) -> &'static [u8] {
        match self.profile {
            #[cfg(feature = "p256")]
            DpeProfile::P256Sha256 => profile_oids::ECDSA_WITH_SHA256_OID,
            #[cfg(feature = "p384")]
            DpeProfile::P384Sha384 => profile_oids::ECDSA_WITH_SHA384_OID,
            #[cfg(feature = "ml-dsa")]
            DpeProfile::Mldsa87 => Self::MLDSA_OID,
        }
    }

    fn hash_oid(&self) -> &'static [u8] {
        match self.profile {
            #[cfg(feature = "p256")]
            DpeProfile::P256Sha256 => profile_oids::HASH_SHA256_OID,
            #[cfg(feature = "p384")]
            DpeProfile::P384Sha384 => Self::HASH_SHA384_OID,
            #[cfg(feature = "ml-dsa")]
            DpeProfile::Mldsa87 => Self::HASH_SHA384_OID,
        }
    }

    /// RFC 5280 requires dates from 1950 through 2049 to use UTCTime. The
    /// platform supplies four-digit years, so omit the century when encoding
    /// dates in that range.
    #[cfg(not(feature = "disable_x509"))]
    fn x509_time(time: &[u8]) -> (u8, &[u8]) {
        if time.len() == 15 && time[14] == b'Z' {
            let year = &time[..4];
            if year >= &b"1950"[..] && year <= &b"2049"[..] {
                return (Self::UTC_TIME_TAG, &time[2..]);
            }
        }
        (Self::GENERALIZE_TIME_TAG, time)
    }

    /// Write all of `bytes` to the certificate buffer.
    #[inline(never)]
    fn encode_bytes(&mut self, bytes: &[u8]) -> usize {
        let size = bytes.len();
        // This could error if `write_at` prevents an overwrite and returns an error.  That is
        // detected by the offset surpassing the certificate length at the end of an encode run,
        // and thus the error reporting is elided here to save instruction space.
        let _ = self.certificate.write_at(self.offset, bytes);
        // Note: Increment the offset regardless of whether the write occurred to allow detection
        // of encoding overflows.
        self.offset += size;
        size
    }

    /// Write a single `byte` to the certificate buffer.
    fn encode_byte(&mut self, byte: u8) -> usize {
        self.encode_bytes(&[byte])
    }

    /// DER-encodes the tag field of an ASN.1 type
    fn encode_tag_field(&mut self, tag: u8) -> usize {
        self.encode_byte(tag)
    }

    /// DER-encodes the size field of an ASN.1 type
    fn encode_size_field(&mut self, size: usize) -> usize {
        let size_width = Self::get_size_width(size);
        if size_width == 1 {
            self.encode_byte(size as u8);
        } else {
            let rem = size_width - 1;
            self.encode_byte(0x80 | rem as u8);
            for i in (0..rem).rev() {
                self.encode_byte((size >> (i * 8)) as u8);
            }
        }
        size_width
    }

    /// The unchecked write primitives advance `offset` even when a write is
    /// skipped (buffer full), so once a structure is fully encoded an `offset`
    /// past the buffer end means the output was silently truncated. Public
    /// encoders call this before returning so a too-small buffer fails loudly.
    fn check_not_truncated(&self) -> Result<(), DpeErrorCode> {
        if self.offset > self.certificate.capacity() {
            return Err(InternalErrorCode::CertSizeOverflow.into());
        }

        Ok(())
    }

    /// DER-encodes a big-endian integer buffer as an ASN.1 INTEGER
    fn encode_integer_bytes(&mut self, integer: &[u8], tagged: bool) -> usize {
        let mut bytes_written = if tagged {
            self.encode_tag_field(Self::INTEGER_TAG)
        } else {
            0
        };

        let size = Self::get_integer_bytes_size(integer);
        bytes_written += self.encode_size_field(size);

        // Compute where to start reading from integer (strips leading zeros)
        let integer_offset = integer.len().saturating_sub(size);

        // If size got larger it is because a null byte needs to be prepended
        if size > integer.len() {
            bytes_written += self.encode_byte(0);
        }

        // integer_offset <= integer.len() by construction, so this never panics.
        bytes_written += self.encode_bytes(&integer[integer_offset..]);

        bytes_written
    }

    /// DER-encodes `integer` as an ASN.1 INTEGER
    fn encode_integer(&mut self, integer: u64, tagged: bool) -> usize {
        self.encode_integer_bytes(&integer.to_be_bytes(), tagged)
    }

    /// DER-encode a primitive TLV: a tag byte, a definite-length size field for
    /// `val.len()`, then `val` itself. This is the common shape of OID, OCTET
    /// STRING, UTF8String and IMPLICIT primitive fields.
    fn encode_tlv(&mut self, tag: u8, val: &[u8]) -> usize {
        let mut bytes_written = self.encode_tag_field(tag);
        bytes_written += self.encode_size_field(val.len());
        bytes_written += self.encode_bytes(val);

        bytes_written
    }

    /// DER-encodes `oid` as an ASN.1 ObjectIdentifier
    fn encode_oid(&mut self, oid: &[u8]) -> usize {
        self.encode_tlv(Self::OID_TAG, oid)
    }

    fn encode_bit_string_bytes(&mut self, unused_bits: u8, bytes: &[u8]) -> usize {
        let mut bytes_written = self.encode_tag_field(Self::BIT_STRING_TAG);
        bytes_written += self.encode_size_field(1 + bytes.len());
        bytes_written += self.encode_byte(unused_bits);
        bytes_written += self.encode_bytes(bytes);
        bytes_written
    }

    /// Encode a DirectoryString for an RDN. Multiple string types are allowed, so
    /// this function accepts a `tag`. This is important because some verifiers
    /// will do an exact DER comparison when building cert chains.
    fn encode_rdn_string(&mut self, s: &DirectoryString) -> usize {
        let (val, tag) = match s {
            DirectoryString::PrintableString(val) => (val, Self::PRINTABLE_STRING_TAG),
            DirectoryString::Utf8String(val) => (val, Self::UTF8_STRING_TAG),
        };
        self.encode_tlv(tag, val)
    }

    fn encode_rdn_attr(&mut self, oid: &[u8], val: &DirectoryString) -> usize {
        self.encode_constructed(Self::SET_OF_TAG, |w| {
            w.encode_constructed(Self::SEQUENCE_TAG, |w| {
                w.encode_oid(oid);
                w.encode_rdn_string(val);
            });
        })
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
        let bytes_written = self.encode_constructed(Self::SEQUENCE_OF_TAG, |w| {
            w.encode_rdn_attr(&Self::RDN_COMMON_NAME_OID, &name.cn);
            w.encode_rdn_attr(&Self::RDN_SERIALNUMBER_OID, &name.serial);
        });

        self.check_not_truncated()?;
        Ok(bytes_written)
    }

    fn encode_alg_id(&mut self, oid: &[u8]) -> usize {
        self.encode_constructed(Self::SEQUENCE_TAG, |w| {
            w.encode_oid(oid);
        })
    }

    // Encode ASN.1 Validity according to Platform
    #[cfg(not(feature = "disable_x509"))]
    fn encode_validity(&mut self, validity: &CertValidity) -> usize {
        let (not_before_tag, not_before) = Self::x509_time(validity.not_before.as_slice());
        let (not_after_tag, not_after) = Self::x509_time(validity.not_after.as_slice());
        self.encode_constructed(Self::SEQUENCE_TAG, |w| {
            w.encode_tlv(not_before_tag, not_before);
            w.encode_tlv(not_after_tag, not_after);
        })
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
    #[cfg(any(feature = "p256", feature = "p384"))]
    fn encode_ecdsa_subject_pubkey_info(
        &mut self,
        pub_key: &EcdsaPubKey,
        curve_oid: &'static [u8],
    ) -> usize {
        self.encode_constructed(Self::SEQUENCE_TAG, |w| {
            w.encode_constructed(Self::SEQUENCE_TAG, |w| {
                w.encode_oid(Self::EC_PUB_OID);
                w.encode_oid(curve_oid);
            });
            w.encode_constructed(Self::BIT_STRING_TAG, |w| {
                // First byte of BIT STRING is the number of unused bits. But all bits
                // are used.
                w.encode_byte(0);
                w.encode_byte(0x4);
                let (x, y) = pub_key.as_slice();
                w.encode_bytes(x);
                w.encode_bytes(y);
            });
        })
    }

    fn encode_ecdsa_sig_value(&mut self, sig: &EcdsaSignature) -> usize {
        let (r, s) = sig.as_slice();
        self.encode_constructed(Self::SEQUENCE_TAG, |w| {
            w.encode_integer_bytes(r, true);
            w.encode_integer_bytes(s, true);
        })
    }

    /// BIT STRING containing
    ///
    /// ECDSA-Sig-Value ::= SEQUENCE {
    ///     r  INTEGER,
    ///     s  INTEGER
    ///   }
    fn encode_ecdsa_signature_bit_string(&mut self, sig: &EcdsaSignature) -> usize {
        self.encode_constructed(Self::BIT_STRING_TAG, |w| {
            // Unused bits
            w.encode_byte(0);
            w.encode_ecdsa_sig_value(sig);
        })
    }

    /// Encode Signature into BIT STRING
    #[cfg(any(not(feature = "disable_x509"), not(feature = "disable_csr")))]
    fn encode_signature_bit_string(&mut self, sig: &Signature) -> usize {
        let alg_bytes = self.encode_alg_id(self.sig_oid());
        let sig_bytes = match sig {
            Signature::Ecdsa(sig) => self.encode_ecdsa_signature_bit_string(sig),
            #[cfg(feature = "ml-dsa")]
            Signature::Mldsa(sig) => self.encode_bit_string_bytes(0, &sig.0),
        };
        alg_bytes + sig_bytes
    }

    /// Encode Signature into OCTET STRING
    #[cfg(not(feature = "disable_csr"))]
    fn encode_signature_octet_string(&mut self, sig: &Signature) -> usize {
        let alg_bytes = self.encode_alg_id(self.sig_oid());
        let sig_bytes = match sig {
            Signature::Ecdsa(sig) => self.encode_constructed(Self::OCTET_STRING_TAG, |w| {
                w.encode_ecdsa_sig_value(sig);
            }),
            #[cfg(feature = "ml-dsa")]
            Signature::Mldsa(sig) => self.encode_tlv(Self::OCTET_STRING_TAG, sig.as_bytes()),
        };
        alg_bytes + sig_bytes
    }

    /// Encode SubjectPublicKeyInfo for an MLDSA-87 public key
    #[cfg(feature = "ml-dsa")]
    fn encode_mldsa_subject_pubkey_info(&mut self, pub_key: &MldsaPublicKey) -> usize {
        self.encode_constructed(Self::SEQUENCE_TAG, |w| {
            w.encode_alg_id(w.sig_oid());
            w.encode_bit_string_bytes(0, &pub_key.0);
        })
    }

    fn encode_version(&mut self) -> usize {
        // Version is EXPLICIT field number 0
        self.encode_constructed(Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED, |w| {
            w.encode_integer(Self::X509_V3, true);
        })
    }

    fn encode_fwid(&mut self, tci: &TciMeasurement) -> usize {
        self.encode_constructed(Self::SEQUENCE_TAG, |w| {
            // hashAlg OID
            let oid = w.hash_oid();
            w.encode_oid(oid);

            // digest OCTET STRING
            w.encode_tlv(Self::OCTET_STRING_TAG, &tci.0);
        })
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
    fn encode_tcb_info(&mut self, node: &TciNodeData, supports_recursive: bool) -> usize {
        self.encode_constructed(Self::SEQUENCE_TAG, |w| {
            // svn INTEGER
            // IMPLICIT [3] Primitive
            w.encode_byte(Self::CONTEXT_SPECIFIC | 0x03);
            w.encode_integer(node.svn.into(), false);

            // fwids SEQUENCE OF
            // IMPLICIT [6] Constructed
            w.encode_constructed(Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED | 0x06, |w| {
                // fwid[0] current measurement
                w.encode_fwid(&node.tci_current);
            });

            // vendorInfo OCTET STRING
            // IMPLICIT[8] Primitive
            let vinfo = &node.locality.to_be_bytes();
            w.encode_tlv(Self::CONTEXT_SPECIFIC | 0x08, vinfo);

            // type OCTET STRING
            // IMPLICIT[9] Primitive
            // Encode big-endian to match vendorInfo (locality) above and the
            // network/DER convention for multi-byte integer fields.
            let tci_type = &node.tci_type.to_be_bytes();
            w.encode_tlv(Self::CONTEXT_SPECIFIC | 0x09, tci_type);

            // Omit integrityRegisters from tcb_info if the profile does not support recursive
            if supports_recursive {
                // integrityRegisters SEQUENCE OF
                // IMPLICIT [11] Constructed
                w.encode_constructed(Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED | 11, |w| {
                    // integrityRegisters[0] SEQUENCE
                    w.encode_constructed(Self::SEQUENCE_TAG, |w| {
                        // IMPLICIT [1] Primitive
                        // registerNum INTEGER
                        w.encode_byte(Self::CONTEXT_SPECIFIC | 0x01);
                        w.encode_integer(Self::INTEGRITY_REGISTER_NUM, false);

                        // IMPLICIT [2] Constructed
                        // registerDigests SEQUENCE OF FWID
                        // cumulative measurement
                        w.encode_constructed(
                            Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED | 0x02,
                            |w| {
                                w.encode_fwid(&node.tci_cumulative);
                            },
                        );
                    });
                });
            }
        })
    }

    /// Encode a tcg-dice-MultiTcbInfo extension
    ///
    /// https://trustedcomputinggroup.org/wp-content/uploads/TCG_DICE_Attestation_Architecture_r22_02dec2020.pdf
    fn encode_multi_tcb_info(
        &mut self,
        measurements: &MeasurementData,
    ) -> Result<usize, DpeErrorCode> {
        let iter = measurements.tci_nodes.iter()?;
        Ok(
            self.encode_extension(Self::MULTI_TCBINFO_OID, self.crit_dice, |w| {
                w.encode_constructed(Self::SEQUENCE_OF_TAG, |w| {
                    for node in iter {
                        w.encode_tcb_info(&node.tci, measurements.supports_recursive);
                    }
                });
            }),
        )
    }

    /// Encode a tcg-dice-Ueid extension
    ///
    /// https://trustedcomputinggroup.org/wp-content/uploads/TCG_DICE_Attestation_Architecture_r22_02dec2020.pdf
    fn encode_ueid(&mut self, measurements: &MeasurementData) -> usize {
        self.encode_extension(Self::UEID_OID, self.crit_dice, |w| {
            w.encode_constructed(Self::SEQUENCE_TAG, |w| {
                w.encode_tlv(Self::OCTET_STRING_TAG, measurements.label);
            });
        })
    }

    /// Encode a BasicConstraints extension
    ///
    /// https://datatracker.ietf.org/doc/html/rfc5280
    fn encode_basic_constraints(&mut self, measurements: &MeasurementData) -> usize {
        self.encode_extension(Self::BASIC_CONSTRAINTS_OID, true, |w| {
            w.encode_constructed(Self::SEQUENCE_TAG, |w| {
                if measurements.is_ca {
                    w.encode_tlv(Self::BOOL_TAG, &[0xFF]);
                }
            });
        })
    }

    /// Encode a KeyUsage extension
    ///
    /// https://datatracker.ietf.org/doc/html/rfc5280
    fn encode_key_usage(&mut self, is_ca: bool) -> usize {
        // Count trailing bits in KeyUsage byte as unused
        let (key_usage, unused_bits) = if is_ca {
            (
                KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::KEY_CERT_SIGN,
                2,
            )
        } else {
            (KeyUsageFlags::DIGITAL_SIGNATURE, 7)
        };
        self.encode_extension(Self::KEY_USAGE_OID, true, |w| {
            w.encode_bit_string_bytes(unused_bits, &[key_usage.0]);
        })
    }

    /// Encode ExtendedKeyUsage extension
    ///
    /// The included EKU OIDs is as follows based on whether or not this certificate is for a CA:
    ///
    /// is_ca = true: id-tcg-kp-identityLoc (2.23.133.8.7)
    /// is_ca = false: id-tcg-kp-attestLoc (2.23.133.8.9)
    ///
    /// https://datatracker.ietf.org/doc/html/rfc5280
    fn encode_extended_key_usage(&mut self, measurements: &MeasurementData) -> usize {
        let policy_oid = if measurements.is_ca {
            Self::ECA_OID
        } else {
            Self::ATTEST_LOC_OID
        };
        self.encode_extension(Self::EXTENDED_KEY_USAGE_OID, true, |w| {
            w.encode_constructed(Self::SEQUENCE_TAG, |w| {
                w.encode_oid(policy_oid);
            });
        })
    }

    /// OtherName ::= SEQUENCE {
    ///    type-id    OBJECT IDENTIFIER,
    ///    value      [0] EXPLICIT ANY DEFINED BY type-id
    /// }
    #[allow(clippy::identity_op)]
    fn encode_other_name(&mut self, other_name: &OtherName) -> usize {
        // otherName is EXPLICIT field number 0
        self.encode_constructed(Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED | 0x0, |w| {
            w.encode_oid(other_name.oid);
            // value is EXPLICIT field number 0
            w.encode_constructed(Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED | 0x0, |w| {
                // value := UTF8STRING
                w.encode_tlv(Self::UTF8_STRING_TAG, other_name.other_name.as_slice());
            });
        })
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
    fn encode_subject_alt_name_extension(&mut self, measurements: &MeasurementData) -> usize {
        match &measurements.subject_alt_name {
            None => 0,
            Some(SubjectAltName::OtherName(other_name)) => {
                self.encode_extension(Self::SUBJECT_ALTERNATIVE_NAME_OID, false, |w| {
                    w.encode_constructed(Self::SEQUENCE_TAG, |w| {
                        w.encode_other_name(other_name);
                    });
                })
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
    ) -> usize {
        if !is_x509 {
            return 0;
        }
        self.encode_extension(Self::AUTHORITY_KEY_IDENTIFIER_OID, false, |w| {
            w.encode_constructed(Self::SEQUENCE_TAG, |w| {
                w.encode_key_identifier(&measurements.authority_key_identifier);
            });
        })
    }

    fn encode_subject_key_identifier_extension(
        &mut self,
        measurements: &MeasurementData,
        is_x509: bool,
    ) -> usize {
        if !measurements.is_ca || !is_x509 {
            return 0;
        }
        self.encode_extension(Self::SUBJECT_KEY_IDENTIFIER_OID, false, |w| {
            // SubjectKeyIdentifier := OCTET STRING
            w.encode_tlv(Self::OCTET_STRING_TAG, &measurements.subject_key_identifier);
        })
    }

    fn encode_extensions(
        &mut self,
        measurements: &MeasurementData,
        is_x509: bool,
    ) -> Result<usize, DpeErrorCode> {
        self.encode_deferred_tlv(Self::SEQUENCE_OF_TAG, |w| {
            w.encode_multi_tcb_info(measurements)?;
            w.encode_ueid(measurements);
            w.encode_basic_constraints(measurements);
            w.encode_key_usage(measurements.is_ca);
            w.encode_extended_key_usage(measurements);
            w.encode_subject_key_identifier_extension(measurements, is_x509);
            w.encode_authority_key_identifier_extension(measurements, is_x509);
            w.encode_subject_alt_name_extension(measurements);
            Ok(())
        })
    }

    /// Encodes an integer representing the CMS version which is dependent on the SignerIdentifier
    ///
    /// If the SignerIdentifier is IssuerAndSerialNumber the version is 1, otherwise it is 3.
    #[cfg(not(feature = "disable_csr"))]
    fn encode_cms_version(&mut self, sid: &SignerIdentifier) -> usize {
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
        self.encode_deferred_tlv(Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED | 0x0, |w| {
            // Attribute Sequence
            w.encode_deferred_tlv(Self::SEQUENCE_TAG, |w| {
                w.encode_oid(Self::EXTENSION_REQUEST_OID);
                // attrValues SET OF
                w.encode_deferred_tlv(Self::SET_OF_TAG, |w| {
                    w.encode_extensions(measurements, /*is_x509=*/ false)?;
                    Ok(())
                })?;
                Ok(())
            })?;
            Ok(())
        })
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
        let bytes_written = self.encode_constructed(Self::SEQUENCE_TAG, |w| {
            // CMS version
            w.encode_cms_version(sid);
            // SignerIdentifier
            w.encode_signer_identifier(sid);
            // digestAlgorithm
            w.encode_alg_id(w.hash_oid());
            w.encode_signature_octet_string(sig);
        });

        self.check_not_truncated()?;
        Ok(bytes_written)
    }

    /// Encode a SignerIdentifier
    ///
    /// SignerIdentifier ::= CHOICE {
    ///     issuerAndSerialNumber IssuerAndSerialNumber,
    ///     subjectKeyIdentifier [0] SubjectKeyIdentifier
    /// }
    #[cfg(not(feature = "disable_csr"))]
    fn encode_signer_identifier(&mut self, sid: &SignerIdentifier) -> usize {
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
    ) -> usize {
        self.encode_constructed(Self::SEQUENCE_TAG, |w| {
            // issuer
            w.encode_bytes(issuer_name);
            // serialNumber
            w.encode_integer_bytes(serial_number, true);
        })
    }

    /// Encode a SubjectKeyIdentifier
    ///
    /// SubjectKeyIdentifier ::= OCTET STRING
    #[allow(clippy::identity_op)]
    #[cfg(not(feature = "disable_csr"))]
    fn encode_subject_key_identifier(&mut self, subject_key_identifier: &[u8]) -> usize {
        // SubjectKeyIdentifier is IMPLICIT field number 0
        self.encode_constructed(Self::CONTEXT_SPECIFIC | 0x0, |w| {
            // SubjectKeyIdentifier OCTET STRING
            w.encode_tlv(Self::OCTET_STRING_TAG, subject_key_identifier);
        })
    }

    /// Encode a KeyIdentifier
    ///
    /// KeyIdentifier ::= OCTET STRING
    #[allow(clippy::identity_op)]
    fn encode_key_identifier(&mut self, key_identifier: &[u8]) -> usize {
        // KeyIdentifier is IMPLICIT field number 0
        self.encode_tlv(Self::CONTEXT_SPECIFIC | 0x0, key_identifier)
    }

    /// Encode an EncapsulatedContentInfo and sign the embedded CSR with the
    /// CMS signer key before finalizing the outer length headers.
    ///
    /// EncapsulatedContentInfo  ::=  SEQUENCE  {
    ///    eContentType ContentType,
    ///    eContent [0] EXPLICIT OCTET STRING OPTIONAL
    /// }
    #[cfg(not(feature = "disable_csr"))]
    #[allow(clippy::identity_op)]
    fn encode_encapsulated_content_info(
        &mut self,
        sign_cb: &mut dyn SignCallback,
        pub_key: &PubKey,
        subject_name: &Name,
        measurements: &MeasurementData,
        sig: &mut Signature,
    ) -> Result<usize, DpeErrorCode> {
        self.encode_deferred_tlv(Self::SEQUENCE_TAG, |w| {
            w.encode_oid(Self::ID_DATA_OID);

            // eContent is EXPLICIT field number 0
            w.encode_deferred_tlv(Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED | 0x0, |w| {
                // eContent OCTET STRING
                w.encode_deferred_tlv(Self::OCTET_STRING_TAG, |w| {
                    let csr_start = w.offset;
                    let csr_bytes_written =
                        w.encode_csr(sign_cb, pub_key, subject_name, measurements, sig)?;
                    sign_cb(
                        &*w.certificate,
                        csr_start..csr_start + csr_bytes_written,
                        false,
                        sig,
                    )?;
                    Ok(())
                })?;
                Ok(())
            })?;

            Ok(())
        })
    }

    fn encode_pub_key_info(&mut self, pub_key: &PubKey) -> Result<usize, DpeErrorCode> {
        #[allow(unreachable_patterns)]
        let size = match pub_key {
            #[cfg(feature = "p256")]
            PubKey::Ecdsa(pub_key @ EcdsaPubKey::Ecdsa256(_)) => {
                self.encode_ecdsa_subject_pubkey_info(pub_key, profile_oids::CURVE_P256_OID)
            }
            #[cfg(feature = "p384")]
            PubKey::Ecdsa(pub_key @ EcdsaPubKey::Ecdsa384(_)) => {
                self.encode_ecdsa_subject_pubkey_info(pub_key, profile_oids::CURVE_P384_OID)
            }
            #[cfg(feature = "ml-dsa")]
            PubKey::Mldsa(pub_key) => self.encode_mldsa_subject_pubkey_info(pub_key),
            _ => return Err(DpeErrorCode::Crypto(CryptoError::MismatchedAlgorithm)),
        };
        Ok(size)
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
        // TBSCertificate SEQUENCE; the length field is backfilled once the
        // content size is known.
        let bytes_written = self.encode_deferred_tlv(Self::SEQUENCE_TAG, |w| {
            // version
            w.encode_version();

            // serialNumber
            w.encode_integer_bytes(serial_number, true);

            // signature
            w.encode_alg_id(w.sig_oid());

            // issuer
            w.encode_bytes(issuer_name);

            // validity
            w.encode_validity(validity);

            // subject
            w.encode_rdn(subject_name)?;

            // subjectPublicKeyInfo
            w.encode_pub_key_info(pubkey)?;

            // extensions (EXPLICIT field number 3)
            w.encode_deferred_tlv(Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED | 0x03, |w| {
                w.encode_extensions(measurements, /*is_x509=*/ true)?;
                Ok(())
            })?;

            Ok(())
        })?;

        self.check_not_truncated()?;
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
        sign_cb: &mut dyn SignCallback,
        serial_number: &[u8],
        issuer_name: &[u8],
        subject_name: &Name,
        pubkey: &PubKey,
        measurements: &MeasurementData,
        validity: &CertValidity,
        sig: &mut Signature,
    ) -> Result<usize, DpeErrorCode> {
        let bytes_written = self.encode_signed_payload(
            sign_cb,
            SignedPayload::Tbs {
                serial_number,
                issuer_name,
                subject_name,
                pubkey,
                measurements,
                validity,
            },
            sig,
        )?;

        self.check_not_truncated()?;
        Ok(bytes_written)
    }

    /// Encode a signed ASN.1 structure: an outer SEQUENCE wrapping a payload
    /// followed by its signature BIT STRING. This is the common envelope for
    /// both an X.509 `Certificate` (TBSCertificate + signature) and a PKCS #10
    /// `CertificateRequest` (CertificationRequestInfo + signature).
    ///
    /// The payload is encoded, signed via `sign_cb`, and the signature
    /// appended; the outer SEQUENCE length is backfilled once both sizes are
    /// known.
    ///
    /// Returns number of bytes written.
    #[cfg(any(not(feature = "disable_x509"), not(feature = "disable_csr")))]
    fn encode_signed_payload(
        &mut self,
        sign_cb: &mut dyn SignCallback,
        payload: SignedPayload,
        sig: &mut Signature,
    ) -> Result<usize, DpeErrorCode> {
        self.encode_deferred_tlv(Self::SEQUENCE_TAG, |w| {
            let payload_start = w.offset;

            let (payload_bytes_written, is_csr) = match payload {
                #[cfg(not(feature = "disable_x509"))]
                SignedPayload::Tbs {
                    serial_number,
                    issuer_name,
                    subject_name,
                    pubkey,
                    measurements,
                    validity,
                } => (
                    w.encode_tbs(
                        serial_number,
                        issuer_name,
                        subject_name,
                        pubkey,
                        measurements,
                        validity,
                    )?,
                    false,
                ),
                #[cfg(not(feature = "disable_csr"))]
                SignedPayload::CertReqInfo {
                    pub_key,
                    subject_name,
                    measurements,
                } => (
                    w.encode_certification_request_info(pub_key, subject_name, measurements)?,
                    true,
                ),
            };

            sign_cb(
                &*w.certificate,
                payload_start..payload_start + payload_bytes_written,
                is_csr,
                sig,
            )?;

            w.encode_signature_bit_string(sig);
            sig.zeroize();

            Ok(())
        })
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
    fn encode_certification_request_info(
        &mut self,
        pub_key: &PubKey,
        subject_name: &Name,
        measurements: &MeasurementData,
    ) -> Result<usize, DpeErrorCode> {
        // CertificationRequestInfo SEQUENCE; the length field is backfilled
        // once the content size is known.
        let bytes_written = self.encode_deferred_tlv(Self::SEQUENCE_TAG, |w| {
            // version
            w.encode_integer(Self::CSR_V0, true);

            // subject
            w.encode_rdn(subject_name)?;

            // subjectPublicKeyInfo
            w.encode_pub_key_info(pub_key)?;

            // attributes
            w.encode_attributes(measurements)?;

            Ok(())
        })?;

        self.check_not_truncated()?;
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
        sign_cb: &mut dyn SignCallback,
        pub_key: &PubKey,
        subject_name: &Name,
        measurements: &MeasurementData,
        sig: &mut Signature,
    ) -> Result<usize, DpeErrorCode> {
        let bytes_written = self.encode_signed_payload(
            sign_cb,
            SignedPayload::CertReqInfo {
                pub_key,
                subject_name,
                measurements,
            },
            sig,
        )?;

        self.check_not_truncated()?;
        Ok(bytes_written)
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
        sign_cb: &mut dyn SignCallback,
        pub_key: &PubKey,
        subject_name: &Name,
        measurements: &MeasurementData,
        sid: &SignerIdentifier,
        sig: &mut Signature,
    ) -> Result<usize, DpeErrorCode> {
        // ContentInfo SEQUENCE. This and the two nested SignedData layers defer
        // their length fields; each layer's length is simply whatever the layer
        // below reports having written.
        let bytes_written = self.encode_deferred_tlv(Self::SEQUENCE_TAG, |w| {
            w.encode_oid(Self::ID_SIGNED_DATA_OID);

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
            w.encode_deferred_tlv(Self::CONTEXT_SPECIFIC | Self::CONSTRUCTED | 0x0, |w| {
                // SignedData sequence
                w.encode_deferred_tlv(Self::SEQUENCE_TAG, |w| {
                    // CMS version
                    w.encode_cms_version(sid);

                    // digestAlgorithms
                    w.encode_constructed(Self::SET_OF_TAG, |w| {
                        w.encode_alg_id(w.hash_oid());
                    });

                    // encapContentInfo (also signs the embedded CSR into `sig`)
                    w.encode_encapsulated_content_info(
                        sign_cb,
                        pub_key,
                        subject_name,
                        measurements,
                        sig,
                    )?;

                    // signerInfos
                    w.encode_deferred_tlv(Self::SET_OF_TAG, |w| {
                        w.encode_signer_info(sig, sid)?;
                        Ok(())
                    })?;
                    sig.zeroize();

                    Ok(())
                })?;
                Ok(())
            })?;

            Ok(())
        })?;

        self.check_not_truncated()?;
        Ok(bytes_written)
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

impl CreateDpeCertResult {
    pub fn zeroed(profile: DpeProfile) -> Self {
        let pub_key = match profile {
            #[cfg(feature = "p256")]
            DpeProfile::P256Sha256 => PubKey::Ecdsa(EcdsaPubKey::Ecdsa256(EcdsaPub256 {
                x: [0u8; curve_256::CURVE_SIZE],
                y: [0u8; curve_256::CURVE_SIZE],
            })),
            #[cfg(feature = "p384")]
            DpeProfile::P384Sha384 => PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(EcdsaPub384 {
                x: [0u8; curve_384::CURVE_SIZE],
                y: [0u8; curve_384::CURVE_SIZE],
            })),
            #[cfg(feature = "ml-dsa")]
            DpeProfile::Mldsa87 => PubKey::Mldsa(MldsaPublicKey(
                [0u8; MldsaAlgorithm::Mldsa87.public_key_size()],
            )),
        };
        Self {
            cert_size: 0,
            pub_key,
            exported_cdi_handle: [0u8; MAX_EXPORTED_CDI_SIZE],
        }
    }
}

fn get_subject_name<'a>(
    crypto: &mut dyn CryptoSuite,
    cert_type: &CertificateType,
    pub_key: &'a PubKey,
    subj_serial: &'a mut [u8],
) -> Result<Name<'a>, DpeErrorCode> {
    crypto.get_pubkey_serial(pub_key, subj_serial)?;

    // The serial number of the subject can be at most 64 bytes
    let truncated_subj_serial = &subj_serial[..64];

    let cn: &[u8] = match cert_type {
        CertificateType::Leaf => b"DPE Leaf",
        CertificateType::Exported => b"DPE Exported CDI",
    };

    let subject_name = Name {
        cn: DirectoryString::PrintableString(cn),
        serial: DirectoryString::PrintableString(truncated_subj_serial),
    };
    Ok(subject_name)
}

fn get_subject_key_identifier(
    crypto: &mut dyn CryptoSuite,
    pub_key: &PubKey,
    subject_key_identifier: &mut [u8],
) -> Result<(), DpeErrorCode> {
    // compute key identifier as SHA hash of the DER encoded subject public key
    let hashed_pub_key = match pub_key {
        PubKey::Ecdsa(pub_key) => {
            let (x, y) = pub_key.as_slice();
            crypto.hash_all(&[&[0x04], &x, &y])?
        }
        #[cfg(feature = "ml-dsa")]
        PubKey::Mldsa(pub_key) => crypto.hash(pub_key.as_slice())?,
    };
    if hashed_pub_key.size() < MAX_KEY_IDENTIFIER_SIZE {
        return Err(InternalErrorCode::KeyIdHashTooSmall.into());
    }
    // truncate key identifier to 20 bytes
    subject_key_identifier.copy_from_slice(&hashed_pub_key.as_slice()[..MAX_KEY_IDENTIFIER_SIZE]);
    Ok(())
}

pub(crate) fn create_exported_dpe_cert(
    args: &CreateDpeCertArgs,
    dpe: &mut DpeInstance,
    env: &mut dyn DpeEnv,
    cert: &mut dyn ResponseBuffer,
    out_result: &mut CreateDpeCertResult,
) -> Result<(), DpeErrorCode> {
    create_dpe_cert_or_csr(
        args,
        dpe,
        env,
        CertificateFormat::X509,
        CertificateType::Exported,
        cert,
        out_result,
    )
}

pub(crate) fn create_dpe_cert(
    args: &CreateDpeCertArgs,
    dpe: &mut DpeInstance,
    env: &mut dyn DpeEnv,
    cert: &mut dyn ResponseBuffer,
    out_result: &mut CreateDpeCertResult,
) -> Result<(), DpeErrorCode> {
    create_dpe_cert_or_csr(
        args,
        dpe,
        env,
        CertificateFormat::X509,
        CertificateType::Leaf,
        cert,
        out_result,
    )
}

#[cfg(not(feature = "disable_csr"))]
pub(crate) fn create_dpe_csr(
    args: &CreateDpeCertArgs,
    dpe: &mut DpeInstance,
    env: &mut dyn DpeEnv,
    csr: &mut dyn ResponseBuffer,
    out_result: &mut CreateDpeCertResult,
) -> Result<(), DpeErrorCode> {
    create_dpe_cert_or_csr(
        args,
        dpe,
        env,
        CertificateFormat::Csr,
        CertificateType::Leaf,
        csr,
        out_result,
    )
}

/// The signed payload variants handled by [`CertWriter::encode_signed_payload`]:
/// an X.509 TBSCertificate or a PKCS #10 CertificationRequestInfo.
pub(crate) enum SignedPayload<'a> {
    #[cfg(not(feature = "disable_x509"))]
    Tbs {
        serial_number: &'a [u8],
        issuer_name: &'a [u8],
        subject_name: &'a Name<'a>,
        pubkey: &'a PubKey,
        measurements: &'a MeasurementData<'a>,
        validity: &'a CertValidity,
    },
    #[cfg(not(feature = "disable_csr"))]
    CertReqInfo {
        pub_key: &'a PubKey,
        subject_name: &'a Name<'a>,
        measurements: &'a MeasurementData<'a>,
    },
}

enum CertOrCsrArgs<'a> {
    Cert {
        issuer_name: &'a [u8],
        cert_validity: &'a CertValidity,
    },
    #[cfg(not(feature = "disable_csr"))]
    Csr {
        signer_identifier: &'a SignerIdentifier,
    },
}

/// DO NOT REFACTOR WITH `impl` PARAMTER
///
/// This function wraps the core x509 logic to prevent monomorphizing the x509 code for each
/// `DpeEnv` used by Caliptra.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn generate_cert_or_csr(
    format_specific_args: CertOrCsrArgs,
    dpe_profile: DpeProfile,
    dice_extensions_are_critical: bool,
    subject_name: &Name,
    pub_key: &PubKey,
    measurements: &MeasurementData,
    sign_cb: &mut dyn SignCallback,
    output_cert_or_csr: &mut dyn ResponseBuffer,
    sig: &mut Signature,
) -> Result<u32, DpeErrorCode> {
    match format_specific_args {
        CertOrCsrArgs::Cert {
            issuer_name,
            cert_validity,
        } => {
            #[cfg(not(feature = "disable_x509"))]
            {
                let mut cert_writer = CertWriter::new(
                    output_cert_or_csr,
                    dpe_profile,
                    dice_extensions_are_critical,
                );
                // Serial number must be truncated to 20 bytes
                let serial_number = subject_name
                    .serial
                    .bytes()
                    .get(..20)
                    .ok_or(DpeErrorCode::from(InternalErrorCode::SerialNumberSliceOob))?;
                let bytes_written = cert_writer.encode_certificate(
                    sign_cb,
                    serial_number,
                    issuer_name,
                    subject_name,
                    pub_key,
                    measurements,
                    cert_validity,
                    sig,
                )?;
                u32::try_from(bytes_written)
                    .map_err(|_| DpeErrorCode::from(InternalErrorCode::CertSizeOverflow))
            }
        }
        #[cfg(not(feature = "disable_csr"))]
        CertOrCsrArgs::Csr { signer_identifier } => {
            let mut cms_writer = CertWriter::new(
                output_cert_or_csr,
                dpe_profile,
                dice_extensions_are_critical,
            );
            let bytes_written = cms_writer.encode_cms(
                sign_cb,
                pub_key,
                subject_name,
                measurements,
                signer_identifier,
                sig,
            )?;
            u32::try_from(bytes_written)
                .map_err(|_| DpeErrorCode::from(InternalErrorCode::CsrSizeOverflow))
        }
    }
}

fn create_dpe_cert_or_csr(
    args: &CreateDpeCertArgs,
    dpe: &mut DpeInstance,
    env: &mut dyn DpeEnv,
    cert_format: CertificateFormat,
    cert_type: CertificateType,
    output_cert_or_csr: &mut dyn ResponseBuffer,
    out_result: &mut CreateDpeCertResult,
) -> Result<(), DpeErrorCode> {
    let parent_idx = env
        .state()
        .get_active_context_pos(args.handle, args.locality)?;
    let digest = dpe.compute_measurement_hash(env, parent_idx)?;
    let (crypto, platform, state) = env.get();

    let mut exported_cdi_handle = None;

    let pub_key_res = match cert_type {
        CertificateType::Exported => {
            let exported_handle = crypto.derive_exported_cdi(&digest, args.cdi_label)?;
            exported_cdi_handle = Some(exported_handle);
            crypto
                .derive_key_pair_exported(&exported_handle, args.key_label, args.context)?
                .public_key(&mut out_result.pub_key)
        }
        CertificateType::Leaf => crypto.derive_pub_key(
            &digest,
            args.cdi_label,
            args.key_label,
            args.context,
            &mut out_result.pub_key,
        ),
    };
    let pub_key_ok = pub_key_res.is_ok();
    #[cfg(feature = "cfi")]
    let pub_key_ok = cfi_launder(pub_key_ok);
    if pub_key_ok {
        #[cfg(feature = "cfi")]
        cfi_assert!(pub_key_res.is_ok());
    } else {
        #[cfg(feature = "cfi")]
        cfi_assert!(pub_key_res.is_err());
    }
    pub_key_res?;
    let pub_key = &out_result.pub_key;
    let mut subj_serial = [0u8; MAX_HASH_SIZE * 2];
    let subject_name = get_subject_name(crypto, &cert_type, pub_key, &mut subj_serial)?;

    let mut subject_key_identifier = [0u8; MAX_KEY_IDENTIFIER_SIZE];
    get_subject_key_identifier(crypto, pub_key, &mut subject_key_identifier)?;

    let mut authority_key_identifier = [0u8; MAX_KEY_IDENTIFIER_SIZE];
    platform.get_issuer_key_identifier(&mut authority_key_identifier)?;

    let subject_alt_name = match platform.get_subject_alternative_name() {
        Ok(subject_alt_name) => Some(subject_alt_name),
        Err(PlatformError::NotImplemented) => None,
        Err(e) => Err(DpeErrorCode::Platform(e))?,
    };

    let is_ca = match cert_type {
        CertificateType::Leaf => false,
        CertificateType::Exported => true,
    };

    let supports_recursive = match cert_type {
        CertificateType::Leaf => state.support.recursive(),
        CertificateType::Exported => false,
    };

    let measurements = MeasurementData {
        tci_nodes: TciNodes::new(parent_idx, &state.contexts)?,
        label: args.ueid,
        is_ca,
        supports_recursive,
        subject_key_identifier,
        authority_key_identifier,
        subject_alt_name,
    };

    // Single signature buffer, filled in place by the sign callback and reused
    // for each signature on the path (X509 cert, or inner CSR + outer CMS).
    let mut sig = Signature::zeroed(crypto.signature_algorithm());

    let mut sign_cb = |buf: &dyn ResponseBuffer,
                       range: core::ops::Range<usize>,
                       use_derived: bool,
                       out: &mut Signature| {
        if use_derived {
            if let Some(exported_handle) = exported_cdi_handle {
                crypto
                    .derive_key_pair_exported(&exported_handle, args.key_label, args.context)?
                    .sign(&SignData::ResponseBuffer(buf, range), out)
            } else {
                crypto.sign_with_derived(
                    &digest,
                    args.cdi_label,
                    args.key_label,
                    args.context,
                    &SignData::ResponseBuffer(buf, range),
                    out,
                )
            }
        } else {
            crypto.sign_with_alias(&SignData::ResponseBuffer(buf, range), out)
        }
    };

    let mut issuer_name = [0u8; MAX_ISSUER_NAME_SIZE];
    let cert_validity = platform.get_cert_validity()?;
    #[cfg(not(feature = "disable_csr"))]
    let signer_identifier = platform.get_signer_identifier()?;
    let format_specific_args = match cert_format {
        CertificateFormat::X509 => {
            let issuer_name = {
                let issuer_len = platform.get_issuer_name(&mut issuer_name)?;
                if issuer_len > MAX_ISSUER_NAME_SIZE {
                    return Err(InternalErrorCode::IssuerNameTooLong.into());
                }
                &issuer_name[..issuer_len]
            };
            CertOrCsrArgs::Cert {
                issuer_name,
                cert_validity: &cert_validity,
            }
        }
        #[cfg(not(feature = "disable_csr"))]
        CertificateFormat::Csr => CertOrCsrArgs::Csr {
            signer_identifier: &signer_identifier,
        },
    };

    let cert_size = generate_cert_or_csr(
        format_specific_args,
        dpe.profile,
        args.dice_extensions_are_critical,
        &subject_name,
        pub_key,
        &measurements,
        &mut sign_cb,
        output_cert_or_csr,
        &mut sig,
    )?;

    // `out_result.pub_key` was already populated in place at derivation time.
    out_result.cert_size = cert_size;
    out_result.exported_cdi_handle = exported_cdi_handle.unwrap_or([0u8; MAX_EXPORTED_CDI_SIZE]);

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
pub(crate) mod tests {
    use crate::context::{Context, ContextState};
    use crate::dpe_instance::tests::DPE_PROFILE;
    use crate::error::{DpeErrorCode, InternalErrorCode};
    use crate::tci::{TciMeasurement, TciNodeData};
    #[cfg(any(feature = "p256", feature = "p384"))]
    use crate::x509::profile_oids;
    use crate::x509::{CertWriter, DirectoryString, MeasurementData, Name, TciNodes};
    use crate::DpeProfile;
    use crate::MAX_HANDLES;
    #[cfg(any(feature = "p384", feature = "p256"))]
    use caliptra_dpe_crypto::ecdsa::{EcdsaAlgorithm, EcdsaPub, EcdsaPubKey, EcdsaSig};
    #[cfg(all(feature = "ml-dsa", not(feature = "p384"), not(feature = "p256")))]
    use caliptra_dpe_crypto::ml_dsa::MldsaPublicKey;
    #[cfg(all(feature = "ml-dsa", not(feature = "p384"), not(feature = "p256")))]
    use caliptra_dpe_crypto::ml_dsa::{MldsaAlgorithm, MldsaSignature};
    use caliptra_dpe_crypto::{PubKey, Signature, SignatureAlgorithm};
    use caliptra_dpe_platform::{
        ArrayVec, CertValidity, OtherName, SignerIdentifier, SubjectAltName,
        MAX_KEY_IDENTIFIER_SIZE, MAX_OTHER_NAME_SIZE, MAX_SN_SIZE, MAX_UEID_SIZE,
    };
    use caliptra_dpe_response_buffer::{ResponseBuffer, SliceResponseBuffer};
    #[cfg(not(feature = "disable_csr"))]
    use cms::content_info::CmsVersion;
    #[cfg(not(feature = "disable_csr"))]
    use cms::signed_data::{SignerIdentifier as CmsSignerIdentifier, SignerInfo as CmsSignerInfo};
    #[cfg(not(feature = "disable_csr"))]
    use der::Decode;
    #[cfg(any(feature = "p384", feature = "p256"))]
    use der::Encode;
    use openssl::hash::{Hasher, MessageDigest};
    #[cfg(not(feature = "disable_csr"))]
    use spki::ObjectIdentifier;
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
        pub register_num: Option<u64>,
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
        pub _operational_flags_mask: Option<asn1::BitString<'a>>,
        #[implicit(11)]
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
            let mut cert_buf = SliceResponseBuffer::new(&mut cert);
            let mut w = CertWriter::new(&mut cert_buf, DPE_PROFILE, true);
            let byte_count = w.encode_integer_bytes(&c, true);
            let n = asn1::parse_single::<u64>(&cert[..byte_count]).unwrap();
            assert_eq!(n, u64::from_be_bytes(c));
            assert_eq!(2 + CertWriter::get_integer_bytes_size(&c), byte_count);
        }

        let integer_cases = [0xFFFFFFFF00000000, 0x0102030405060708, 0x2];

        for c in integer_cases {
            let mut cert = [0u8; 128];
            let mut cert_buf = SliceResponseBuffer::new(&mut cert);
            let mut w = CertWriter::new(&mut cert_buf, DPE_PROFILE, true);
            let byte_count = w.encode_integer(c, true);
            let n = asn1::parse_single::<u64>(&cert[..byte_count]).unwrap();
            assert_eq!(n, c);
            assert_eq!(
                2 + CertWriter::get_integer_bytes_size(&c.to_be_bytes()),
                byte_count
            );
        }
    }

    #[test]
    fn test_rdn() {
        let mut cert = [0u8; 256];
        let test_name = Name {
            cn: DirectoryString::PrintableString(b"Caliptra Alias"),
            serial: DirectoryString::PrintableString(&[0x0u8; DPE_PROFILE.hash_size() * 2]),
        };

        let mut cert_buf = SliceResponseBuffer::new(&mut cert);
        let mut w = CertWriter::new(&mut cert_buf, DPE_PROFILE, true);
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
    }

    /// Run `encode` over three buffers: exactly the required size (must succeed
    /// with `Ok(exact)`), one byte too small, and half size (each must report a
    /// truncation `Err`, never a silently-truncated `Ok`). The exact size is
    /// discovered by encoding once into a generous buffer.
    ///
    /// For the truncating cases the writer is handed a slice that is immediately
    /// followed, in the same allocation, by a canary region; after encoding the
    /// canary must be untouched, proving no write landed past the writer's slice.
    fn assert_overflow_detected<F>(mut encode: F)
    where
        F: FnMut(&mut CertWriter) -> Result<usize, DpeErrorCode>,
    {
        let mut big = vec![0u8; 16384];
        let mut sbuf = SliceResponseBuffer::new(&mut big);
        let exact = encode(&mut CertWriter::new(&mut sbuf, DPE_PROFILE, true))
            .expect("encoding into a large buffer should succeed");

        let mut buf = vec![0u8; exact];
        assert_eq!(
            encode(&mut CertWriter::new(
                &mut SliceResponseBuffer::new(&mut buf),
                DPE_PROFILE,
                true
            )),
            Ok(exact),
            "exact-fit buffer ({exact}) should succeed",
        );

        const CANARY: u8 = 0xA5;
        const CANARY_LEN: usize = 64;
        for len in [exact - 1, exact / 2] {
            // Writable region of `len` bytes followed by a canary region, all in
            // one allocation so an out-of-bounds write would clobber the canary.
            let mut backing = vec![CANARY; len + CANARY_LEN];
            let (writable, canary) = backing.split_at_mut(len);
            assert_eq!(
                encode(&mut CertWriter::new(
                    &mut SliceResponseBuffer::new(writable),
                    DPE_PROFILE,
                    true
                )),
                Err(DpeErrorCode::InternalError(
                    InternalErrorCode::CertSizeOverflow
                )),
                "undersized buffer ({len} of {exact}) must report truncation",
            );
            assert!(
                canary.iter().all(|&b| b == CANARY),
                "buffer overflow: a write past the {len}-byte buffer clobbered the canary",
            );
        }
    }

    /// Every public `CertWriter` encoder must report truncation rather than
    /// silently emitting a short structure when the output buffer is too small.
    #[test]
    fn test_pub_fn_buffer_overflow_is_detected() {
        // ----- shared inputs (mirror build_test_cert_*) -----
        let mut issuer_der = [0u8; 1024];
        let mut ibuf = SliceResponseBuffer::new(&mut issuer_der);
        let issuer_len = CertWriter::new(&mut ibuf, DPE_PROFILE, true)
            .encode_rdn(&TEST_ISSUER_NAME)
            .unwrap();
        let issuer = &issuer_der[..issuer_len];

        let context = Context {
            state: ContextState::Active,
            ..Context::default()
        };
        let contexts = [context];
        let subject_key_identifier = [0u8; MAX_KEY_IDENTIFIER_SIZE];
        let mut other_name = ArrayVec::new();
        other_name
            .try_extend_from_slice(DEFAULT_OTHER_NAME_VALUE.as_bytes())
            .unwrap();
        let measurements = MeasurementData {
            label: &[0; DPE_PROFILE.hash_size()],
            tci_nodes: TciNodes::new(0, &contexts).unwrap(),
            is_ca: false,
            supports_recursive: true,
            subject_key_identifier,
            authority_key_identifier: subject_key_identifier,
            subject_alt_name: Some(SubjectAltName::OtherName(OtherName {
                oid: DEFAULT_OTHER_NAME_OID,
                other_name,
            })),
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

        // Public key + signature for the active profile.
        #[cfg(feature = "p384")]
        let (pub_key, test_sig) = {
            let test_pub = EcdsaPub::from_slice(&[0xAA; ECC_INT_SIZE], &[0xBB; ECC_INT_SIZE]);
            let pub_key = PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(test_pub));
            let sig = Signature::Ecdsa(
                EcdsaSig::from_slice(&[0xCC; ECC_INT_SIZE], &[0xDD; ECC_INT_SIZE]).into(),
            );
            (pub_key, sig)
        };
        #[cfg(all(feature = "p256", not(feature = "p384")))]
        let (pub_key, test_sig) = {
            let test_pub = EcdsaPub::from_slice(&[0xAA; ECC_INT_SIZE], &[0xBB; ECC_INT_SIZE]);
            let pub_key = PubKey::Ecdsa(EcdsaPubKey::Ecdsa256(test_pub));
            let sig = Signature::Ecdsa(
                EcdsaSig::from_slice(&[0xCC; ECC_INT_SIZE], &[0xDD; ECC_INT_SIZE]).into(),
            );
            (pub_key, sig)
        };
        #[cfg(all(feature = "ml-dsa", not(feature = "p384"), not(feature = "p256")))]
        let (pub_key, test_sig) = {
            const ALGORITHM: MldsaAlgorithm = match DPE_PROFILE.alg() {
                SignatureAlgorithm::Mldsa(a) => a,
                _ => panic!("non-ml-dsa profile in ml-dsa test"),
            };
            (
                PubKey::Mldsa(MldsaPublicKey::from_slice(
                    &[0xAA; ALGORITHM.public_key_size()],
                )),
                Signature::Mldsa(MldsaSignature([0xBB; ALGORITHM.signature_size()])),
            )
        };

        let mut sign_cb = |_buf: &dyn ResponseBuffer,
                           _range: core::ops::Range<usize>,
                           _use_derived: bool,
                           out: &mut Signature| {
            *out = test_sig.clone();
            Ok(())
        };
        let mut sig = test_sig.clone();

        // SubjectKeyIdentifier keeps the SignerIdentifier setup simple.
        let mut ski = ArrayVec::new();
        ski.try_extend_from_slice(&subject_key_identifier).unwrap();
        let sid = SignerIdentifier::SubjectKeyIdentifier(ski);

        // ----- exercise every public encoder -----
        assert_overflow_detected(|w| w.encode_rdn(&TEST_SUBJECT_NAME));
        assert_overflow_detected(|w| {
            w.encode_tbs(
                TEST_SERIAL,
                issuer,
                &TEST_SUBJECT_NAME,
                &pub_key,
                &measurements,
                &validity,
            )
        });
        assert_overflow_detected(|w| {
            w.encode_certification_request_info(&pub_key, &TEST_SUBJECT_NAME, &measurements)
        });
        assert_overflow_detected(|w| w.encode_signer_info(&test_sig, &sid));
        assert_overflow_detected(|w| {
            w.encode_certificate(
                &mut sign_cb,
                TEST_SERIAL,
                issuer,
                &TEST_SUBJECT_NAME,
                &pub_key,
                &measurements,
                &validity,
                &mut sig,
            )
        });
        assert_overflow_detected(|w| {
            w.encode_csr(
                &mut sign_cb,
                &pub_key,
                &TEST_SUBJECT_NAME,
                &measurements,
                &mut sig,
            )
        });
        assert_overflow_detected(|w| {
            w.encode_cms(
                &mut sign_cb,
                &pub_key,
                &TEST_SUBJECT_NAME,
                &measurements,
                &sid,
                &mut sig,
            )
        });
    }

    #[cfg(any(feature = "p384", feature = "p256"))]
    #[test]
    fn test_subject_pubkey() {
        let mut cert = [0u8; 384];
        let test_key = EcdsaPubKey::Ecdsa384(EcdsaPub::default());

        let curve_oid = match DPE_PROFILE {
            #[cfg(feature = "p256")]
            DpeProfile::P256Sha256 => profile_oids::CURVE_P256_OID,
            #[cfg(feature = "p384")]
            DpeProfile::P384Sha384 => profile_oids::CURVE_P384_OID,
            #[cfg(feature = "ml-dsa")]
            DpeProfile::Mldsa87 => unreachable!("mldsa87 is not an ecdsa profile"),
        };

        let mut cert_buf = SliceResponseBuffer::new(&mut cert);
        let mut w = CertWriter::new(&mut cert_buf, DPE_PROFILE, true);
        let bytes_written = w.encode_ecdsa_subject_pubkey_info(&test_key, curve_oid);

        SubjectPublicKeyInfo::from_der(&cert[..bytes_written]).unwrap();
    }

    #[cfg(all(feature = "ml-dsa", not(feature = "p384"), not(feature = "p256")))]
    #[test]
    fn test_subject_pubkey() {
        let mut cert = [0u8; 4096];
        let test_key = MldsaPublicKey([0; MldsaAlgorithm::Mldsa87.public_key_size()]);

        let mut cert_buf = SliceResponseBuffer::new(&mut cert);
        let mut w = CertWriter::new(&mut cert_buf, DPE_PROFILE, true);
        let bytes_written = w.encode_mldsa_subject_pubkey_info(&test_key);

        let (rem, _) = SubjectPublicKeyInfo::from_der(&cert[..bytes_written]).unwrap();
        assert!(rem.is_empty());
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
        let mut supports_recursive = true;
        let mut cert_buf = SliceResponseBuffer::new(&mut cert);
        let mut w = CertWriter::new(&mut cert_buf, DPE_PROFILE, true);
        let mut bytes_written = w.encode_tcb_info(&node, supports_recursive);
        let mut parsed_tcb_info = asn1::parse_single::<TcbInfo>(&cert[..bytes_written]).unwrap();

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
        let ir = ir_itr.next().unwrap();
        assert_eq!(ir.register_num.unwrap(), CertWriter::INTEGRITY_REGISTER_NUM);
        let mut fwid_itr = ir.register_digests.unwrap();
        let expected_cumulative = fwid_itr.next().unwrap().digest;
        assert_eq!(expected_cumulative, node.tci_cumulative.0);

        // test tbs_info with supports_recursive = false
        supports_recursive = false;
        let mut cert_buf = SliceResponseBuffer::new(&mut cert);
        let mut w = CertWriter::new(&mut cert_buf, DPE_PROFILE, true);
        bytes_written = w.encode_tcb_info(&node, supports_recursive);

        parsed_tcb_info = asn1::parse_single::<TcbInfo>(&cert[..bytes_written]).unwrap();

        // Check that only FWID[0] is present
        let mut fwid_itr = parsed_tcb_info.fwids.unwrap();
        let expected_current = fwid_itr.next().unwrap().digest;
        assert!(fwid_itr.next().is_none());
        assert_eq!(expected_current, node.tci_current.0);
    }

    fn get_key_usage(is_ca: bool) -> KeyUsage {
        let mut cert = [0u8; 32];
        let mut cert_buf = SliceResponseBuffer::new(&mut cert);
        let mut w = CertWriter::new(&mut cert_buf, DPE_PROFILE, true);
        let bytes_written = w.encode_key_usage(is_ca);

        let mut parser = X509ExtensionParser::new().with_deep_parse_extensions(false);
        let (rem, ext) = parser.parse(&cert[..bytes_written]).unwrap();
        assert!(rem.is_empty());
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

    #[cfg(any(feature = "p384", feature = "p256"))]
    const ECC_INT_SIZE: usize = DPE_PROFILE.ecc_int_size();

    const DEFAULT_OTHER_NAME_OID: &[u8] = &[0, 0, 0];
    const DEFAULT_OTHER_NAME_VALUE: &str = "default-other-name";

    #[cfg(any(feature = "p384", feature = "p256"))]
    fn build_test_cert_ecdsa(is_ca: bool, cert_buf: &mut [u8]) -> (usize, X509Certificate<'_>) {
        let mut issuer_der = [0u8; 1024];
        let mut ibuf = SliceResponseBuffer::new(&mut issuer_der);
        let mut issuer_writer = CertWriter::new(&mut ibuf, DPE_PROFILE, true);
        let issuer_len = issuer_writer.encode_rdn(&TEST_ISSUER_NAME).unwrap();

        let test_pub = EcdsaPub::from_slice(&[0xAA; ECC_INT_SIZE], &[0xBB; ECC_INT_SIZE]);

        let context = Context {
            state: ContextState::Active,
            ..Context::default()
        };
        let contexts = [context];

        let mut hasher = match DPE_PROFILE {
            #[cfg(feature = "p256")]
            DpeProfile::P256Sha256 => Hasher::new(MessageDigest::sha256()).unwrap(),
            #[cfg(feature = "p384")]
            DpeProfile::P384Sha384 => Hasher::new(MessageDigest::sha384()).unwrap(),
            #[cfg(feature = "ml-dsa")]
            DpeProfile::Mldsa87 => unreachable!("mldsa87 in ecdsa test"),
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
            tci_nodes: TciNodes::new(0, &contexts).unwrap(),
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

        let mut sign_cb = |_buf: &dyn ResponseBuffer,
                           _range: core::ops::Range<usize>,
                           _use_derived: bool,
                           out: &mut Signature| {
            *out = test_sig.clone();
            Ok(())
        };
        let mut sig = test_sig.clone();

        let mut cbuf = SliceResponseBuffer::new(cert_buf);
        let mut w = CertWriter::new(&mut cbuf, DPE_PROFILE, true);
        let bytes_written = w
            .encode_certificate(
                &mut sign_cb,
                TEST_SERIAL,
                &issuer_der[..issuer_len],
                &TEST_SUBJECT_NAME,
                &pub_key,
                &measurements,
                &validity,
                &mut sig,
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

    #[cfg(all(feature = "ml-dsa", not(feature = "p384"), not(feature = "p256")))]
    fn build_test_cert_mldsa(is_ca: bool, cert_buf: &mut [u8]) -> (usize, X509Certificate<'_>) {
        let mut issuer_der = [0u8; 1024];
        let mut ibuf = SliceResponseBuffer::new(&mut issuer_der);
        let mut issuer_writer = CertWriter::new(&mut ibuf, DPE_PROFILE, true);
        let issuer_len = issuer_writer.encode_rdn(&TEST_ISSUER_NAME).unwrap();

        const ALGORITHM: MldsaAlgorithm = match DPE_PROFILE.alg() {
            SignatureAlgorithm::Mldsa(mldsa_algorithm) => mldsa_algorithm,
            _ => panic!("non-ml-dsa profile in ml-dsa test"),
        };

        let test_pub = MldsaPublicKey::from_slice(&[0xAA; ALGORITHM.public_key_size()]);

        let context = Context {
            state: ContextState::Active,
            ..Context::default()
        };
        let contexts = [context];

        let mut hasher = match DPE_PROFILE {
            DpeProfile::Mldsa87 => Hasher::new(MessageDigest::sha384()).unwrap(),
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
            tci_nodes: TciNodes::new(0, &contexts).unwrap(),
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
            SignatureAlgorithm::Mldsa(MldsaAlgorithm::Mldsa87) => PubKey::Mldsa(test_pub),
            _ => unreachable!("non-ml-dsa profile in ml-dsa test"),
        };

        let test_sig: Signature = match DPE_PROFILE.alg() {
            SignatureAlgorithm::Mldsa(MldsaAlgorithm::Mldsa87) => {
                Signature::Mldsa(MldsaSignature([0xBB; ALGORITHM.signature_size()]))
            }
            _ => unreachable!("non-ml-dsa profile in ml-dsa test"),
        };

        let mut sign_cb = |_buf: &dyn ResponseBuffer,
                           _range: core::ops::Range<usize>,
                           _use_derived: bool,
                           out: &mut Signature| {
            *out = test_sig.clone();
            Ok(())
        };
        let mut sig = test_sig.clone();

        let mut cbuf = SliceResponseBuffer::new(cert_buf);
        let mut w = CertWriter::new(&mut cbuf, DPE_PROFILE, true);
        let bytes_written = w
            .encode_certificate(
                &mut sign_cb,
                TEST_SERIAL,
                &issuer_der[..issuer_len],
                &TEST_SUBJECT_NAME,
                &pub_key,
                &measurements,
                &validity,
                &mut sig,
            )
            .unwrap();

        let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
        let cert = match parser.parse(&cert_buf[..bytes_written]) {
            Ok((_, parsed_cert)) => {
                assert_eq!(parsed_cert.version(), X509Version::V3);
                assert_eq!(
                    parsed_cert.tbs_certificate.signature.algorithm.as_bytes(),
                    const_oid::db::fips204::ID_ML_DSA_87.as_bytes()
                );
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
    #[cfg_attr(miri, ignore)]
    fn test_full_leaf() {
        #[cfg(any(feature = "p384", feature = "p256"))]
        let mut cert_buf = [0u8; 1024];
        #[cfg(any(feature = "p384", feature = "p256"))]
        let (_, cert) = build_test_cert_ecdsa(false, &mut cert_buf);
        #[cfg(all(feature = "ml-dsa", not(feature = "p384"), not(feature = "p256")))]
        let mut cert_buf = [0u8; 8192];
        #[cfg(all(feature = "ml-dsa", not(feature = "p384"), not(feature = "p256")))]
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

        if cert.get_extension_unique(&oid!(2.5.29 .35)).is_err() {
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
    #[cfg_attr(miri, ignore)]
    fn test_full_ca() {
        #[cfg(any(feature = "p384", feature = "p256"))]
        let mut cert_buf = [0u8; 1024];
        #[cfg(any(feature = "p384", feature = "p256"))]
        let (_, cert) = build_test_cert_ecdsa(true, &mut cert_buf);
        #[cfg(all(feature = "ml-dsa", not(feature = "p384"), not(feature = "p256")))]
        let mut cert_buf = [0u8; 8192];
        #[cfg(all(feature = "ml-dsa", not(feature = "p384"), not(feature = "p256")))]
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
            #[cfg(feature = "p256")]
            DpeProfile::P256Sha256 => Hasher::new(MessageDigest::sha256()).unwrap(),
            #[cfg(feature = "p384")]
            DpeProfile::P384Sha384 => Hasher::new(MessageDigest::sha384()).unwrap(),
            #[cfg(feature = "ml-dsa")]
            DpeProfile::Mldsa87 => Hasher::new(MessageDigest::sha384()).unwrap(),
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

    fn build_test_context() -> Context {
        use crate::tci::TciMeasurement;

        let mut context = Context::new();
        let mut node = TciNodeData::new();
        node.tci_type = 0x01020304;
        node.tci_current = TciMeasurement([0xAA; DPE_PROFILE.tci_size()]);
        node.tci_cumulative = TciMeasurement([0xBB; DPE_PROFILE.tci_size()]);
        node.locality = 0x05060708;

        context.tci = node;
        context.state = ContextState::Active;
        context
    }

    fn build_test_measurements(contexts: &[Context], is_ca: bool) -> MeasurementData<'_> {
        MeasurementData {
            label: &[0xAA; 4],
            tci_nodes: TciNodes::new(0, contexts).unwrap(),
            is_ca,
            supports_recursive: true,
            subject_key_identifier: [0xBB; MAX_KEY_IDENTIFIER_SIZE],
            authority_key_identifier: [0xCC; MAX_KEY_IDENTIFIER_SIZE],
            subject_alt_name: None,
        }
    }

    #[test]
    fn test_encode_multi_tcb_info_bytes() {
        let context = build_test_context();
        let contexts = [context];
        let measurements = build_test_measurements(&contexts, true);

        let mut buf = [0u8; 1024];
        let mut sbuf = SliceResponseBuffer::new(&mut buf);
        let mut w = CertWriter::new(&mut sbuf, DPE_PROFILE, true);
        let n = w.encode_multi_tcb_info(&measurements).unwrap();

        let expected: &[u8] = match DPE_PROFILE {
            #[cfg(feature = "p256")]
            DpeProfile::P256Sha256 => &[
                0x30, 0x81, 0x89, // SEQUENCE
                0x06, 0x06, 0x67, 0x81, 0x05, 0x05, 0x04, 0x05, // OID 2.23.133.5.4.5
                0x01, 0x01, 0xff, // BOOLEAN critical
                0x04, 0x7c, // OCTET STRING
                0x30, 0x7a, // SEQUENCE OF
                0x30, 0x78, // TcbInfo SEQUENCE
                0x83, 0x01, 0x00, // [3] svn
                0xa6, 0x2f, // [6] fwids
                0x30, 0x2d, // FWID SEQUENCE
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, // hashAlg
                0x04, 0x02, 0x01, // SHA-256
                0x04, 0x20, // digest OCTET STRING (32 bytes)
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //
                0x88, 0x04, 0x05, 0x06, 0x07, 0x08, // [8] vendorInfo (locality)
                0x89, 0x04, 0x04, 0x03, 0x02, 0x01, // [9] tci_type
                0xab, 0x36, // [11] integrityRegisters
                0x30, 0x34, // IntegrityRegister SEQUENCE
                0x81, 0x01, 0x00, // [1] registerNum
                0xa2, 0x2f, // [2] registerDigests
                0x30, 0x2d, // FWID SEQUENCE
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, // hashAlg
                0x04, 0x02, 0x01, // SHA-256
                0x04, 0x20, // digest OCTET STRING (32 bytes)
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, //
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, //
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, //
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, //
            ],
            #[cfg(feature = "p384")]
            DpeProfile::P384Sha384 => &[
                0x30, 0x81, 0xac, // SEQUENCE
                0x06, 0x06, 0x67, 0x81, 0x05, 0x05, 0x04, 0x05, // OID 2.23.133.5.4.5
                0x01, 0x01, 0xff, // BOOLEAN critical
                0x04, 0x81, 0x9e, // OCTET STRING
                0x30, 0x81, 0x9b, // SEQUENCE OF
                0x30, 0x81, 0x98, // TcbInfo SEQUENCE
                0x83, 0x01, 0x00, // [3] svn
                0xa6, 0x3f, // [6] fwids
                0x30, 0x3d, // FWID SEQUENCE
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, // hashAlg
                0x04, 0x02, 0x02, // SHA-384
                0x04, 0x30, // digest OCTET STRING (48 bytes)
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //
                0x88, 0x04, 0x05, 0x06, 0x07, 0x08, // [8] vendorInfo (locality)
                0x89, 0x04, 0x04, 0x03, 0x02, 0x01, // [9] tci_type
                0xab, 0x46, // [11] integrityRegisters
                0x30, 0x44, // IntegrityRegister SEQUENCE
                0x81, 0x01, 0x00, // [1] registerNum
                0xa2, 0x3f, // [2] registerDigests
                0x30, 0x3d, // FWID SEQUENCE
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, // hashAlg
                0x04, 0x02, 0x02, // SHA-384
                0x04, 0x30, // digest OCTET STRING (48 bytes)
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, //
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, //
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, //
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, //
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, //
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, //
            ],
            #[cfg(feature = "ml-dsa")]
            DpeProfile::Mldsa87 => &[
                0x30, 0x81, 0xac, // SEQUENCE
                0x06, 0x06, 0x67, 0x81, 0x05, 0x05, 0x04, 0x05, // OID 2.23.133.5.4.5
                0x01, 0x01, 0xff, // BOOLEAN critical
                0x04, 0x81, 0x9e, // OCTET STRING
                0x30, 0x81, 0x9b, // SEQUENCE OF
                0x30, 0x81, 0x98, // TcbInfo SEQUENCE
                0x83, 0x01, 0x00, // [3] svn
                0xa6, 0x3f, // [6] fwids
                0x30, 0x3d, // FWID SEQUENCE
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, // hashAlg
                0x04, 0x02, 0x02, // SHA-384
                0x04, 0x30, // digest OCTET STRING (48 bytes)
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //
                0x88, 0x04, 0x05, 0x06, 0x07, 0x08, // [8] vendorInfo (locality)
                0x89, 0x04, 0x04, 0x03, 0x02, 0x01, // [9] tci_type
                0xab, 0x46, // [11] integrityRegisters
                0x30, 0x44, // IntegrityRegister SEQUENCE
                0x81, 0x01, 0x00, // [1] registerNum
                0xa2, 0x3f, // [2] registerDigests
                0x30, 0x3d, // FWID SEQUENCE
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, // hashAlg
                0x04, 0x02, 0x02, // SHA-384
                0x04, 0x30, // digest OCTET STRING (48 bytes)
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, //
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, //
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, //
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, //
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, //
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, //
            ],
        };
        assert_eq!(&buf[..n], expected);
    }

    #[test]
    fn test_multi_tcb_info_size_varies_with_svn() {
        use crate::tci::TciMeasurement;

        // Node 0 (root): SVN=0 → DER INTEGER 1 byte content → 3 bytes with [3] tag+len
        let mut ctx0 = Context::new();
        ctx0.tci.tci_type = 0x01020304;
        ctx0.tci.tci_current = TciMeasurement([0xAA; DPE_PROFILE.tci_size()]);
        ctx0.tci.tci_cumulative = TciMeasurement([0xBB; DPE_PROFILE.tci_size()]);
        ctx0.tci.locality = 0x05060708;
        ctx0.tci.svn = 0; // 1-byte DER content
        ctx0.parent_idx = Context::ROOT_INDEX;
        ctx0.state = ContextState::Active;

        // Node 1 (child): SVN=128 → DER INTEGER needs 0x00 prefix → 2-byte content → 4 bytes
        // This node's TCB info will be 1 byte larger than node 0's.
        let mut ctx1 = Context::new();
        ctx1.tci.tci_type = 0x01020304;
        ctx1.tci.tci_current = TciMeasurement([0xAA; DPE_PROFILE.tci_size()]);
        ctx1.tci.tci_cumulative = TciMeasurement([0xBB; DPE_PROFILE.tci_size()]);
        ctx1.tci.locality = 0x05060708;
        ctx1.tci.svn = 128; // 2-byte DER content (needs leading 0x00)
        ctx1.parent_idx = 0; // child of ctx0
        ctx1.state = ContextState::Active;

        let contexts = [ctx0, ctx1];
        // Leaf is index 1; iterator walks root→child (idx 0 then idx 1).
        let measurements = MeasurementData {
            label: &[0xAA; 4],
            tci_nodes: TciNodes::new(1, &contexts).unwrap(),
            is_ca: false,
            supports_recursive: true,
            subject_key_identifier: [0xBB; MAX_KEY_IDENTIFIER_SIZE],
            authority_key_identifier: [0xCC; MAX_KEY_IDENTIFIER_SIZE],
            subject_alt_name: None,
        };

        // Encode the extension and measure actual bytes written.
        let mut buf = [0u8; 1024];
        let mut sbuf = SliceResponseBuffer::new(&mut buf);
        let mut w = CertWriter::new(&mut sbuf, DPE_PROFILE, true);
        let n = w.encode_multi_tcb_info(&measurements).unwrap();

        let mut parser = X509ExtensionParser::new().with_deep_parse_extensions(false);
        let (rem, ext) = parser.parse(&buf[..n]).unwrap();
        assert!(rem.is_empty());
        let parsed = asn1::parse_single::<asn1::SequenceOf<TcbInfo>>(ext.value).unwrap();
        assert_eq!(parsed.count(), 2);

        // Confirm the two nodes have different individual TCB info sizes (the case we are trying to cover with this test)
        let mut nbuf = [0u8; 256];
        let node0_size =
            CertWriter::new(&mut SliceResponseBuffer::new(&mut nbuf), DPE_PROFILE, true)
                .encode_tcb_info(&contexts[0].tci, true);
        let node1_size =
            CertWriter::new(&mut SliceResponseBuffer::new(&mut nbuf), DPE_PROFILE, true)
                .encode_tcb_info(&contexts[1].tci, true);
        assert_ne!(
            node0_size, node1_size,
            "test requires nodes with different tcb_info sizes to be meaningful"
        );
        assert_ne!(node0_size * 2, node0_size + node1_size);
    }

    #[test]
    fn test_encode_ueid_bytes() {
        let context = build_test_context();
        let contexts = [context];
        let measurements = build_test_measurements(&contexts, true);

        let mut buf = [0u8; 1024];
        let mut sbuf = SliceResponseBuffer::new(&mut buf);
        let mut w = CertWriter::new(&mut sbuf, DPE_PROFILE, true);
        let n = w.encode_ueid(&measurements);

        let expected: &[u8] = &[
            0x30, 0x15, // SEQUENCE
            0x06, 0x06, 0x67, 0x81, 0x05, 0x05, 0x04, 0x04, // OID 2.23.133.5.4.4
            0x01, 0x01, 0xff, // BOOLEAN critical
            0x04, 0x08, // OCTET STRING
            0x30, 0x06, // SEQUENCE
            0x04, 0x04, 0xaa, 0xaa, 0xaa, 0xaa, // OCTET STRING (ueid)
        ];
        assert_eq!(&buf[..n], expected);
    }

    #[test]
    fn test_encode_basic_constraints_bytes() {
        let context = build_test_context();
        let contexts = [context];
        let measurements = build_test_measurements(&contexts, true);

        let mut buf = [0u8; 1024];
        let mut sbuf = SliceResponseBuffer::new(&mut buf);
        let mut w = CertWriter::new(&mut sbuf, DPE_PROFILE, true);
        let n = w.encode_basic_constraints(&measurements);

        let expected: &[u8] = &[
            0x30, 0x0f, // SEQUENCE
            0x06, 0x03, 0x55, 0x1d, 0x13, // OID 2.5.29.19
            0x01, 0x01, 0xff, // BOOLEAN critical
            0x04, 0x05, // OCTET STRING
            0x30, 0x03, // SEQUENCE
            0x01, 0x01, 0xff, // BOOLEAN cA=TRUE
        ];
        assert_eq!(&buf[..n], expected);
    }

    #[test]
    fn test_encode_key_usage_bytes() {
        let mut buf = [0u8; 1024];
        let mut sbuf = SliceResponseBuffer::new(&mut buf);
        let mut w = CertWriter::new(&mut sbuf, DPE_PROFILE, true);
        let n = w.encode_key_usage(true);

        let expected: &[u8] = &[
            0x30, 0x0e, // SEQUENCE
            0x06, 0x03, 0x55, 0x1d, 0x0f, // OID 2.5.29.15
            0x01, 0x01, 0xff, // BOOLEAN critical
            0x04, 0x04, // OCTET STRING
            0x03, 0x02, 0x02, 0x84, // BIT STRING (digitalSignature | keyCertSign)
        ];
        assert_eq!(&buf[..n], expected);
    }

    #[test]
    fn test_encode_extended_key_usage_bytes() {
        let context = build_test_context();
        let contexts = [context];
        let measurements = build_test_measurements(&contexts, true);

        let mut buf = [0u8; 1024];
        let mut sbuf = SliceResponseBuffer::new(&mut buf);
        let mut w = CertWriter::new(&mut sbuf, DPE_PROFILE, true);
        let n = w.encode_extended_key_usage(&measurements);

        let expected: &[u8] = &[
            0x30, 0x15, // SEQUENCE
            0x06, 0x03, 0x55, 0x1d, 0x25, // OID 2.5.29.37
            0x01, 0x01, 0xff, // BOOLEAN critical
            0x04, 0x0b, // OCTET STRING
            0x30, 0x09, // SEQUENCE
            0x06, 0x07, 0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x0c, // OID tcg-dice-kp-eca
        ];
        assert_eq!(&buf[..n], expected);
    }

    #[test]
    fn test_encode_subject_alt_name_extension_bytes() {
        let context = build_test_context();
        let contexts = [context];
        let mut measurements = build_test_measurements(&contexts, true);

        let mut other_name_val = ArrayVec::new();
        other_name_val.try_extend_from_slice(b"test").unwrap();
        let san = SubjectAltName::OtherName(OtherName {
            oid: &[0x01, 0x02, 0x03],
            other_name: other_name_val,
        });
        measurements.subject_alt_name = Some(san);

        let mut buf = [0u8; 1024];
        let mut sbuf = SliceResponseBuffer::new(&mut buf);
        let mut w = CertWriter::new(&mut sbuf, DPE_PROFILE, true);
        let n = w.encode_subject_alt_name_extension(&measurements);

        let expected: &[u8] = &[
            0x30, 0x18, // SEQUENCE
            0x06, 0x03, 0x55, 0x1d, 0x11, // OID 2.5.29.17
            0x04, 0x11, // OCTET STRING
            0x30, 0x0f, // SEQUENCE (GeneralNames)
            0xa0, 0x0d, // [0] otherName
            0x06, 0x03, 0x01, 0x02, 0x03, // type-id OID
            0xa0, 0x06, 0x0c, 0x04, 0x74, 0x65, 0x73, 0x74, // [0] EXPLICIT UTF8 "test"
        ];
        assert_eq!(&buf[..n], expected);
    }

    #[test]
    fn test_encode_authority_key_identifier_extension_bytes() {
        let context = build_test_context();
        let contexts = [context];
        let measurements = build_test_measurements(&contexts, true);

        let mut buf = [0u8; 1024];
        let mut sbuf = SliceResponseBuffer::new(&mut buf);
        let mut w = CertWriter::new(&mut sbuf, DPE_PROFILE, true);
        let n = w.encode_authority_key_identifier_extension(&measurements, true);

        let expected: &[u8] = &[
            0x30, 0x1f, // SEQUENCE
            0x06, 0x03, 0x55, 0x1d, 0x23, // OID 2.5.29.35
            0x04, 0x18, // OCTET STRING
            0x30, 0x16, // SEQUENCE
            0x80, 0x14, // [0] keyIdentifier
            0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, //
            0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, //
            0xcc, 0xcc, 0xcc, 0xcc, //
        ];
        assert_eq!(&buf[..n], expected);
    }

    #[test]
    fn test_encode_subject_key_identifier_extension_bytes() {
        let context = build_test_context();
        let contexts = [context];
        let measurements = build_test_measurements(&contexts, true);

        let mut buf = [0u8; 1024];
        let mut sbuf = SliceResponseBuffer::new(&mut buf);
        let mut w = CertWriter::new(&mut sbuf, DPE_PROFILE, true);
        let n = w.encode_subject_key_identifier_extension(&measurements, true);

        let expected: &[u8] = &[
            0x30, 0x1d, // SEQUENCE
            0x06, 0x03, 0x55, 0x1d, 0x0e, // OID 2.5.29.14
            0x04, 0x16, // OCTET STRING
            0x04, 0x14, // OCTET STRING (subjectKeyIdentifier)
            0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, //
            0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, //
            0xbb, 0xbb, 0xbb, 0xbb, //
        ];
        assert_eq!(&buf[..n], expected);
    }

    // ===== Correctness tests for encode_tbs / encode_certification_request_info /
    //       encode_csr / encode_signer_info =====

    fn strip_der_int_leading_zero(b: &[u8]) -> &[u8] {
        b.strip_prefix(&[0u8]).unwrap_or(b)
    }

    fn make_validity(_max_size: bool) -> CertValidity {
        // Use the same strings for both typical and max cases since validity
        // length is not what exercises the multi-byte length paths.
        let mut not_before = ArrayVec::new();
        not_before
            .try_extend_from_slice(b"20230227000000Z")
            .unwrap();
        let mut not_after = ArrayVec::new();
        not_after.try_extend_from_slice(b"99991231235959Z").unwrap();
        CertValidity {
            not_before,
            not_after,
        }
    }

    fn encode_issuer_der(cn_len: usize, serial_len: usize) -> Vec<u8> {
        let cn: Vec<u8> = std::iter::repeat_n(b'A', cn_len).collect();
        let sn: Vec<u8> = std::iter::repeat_n(b'0', serial_len).collect();
        let name = Name {
            cn: DirectoryString::PrintableString(&cn),
            serial: DirectoryString::PrintableString(&sn),
        };
        let mut buf = vec![0u8; 1024];
        let mut sbuf = SliceResponseBuffer::new(&mut buf);
        let n = CertWriter::new(&mut sbuf, DPE_PROFILE, true)
            .encode_rdn(&name)
            .unwrap();
        buf.truncate(n);
        buf
    }

    /// Build `n` active contexts linked into a single child->root chain: index 0
    /// is the leaf, index `n - 1` is the root (`parent_idx[i] == i + 1`). Both
    /// `parent_idx` and the parent's `children` bitmap are populated because the
    /// root->leaf traversal used by `first_node()` walks the `children` links.
    /// This makes `TciNodes::new(0, ..)` yield all `n` nodes, so the `max_size`
    /// cases actually exercise a full MAX_HANDLES multiTcbInfo instead of
    /// collapsing to a single node (every default context points at `ROOT_INDEX`).
    fn make_test_contexts(n: usize) -> Vec<Context> {
        let mut contexts: Vec<Context> = (0..n)
            .map(|_| Context {
                state: ContextState::Active,
                ..Context::default()
            })
            .collect();
        #[allow(clippy::needless_range_loop)]
        for i in 0..n {
            if i + 1 < n {
                contexts[i].parent_idx = (i + 1) as u8;
                contexts[i + 1].children.add_child(i).unwrap();
            } else {
                contexts[i].parent_idx = Context::ROOT_INDEX;
            }
        }
        contexts
    }

    /// Assert that a freshly encoded top-level SEQUENCE (a TBSCertificate or a
    /// CertificationRequestInfo) uses the 3-byte DER long-form length field —
    /// i.e. its content length is in `256..=65535` (`get_size_width == 3`).
    ///
    /// This is a hard precondition of the deferred-length optimization:
    /// `encode_tbs` / `encode_certification_request_info` reserve exactly
    /// `SIZE_TAG_OFFSET` (3) bytes for the length before the content size is
    /// known, then backfill it. If a real structure ever encoded to a shorter
    /// (<256, width 1-2) or longer (>65535, width 4-5) length, the reserved
    /// width would be wrong and `backfill_size` would reject it (or leave a gap
    /// in the output). Checking the minimal and maximal structures the
    /// implementation can emit guards that this never happens in practice.
    fn assert_seq_len_width3(der: &[u8], what: &str) {
        assert_eq!(
            der[0],
            CertWriter::SEQUENCE_TAG,
            "{what}: expected SEQUENCE tag"
        );
        assert_eq!(
            der[1], 0x82,
            "{what}: outer length byte is {:#04x}, not the 3-byte form (0x82) the \
             deferred-length optimization reserves",
            der[1],
        );
        let len = ((der[2] as usize) << 8) | der[3] as usize;
        assert!(
            (256..=65535).contains(&len),
            "{what}: content length {len} is outside the deferred-length bounds 256..=65535",
        );
    }

    /// The floor of the 3-byte deferred-length assumption.
    ///
    /// Every deferred-length structure contains a TBSCertificate or a
    /// CertificationRequestInfo, so those two are the smallest things the
    /// encoder can emit. Encode both with the most degenerate inputs the API
    /// accepts (1-character issuer CN/serial, 1-character subject serial, no
    /// SAN, not a CA, no recursive support, a single TCI node) and check they
    /// still need the 3-byte length form. Real inputs are strictly larger
    /// (the subject serial alone is `2 * hash_size` hex characters).
    #[test]
    fn test_deferred_length_width_floor() {
        let issuer_der = encode_issuer_der(1, 1);
        let label_bytes = vec![0u8; DPE_PROFILE.hash_size()];
        let contexts = make_test_contexts(1);
        let ski = [0xBBu8; MAX_KEY_IDENTIFIER_SIZE];
        let measurements = MeasurementData {
            label: &label_bytes,
            tci_nodes: TciNodes::new(0, contexts.as_slice()).unwrap(),
            is_ca: false,
            supports_recursive: false,
            subject_key_identifier: ski,
            authority_key_identifier: ski,
            subject_alt_name: None,
        };
        #[allow(unreachable_patterns)]
        let pub_key =
            match DPE_PROFILE {
                #[cfg(feature = "p256")]
                DpeProfile::P256Sha256 => PubKey::Ecdsa(EcdsaPubKey::Ecdsa256(
                    EcdsaPub::from_slice(&[0xAA; ECC_INT_SIZE], &[0xBB; ECC_INT_SIZE]),
                )),
                #[cfg(feature = "p384")]
                DpeProfile::P384Sha384 => PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(
                    EcdsaPub::from_slice(&[0xAA; ECC_INT_SIZE], &[0xBB; ECC_INT_SIZE]),
                )),
                #[cfg(feature = "ml-dsa")]
                DpeProfile::Mldsa87 => PubKey::Mldsa(caliptra_dpe_crypto::ml_dsa::MldsaPublicKey(
                    [0xAA; caliptra_dpe_crypto::ml_dsa::MldsaAlgorithm::Mldsa87.public_key_size()],
                )),
                _ => panic!("unsupported profile"),
            };
        let subject = Name {
            cn: DirectoryString::PrintableString(b"DPE Leaf"),
            serial: DirectoryString::PrintableString(b"0"),
        };

        let mut buf = vec![0u8; 65536];
        let mut sbuf = SliceResponseBuffer::new(&mut buf);
        let n = CertWriter::new(&mut sbuf, DPE_PROFILE, true)
            .encode_tbs(
                TEST_SERIAL,
                &issuer_der,
                &subject,
                &pub_key,
                &measurements,
                &make_validity(false),
            )
            .unwrap();
        assert_seq_len_width3(&buf[..n], "minimal TBSCertificate");

        let mut buf = vec![0u8; 65536];
        let mut sbuf = SliceResponseBuffer::new(&mut buf);
        let n = CertWriter::new(&mut sbuf, DPE_PROFILE, true)
            .encode_certification_request_info(&pub_key, &subject, &measurements)
            .unwrap();
        assert_seq_len_width3(&buf[..n], "minimal CertificationRequestInfo");
    }

    // Expected DER bytes of SEQUENCE { INTEGER(r), INTEGER(s) } for our ECDSA test sig.
    // Both r=[0xCC; ECC_INT_SIZE] and s=[0xDD; ECC_INT_SIZE] have the high bit set,
    // so DER INTEGER encoding prepends 0x00.
    #[cfg(any(feature = "p384", feature = "p256"))]
    fn expected_ecdsa_sig_der() -> Vec<u8> {
        let int_len = ECC_INT_SIZE + 1; // value bytes including 0x00 sign extension
        let seq_content = 4 + 2 * int_len; // two integers: (tag + len + value) * 2
        let mut v = Vec::with_capacity(2 + seq_content);
        v.push(0x30);
        v.push(seq_content as u8);
        // r
        v.push(0x02);
        v.push(int_len as u8);
        v.push(0x00);
        v.extend(std::iter::repeat_n(0xCC, ECC_INT_SIZE));
        // s
        v.push(0x02);
        v.push(int_len as u8);
        v.push(0x00);
        v.extend(std::iter::repeat_n(0xDD, ECC_INT_SIZE));
        v
    }

    // ---- encode_tbs correctness tests ----

    #[cfg(any(feature = "p384", feature = "p256"))]
    fn run_encode_tbs_ecdsa(n_nodes: usize, max_size: bool) {
        let test_pub = EcdsaPub::from_slice(&[0xAA; ECC_INT_SIZE], &[0xBB; ECC_INT_SIZE]);
        let pub_key = match DPE_PROFILE.alg() {
            #[cfg(feature = "p256")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
                PubKey::Ecdsa(EcdsaPubKey::Ecdsa256(test_pub))
            }
            #[cfg(feature = "p384")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
                PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(test_pub))
            }
            _ => panic!("not an ECDSA profile"),
        };

        let serial: Vec<u8> = if max_size {
            vec![0xFF; MAX_SN_SIZE]
        } else {
            TEST_SERIAL.to_vec()
        };

        let (issuer_der, label_bytes, other_name_value) = if max_size {
            let issuer = encode_issuer_der(40, 60);
            let label = vec![0xAB; MAX_UEID_SIZE];
            let other_name: Vec<u8> = std::iter::repeat_n(b'X', MAX_OTHER_NAME_SIZE).collect();
            (issuer, label, other_name)
        } else {
            let issuer = encode_issuer_der(14, DPE_PROFILE.hash_size() * 2);
            let label = vec![0u8; DPE_PROFILE.hash_size()];
            let other_name = DEFAULT_OTHER_NAME_VALUE.as_bytes().to_vec();
            (issuer, label, other_name)
        };

        let contexts = make_test_contexts(n_nodes);
        let ski = [0xBBu8; MAX_KEY_IDENTIFIER_SIZE];
        let mut other_name_av = ArrayVec::new();
        other_name_av
            .try_extend_from_slice(&other_name_value)
            .unwrap();
        let measurements = MeasurementData {
            label: &label_bytes,
            tci_nodes: TciNodes::new(0, contexts.as_slice()).unwrap(),
            is_ca: false,
            supports_recursive: true,
            subject_key_identifier: ski,
            authority_key_identifier: ski,
            subject_alt_name: Some(SubjectAltName::OtherName(OtherName {
                oid: DEFAULT_OTHER_NAME_OID,
                other_name: other_name_av,
            })),
        };
        let validity = make_validity(max_size);

        let mut buf = vec![0u8; 65536];
        let mut sbuf = SliceResponseBuffer::new(&mut buf);
        let mut w = CertWriter::new(&mut sbuf, DPE_PROFILE, true);
        let n = w
            .encode_tbs(
                &serial,
                &issuer_der,
                &TEST_SUBJECT_NAME,
                &pub_key,
                &measurements,
                &validity,
            )
            .unwrap();
        assert_seq_len_width3(&buf[..n], "TBSCertificate");

        let (_, tbs) = TbsCertificate::from_der(&buf[..n])
            .unwrap_or_else(|e| panic!("TbsCertificate::from_der failed: {:?}", e));

        assert_eq!(tbs.version(), X509Version::V3, "version must be V3");

        // Serial: raw_serial() returns the DER INTEGER content, which may include a
        // leading 0x00 sign-extension byte for values with the high bit set.
        assert_eq!(
            strip_der_int_leading_zero(tbs.raw_serial()),
            serial.as_slice(),
        );

        // Subject name round-trips as expected
        let expected_subject = format!(
            "CN={}, serialNumber={}",
            str::from_utf8(TEST_SUBJECT_NAME.cn.bytes()).unwrap(),
            str::from_utf8(TEST_SUBJECT_NAME.serial.bytes()).unwrap(),
        );
        assert_eq!(
            tbs.subject.to_string_with_registry(oid_registry()).unwrap(),
            expected_subject,
        );

        // SPKI round-trips
        SubjectPublicKeyInfo::from_der(tbs.subject_pki.raw)
            .expect("subject_pki must round-trip via SubjectPublicKeyInfo::from_der");

        // DICE UEID extension is present and carries the right label
        let ueid_ext = tbs
            .get_extension_unique(&oid!(2.23.133 .5 .4 .4))
            .unwrap()
            .unwrap_or_else(|| panic!("UEID extension missing"));
        let parsed_ueid = asn1::parse_single::<Ueid>(ueid_ext.value).unwrap();
        assert_eq!(parsed_ueid.ueid, label_bytes.as_slice());

        // At least one tcbInfo extension is present
        assert!(
            tbs.extensions()
                .iter()
                .any(|e| e.oid.to_id_string() == "2.23.133.5.4.5"),
            "tcbInfo extension missing"
        );
    }

    #[cfg(any(feature = "p384", feature = "p256"))]
    #[test]
    fn test_encode_tbs_ecdsa() {
        run_encode_tbs_ecdsa(1, false);
        run_encode_tbs_ecdsa(MAX_HANDLES, true);
    }

    #[cfg(all(feature = "ml-dsa", not(feature = "p384"), not(feature = "p256")))]
    fn run_encode_tbs_mldsa(n_nodes: usize, max_size: bool) {
        const ALGORITHM: MldsaAlgorithm = match DPE_PROFILE.alg() {
            SignatureAlgorithm::Mldsa(a) => a,
            _ => panic!("non-ml-dsa profile in ml-dsa test"),
        };
        let test_pub = MldsaPublicKey::from_slice(&[0xAAu8; ALGORITHM.public_key_size()]);
        let pub_key = PubKey::Mldsa(test_pub);

        let serial: Vec<u8> = if max_size {
            vec![0xFF; MAX_SN_SIZE]
        } else {
            TEST_SERIAL.to_vec()
        };

        let (issuer_der, label_bytes, other_name_value) = if max_size {
            let issuer = encode_issuer_der(40, 60);
            let label = vec![0xAB; MAX_UEID_SIZE];
            let other_name: Vec<u8> = std::iter::repeat_n(b'X', MAX_OTHER_NAME_SIZE).collect();
            (issuer, label, other_name)
        } else {
            let issuer = encode_issuer_der(14, DPE_PROFILE.hash_size() * 2);
            let label = vec![0u8; DPE_PROFILE.hash_size()];
            let other_name = DEFAULT_OTHER_NAME_VALUE.as_bytes().to_vec();
            (issuer, label, other_name)
        };

        let contexts = make_test_contexts(n_nodes);
        let ski = [0xBBu8; MAX_KEY_IDENTIFIER_SIZE];
        let mut other_name_av = ArrayVec::new();
        other_name_av
            .try_extend_from_slice(&other_name_value)
            .unwrap();
        let measurements = MeasurementData {
            label: &label_bytes,
            tci_nodes: TciNodes::new(0, contexts.as_slice()).unwrap(),
            is_ca: false,
            supports_recursive: true,
            subject_key_identifier: ski,
            authority_key_identifier: ski,
            subject_alt_name: Some(SubjectAltName::OtherName(OtherName {
                oid: DEFAULT_OTHER_NAME_OID,
                other_name: other_name_av,
            })),
        };
        let validity = make_validity(max_size);

        let mut buf = vec![0u8; 65536];
        let mut sbuf = SliceResponseBuffer::new(&mut buf);
        let mut w = CertWriter::new(&mut sbuf, DPE_PROFILE, true);
        let n = w
            .encode_tbs(
                &serial,
                &issuer_der,
                &TEST_SUBJECT_NAME,
                &pub_key,
                &measurements,
                &validity,
            )
            .unwrap();
        assert_seq_len_width3(&buf[..n], "TBSCertificate");

        let (_, tbs) = TbsCertificate::from_der(&buf[..n])
            .unwrap_or_else(|e| panic!("TbsCertificate::from_der failed (mldsa): {:?}", e));

        assert_eq!(tbs.version(), X509Version::V3);
        assert_eq!(
            strip_der_int_leading_zero(tbs.raw_serial()),
            serial.as_slice(),
        );

        // Verify ML-DSA signature algorithm OID in TBS
        assert_eq!(
            tbs.signature.algorithm.as_bytes(),
            const_oid::db::fips204::ID_ML_DSA_87.as_bytes()
        );

        SubjectPublicKeyInfo::from_der(tbs.subject_pki.raw).expect("mldsa spki must parse");

        let ueid_ext = tbs
            .get_extension_unique(&oid!(2.23.133 .5 .4 .4))
            .unwrap()
            .unwrap_or_else(|| panic!("UEID extension missing (mldsa)"));
        let parsed_ueid = asn1::parse_single::<Ueid>(ueid_ext.value).unwrap();
        assert_eq!(parsed_ueid.ueid, label_bytes.as_slice());

        assert!(
            tbs.extensions()
                .iter()
                .any(|e| e.oid.to_id_string() == "2.23.133.5.4.5"),
            "tcbInfo extension missing (mldsa)"
        );
    }

    #[cfg(all(feature = "ml-dsa", not(feature = "p384"), not(feature = "p256")))]
    #[test]
    fn test_encode_tbs_mldsa() {
        run_encode_tbs_mldsa(1, false);
        run_encode_tbs_mldsa(MAX_HANDLES, true);
    }

    // ---- encode_certification_request_info correctness tests ----

    // A minimal ASN.1 struct to parse the first three fields of a
    // CertificationRequestInfo SEQUENCE (version, subject, subjectPKInfo).
    // The attributes field at position 4 is captured by a raw Tlv so that
    // parse_single doesn't fail on trailing bytes.
    #[derive(asn1::Asn1Read)]
    struct CertReqInfoParsed<'a> {
        version: u64,
        subject: asn1::Tlv<'a>,
        subject_pki: asn1::Tlv<'a>,
        attributes: asn1::Tlv<'a>,
    }

    #[cfg(any(feature = "p384", feature = "p256"))]
    fn run_encode_cri_ecdsa(n_nodes: usize, max_size: bool) {
        let test_pub = EcdsaPub::from_slice(&[0xAA; ECC_INT_SIZE], &[0xBB; ECC_INT_SIZE]);
        let pub_key = match DPE_PROFILE.alg() {
            #[cfg(feature = "p256")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
                PubKey::Ecdsa(EcdsaPubKey::Ecdsa256(test_pub))
            }
            #[cfg(feature = "p384")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
                PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(test_pub))
            }
            _ => panic!("not an ECDSA profile"),
        };

        let label_bytes: Vec<u8> = if max_size {
            vec![0xAB; MAX_UEID_SIZE]
        } else {
            vec![0u8; DPE_PROFILE.hash_size()]
        };
        let other_name_value: Vec<u8> = if max_size {
            std::iter::repeat_n(b'X', MAX_OTHER_NAME_SIZE).collect()
        } else {
            DEFAULT_OTHER_NAME_VALUE.as_bytes().to_vec()
        };

        let contexts = make_test_contexts(n_nodes);
        let ski = [0xBBu8; MAX_KEY_IDENTIFIER_SIZE];
        let mut other_name_av = ArrayVec::new();
        other_name_av
            .try_extend_from_slice(&other_name_value)
            .unwrap();
        let measurements = MeasurementData {
            label: &label_bytes,
            tci_nodes: TciNodes::new(0, contexts.as_slice()).unwrap(),
            is_ca: false,
            supports_recursive: true,
            subject_key_identifier: ski,
            authority_key_identifier: ski,
            subject_alt_name: Some(SubjectAltName::OtherName(OtherName {
                oid: DEFAULT_OTHER_NAME_OID,
                other_name: other_name_av,
            })),
        };

        let mut buf = vec![0u8; 65536];
        let mut sbuf = SliceResponseBuffer::new(&mut buf);
        let mut w = CertWriter::new(&mut sbuf, DPE_PROFILE, true);
        let n = w
            .encode_certification_request_info(&pub_key, &TEST_SUBJECT_NAME, &measurements)
            .unwrap();
        assert_seq_len_width3(&buf[..n], "CertificationRequestInfo");

        let cri = asn1::parse_single::<CertReqInfoParsed>(&buf[..n])
            .unwrap_or_else(|e| panic!("CertReqInfo parse failed (ecdsa): {:?}", e));

        assert_eq!(cri.version, 0, "CRI version must be 0");

        // Subject must be parseable as an X509Name
        let (_, subject_name) = X509Name::from_der(cri.subject.full_data())
            .expect("CRI subject must parse as X509Name");
        let expected_subject = format!(
            "CN={}, serialNumber={}",
            str::from_utf8(TEST_SUBJECT_NAME.cn.bytes()).unwrap(),
            str::from_utf8(TEST_SUBJECT_NAME.serial.bytes()).unwrap(),
        );
        assert_eq!(
            subject_name
                .to_string_with_registry(oid_registry())
                .unwrap(),
            expected_subject,
        );

        // subjectPKInfo must be parseable
        SubjectPublicKeyInfo::from_der(cri.subject_pki.full_data())
            .expect("CRI subjectPKInfo must parse");

        // attributes field must start with [0] IMPLICIT context tag (0xA0)
        assert_eq!(
            cri.attributes.full_data()[0],
            0xA0,
            "attributes must start with [0] context tag"
        );

        // UEID OID bytes must appear within the attributes
        let ueid_oid_bytes: &[u8] = &[0x67, 0x81, 0x05, 0x05, 0x04, 0x04];
        assert!(
            cri.attributes
                .full_data()
                .windows(ueid_oid_bytes.len())
                .any(|w| w == ueid_oid_bytes),
            "UEID OID not found in CRI attributes"
        );
    }

    #[cfg(any(feature = "p384", feature = "p256"))]
    #[test]
    fn test_encode_cri_ecdsa() {
        run_encode_cri_ecdsa(1, false);
        run_encode_cri_ecdsa(MAX_HANDLES, true);
    }

    #[cfg(all(feature = "ml-dsa", not(feature = "p384"), not(feature = "p256")))]
    fn run_encode_cri_mldsa(n_nodes: usize, max_size: bool) {
        const ALGORITHM: MldsaAlgorithm = match DPE_PROFILE.alg() {
            SignatureAlgorithm::Mldsa(a) => a,
            _ => panic!("non-ml-dsa profile in ml-dsa test"),
        };
        let test_pub = MldsaPublicKey::from_slice(&[0xAAu8; ALGORITHM.public_key_size()]);
        let pub_key = PubKey::Mldsa(test_pub);

        let label_bytes: Vec<u8> = if max_size {
            vec![0xAB; MAX_UEID_SIZE]
        } else {
            vec![0u8; DPE_PROFILE.hash_size()]
        };
        let other_name_value: Vec<u8> = if max_size {
            std::iter::repeat_n(b'X', MAX_OTHER_NAME_SIZE).collect()
        } else {
            DEFAULT_OTHER_NAME_VALUE.as_bytes().to_vec()
        };

        let contexts = make_test_contexts(n_nodes);
        let ski = [0xBBu8; MAX_KEY_IDENTIFIER_SIZE];
        let mut other_name_av = ArrayVec::new();
        other_name_av
            .try_extend_from_slice(&other_name_value)
            .unwrap();
        let measurements = MeasurementData {
            label: &label_bytes,
            tci_nodes: TciNodes::new(0, contexts.as_slice()).unwrap(),
            is_ca: false,
            supports_recursive: true,
            subject_key_identifier: ski,
            authority_key_identifier: ski,
            subject_alt_name: Some(SubjectAltName::OtherName(OtherName {
                oid: DEFAULT_OTHER_NAME_OID,
                other_name: other_name_av,
            })),
        };

        let mut buf = vec![0u8; 65536];
        let mut sbuf = SliceResponseBuffer::new(&mut buf);
        let mut w = CertWriter::new(&mut sbuf, DPE_PROFILE, true);
        let n = w
            .encode_certification_request_info(&pub_key, &TEST_SUBJECT_NAME, &measurements)
            .unwrap();
        assert_seq_len_width3(&buf[..n], "CertificationRequestInfo");

        let cri = asn1::parse_single::<CertReqInfoParsed>(&buf[..n])
            .unwrap_or_else(|e| panic!("CertReqInfo parse failed (mldsa): {:?}", e));

        assert_eq!(cri.version, 0);
        X509Name::from_der(cri.subject.full_data()).expect("mldsa CRI subject must parse");
        SubjectPublicKeyInfo::from_der(cri.subject_pki.full_data())
            .expect("mldsa CRI subjectPKInfo must parse");
        assert_eq!(cri.attributes.full_data()[0], 0xA0);

        let ueid_oid_bytes: &[u8] = &[0x67, 0x81, 0x05, 0x05, 0x04, 0x04];
        assert!(
            cri.attributes
                .full_data()
                .windows(ueid_oid_bytes.len())
                .any(|w| w == ueid_oid_bytes),
            "UEID OID not found in mldsa CRI attributes"
        );
    }

    #[cfg(all(feature = "ml-dsa", not(feature = "p384"), not(feature = "p256")))]
    #[test]
    fn test_encode_cri_mldsa() {
        run_encode_cri_mldsa(1, false);
        run_encode_cri_mldsa(MAX_HANDLES, true);
    }

    // ---- encode_csr correctness tests ----

    #[cfg(any(feature = "p384", feature = "p256"))]
    fn run_encode_csr_ecdsa(n_nodes: usize, max_size: bool) {
        let test_pub = EcdsaPub::from_slice(&[0xAA; ECC_INT_SIZE], &[0xBB; ECC_INT_SIZE]);
        let pub_key = match DPE_PROFILE.alg() {
            #[cfg(feature = "p256")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
                PubKey::Ecdsa(EcdsaPubKey::Ecdsa256(test_pub))
            }
            #[cfg(feature = "p384")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
                PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(test_pub))
            }
            _ => panic!("not an ECDSA profile"),
        };
        let test_sig = match DPE_PROFILE.alg() {
            #[cfg(feature = "p256")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => Signature::Ecdsa(
                EcdsaSig::from_slice(&[0xCC; ECC_INT_SIZE], &[0xDD; ECC_INT_SIZE]).into(),
            ),
            #[cfg(feature = "p384")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => Signature::Ecdsa(
                EcdsaSig::from_slice(&[0xCC; ECC_INT_SIZE], &[0xDD; ECC_INT_SIZE]).into(),
            ),
            _ => panic!("not an ECDSA profile"),
        };
        let mut sign_cb = |_buf: &dyn ResponseBuffer,
                           _range: core::ops::Range<usize>,
                           _use_derived: bool,
                           out: &mut Signature| {
            *out = test_sig.clone();
            Ok(())
        };
        let mut sig = test_sig.clone();

        let label_bytes: Vec<u8> = if max_size {
            vec![0xAB; MAX_UEID_SIZE]
        } else {
            vec![0u8; DPE_PROFILE.hash_size()]
        };
        let other_name_value: Vec<u8> = if max_size {
            std::iter::repeat_n(b'X', MAX_OTHER_NAME_SIZE).collect()
        } else {
            DEFAULT_OTHER_NAME_VALUE.as_bytes().to_vec()
        };

        let contexts = make_test_contexts(n_nodes);
        let ski = [0xBBu8; MAX_KEY_IDENTIFIER_SIZE];
        let mut other_name_av = ArrayVec::new();
        other_name_av
            .try_extend_from_slice(&other_name_value)
            .unwrap();
        let measurements = MeasurementData {
            label: &label_bytes,
            tci_nodes: TciNodes::new(0, contexts.as_slice()).unwrap(),
            is_ca: false,
            supports_recursive: true,
            subject_key_identifier: ski,
            authority_key_identifier: ski,
            subject_alt_name: Some(SubjectAltName::OtherName(OtherName {
                oid: DEFAULT_OTHER_NAME_OID,
                other_name: other_name_av,
            })),
        };

        let mut buf = vec![0u8; 65536];
        let mut sbuf = SliceResponseBuffer::new(&mut buf);
        let mut w = CertWriter::new(&mut sbuf, DPE_PROFILE, true);
        let n = w
            .encode_csr(
                &mut sign_cb,
                &pub_key,
                &TEST_SUBJECT_NAME,
                &measurements,
                &mut sig,
            )
            .unwrap();

        let (_, csr) = X509CertificationRequest::from_der(&buf[..n])
            .unwrap_or_else(|e| panic!("CSR parse failed (ecdsa): {:?}", e));
        let cri = &csr.certification_request_info;

        assert_eq!(cri.version.0, 0, "CRI version must be 0");

        // Signature algorithm OID
        let expected_sig_alg = match DPE_PROFILE.alg() {
            #[cfg(feature = "p256")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => "1.2.840.10045.4.3.2",
            #[cfg(feature = "p384")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => "1.2.840.10045.4.3.3",
            _ => panic!("not an ECDSA profile"),
        };
        assert_eq!(
            csr.signature_algorithm.algorithm.to_id_string(),
            expected_sig_alg,
        );

        // Signature value: BIT STRING content must be DER SEQUENCE { INTEGER(r), INTEGER(s) }
        assert_eq!(
            csr.signature_value.data.as_ref(),
            expected_ecdsa_sig_der().as_slice(),
        );

        // Subject round-trips
        let expected_subject = format!(
            "CN={}, serialNumber={}",
            str::from_utf8(TEST_SUBJECT_NAME.cn.bytes()).unwrap(),
            str::from_utf8(TEST_SUBJECT_NAME.serial.bytes()).unwrap(),
        );
        assert_eq!(
            cri.subject.to_string_with_registry(oid_registry()).unwrap(),
            expected_subject,
        );

        // DICE UEID extension in requested extensions
        assert!(
            csr.requested_extensions()
                .map(|mut it| it.any(|_| true))
                .unwrap_or(false),
            "CSR must have requested extensions"
        );
    }

    #[cfg(any(feature = "p384", feature = "p256"))]
    #[test]
    fn test_encode_csr_ecdsa() {
        run_encode_csr_ecdsa(1, false);
        run_encode_csr_ecdsa(MAX_HANDLES, true);
    }

    #[cfg(all(feature = "ml-dsa", not(feature = "p384"), not(feature = "p256")))]
    fn run_encode_csr_mldsa(n_nodes: usize, max_size: bool) {
        const ALGORITHM: MldsaAlgorithm = match DPE_PROFILE.alg() {
            SignatureAlgorithm::Mldsa(a) => a,
            _ => panic!("non-ml-dsa profile in ml-dsa test"),
        };
        let test_pub = MldsaPublicKey::from_slice(&[0xAAu8; ALGORITHM.public_key_size()]);
        let pub_key = PubKey::Mldsa(test_pub);
        let test_sig = Signature::Mldsa(MldsaSignature([0xBBu8; ALGORITHM.signature_size()]));
        let mut sign_cb = |_buf: &dyn ResponseBuffer,
                           _range: core::ops::Range<usize>,
                           _use_derived: bool,
                           out: &mut Signature| {
            *out = test_sig.clone();
            Ok(())
        };
        let mut sig = test_sig.clone();

        let label_bytes: Vec<u8> = if max_size {
            vec![0xAB; MAX_UEID_SIZE]
        } else {
            vec![0u8; DPE_PROFILE.hash_size()]
        };
        let other_name_value: Vec<u8> = if max_size {
            std::iter::repeat_n(b'X', MAX_OTHER_NAME_SIZE).collect()
        } else {
            DEFAULT_OTHER_NAME_VALUE.as_bytes().to_vec()
        };

        let contexts = make_test_contexts(n_nodes);
        let ski = [0xBBu8; MAX_KEY_IDENTIFIER_SIZE];
        let mut other_name_av = ArrayVec::new();
        other_name_av
            .try_extend_from_slice(&other_name_value)
            .unwrap();
        let measurements = MeasurementData {
            label: &label_bytes,
            tci_nodes: TciNodes::new(0, contexts.as_slice()).unwrap(),
            is_ca: false,
            supports_recursive: true,
            subject_key_identifier: ski,
            authority_key_identifier: ski,
            subject_alt_name: Some(SubjectAltName::OtherName(OtherName {
                oid: DEFAULT_OTHER_NAME_OID,
                other_name: other_name_av,
            })),
        };

        let mut buf = vec![0u8; 65536];
        let mut sbuf = SliceResponseBuffer::new(&mut buf);
        let mut w = CertWriter::new(&mut sbuf, DPE_PROFILE, true);
        let n = w
            .encode_csr(
                &mut sign_cb,
                &pub_key,
                &TEST_SUBJECT_NAME,
                &measurements,
                &mut sig,
            )
            .unwrap();

        let (_, csr) = X509CertificationRequest::from_der(&buf[..n])
            .unwrap_or_else(|e| panic!("CSR parse failed (mldsa): {:?}", e));
        let cri = &csr.certification_request_info;

        assert_eq!(cri.version.0, 0);
        assert_eq!(
            csr.signature_algorithm.algorithm.as_bytes(),
            const_oid::db::fips204::ID_ML_DSA_87.as_bytes()
        );

        // Signature value: BIT STRING content is raw ML-DSA bytes
        assert_eq!(
            csr.signature_value.data.as_ref(),
            &[0xBBu8; ALGORITHM.signature_size()][..],
        );

        assert!(
            csr.requested_extensions()
                .map(|mut it| it.any(|_| true))
                .unwrap_or(false),
            "mldsa CSR must have requested extensions"
        );
    }

    #[cfg(all(feature = "ml-dsa", not(feature = "p384"), not(feature = "p256")))]
    #[test]
    fn test_encode_csr_mldsa() {
        run_encode_csr_mldsa(1, false);
        run_encode_csr_mldsa(MAX_HANDLES, true);
    }

    // ---- encode_signer_info correctness tests ----

    #[cfg(any(feature = "p384", feature = "p256"))]
    fn run_encode_signer_info_ecdsa(
        issuer_der: &[u8],
        serial: &[u8],
        ski_bytes: &[u8; MAX_KEY_IDENTIFIER_SIZE],
    ) {
        let test_sig = match DPE_PROFILE.alg() {
            #[cfg(feature = "p256")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => Signature::Ecdsa(
                EcdsaSig::from_slice(&[0xCC; ECC_INT_SIZE], &[0xDD; ECC_INT_SIZE]).into(),
            ),
            #[cfg(feature = "p384")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => Signature::Ecdsa(
                EcdsaSig::from_slice(&[0xCC; ECC_INT_SIZE], &[0xDD; ECC_INT_SIZE]).into(),
            ),
            _ => panic!("not an ECDSA profile"),
        };

        let expected_sig_alg = match DPE_PROFILE.alg() {
            #[cfg(feature = "p256")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => "1.2.840.10045.4.3.2",
            #[cfg(feature = "p384")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => "1.2.840.10045.4.3.3",
            _ => panic!("not an ECDSA profile"),
        };
        let expected_hash_alg = match DPE_PROFILE.alg() {
            #[cfg(feature = "p256")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => "2.16.840.1.101.3.4.2.1",
            #[cfg(feature = "p384")]
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => "2.16.840.1.101.3.4.2.2",
            _ => panic!("not an ECDSA profile"),
        };

        // -- IssuerAndSerialNumber variant --
        let mut isn_name = ArrayVec::new();
        isn_name.try_extend_from_slice(issuer_der).unwrap();
        let mut isn_serial = ArrayVec::new();
        isn_serial.try_extend_from_slice(serial).unwrap();
        let sid_isn = SignerIdentifier::IssuerAndSerialNumber {
            issuer_name: isn_name,
            serial_number: isn_serial,
        };

        let mut buf = vec![0u8; 65536];
        let mut sbuf = SliceResponseBuffer::new(&mut buf);
        let mut w = CertWriter::new(&mut sbuf, DPE_PROFILE, true);
        let n = w.encode_signer_info(&test_sig, &sid_isn).unwrap();

        let si = CmsSignerInfo::from_der(&buf[..n])
            .unwrap_or_else(|e| panic!("SignerInfo (ISN) parse failed (ecdsa): {:?}", e));

        assert_eq!(
            si.version,
            CmsVersion::V1,
            "IssuerAndSerialNumber → version 1"
        );
        assert_eq!(
            si.signature_algorithm.oid,
            ObjectIdentifier::new_unwrap(expected_sig_alg)
        );
        assert!(si
            .digest_alg
            .assert_algorithm_oid(ObjectIdentifier::new_unwrap(expected_hash_alg))
            .is_ok());
        assert_eq!(si.signature.as_bytes(), expected_ecdsa_sig_der().as_slice());

        // Verify the ISN fields
        match &si.sid {
            CmsSignerIdentifier::IssuerAndSerialNumber(isn) => {
                // serial_number.as_bytes() includes a leading 0x00 for DER INTEGER
                // sign-extension when the high bit is set; strip it before comparing.
                assert_eq!(
                    strip_der_int_leading_zero(isn.serial_number.as_bytes()),
                    serial,
                );
                let issuer_der_roundtrip = isn.issuer.to_der().unwrap();
                assert_eq!(issuer_der_roundtrip.as_slice(), issuer_der);
            }
            _ => panic!("expected IssuerAndSerialNumber SignerIdentifier"),
        }

        // -- SubjectKeyIdentifier variant --
        let mut ski_av = ArrayVec::new();
        ski_av.try_extend_from_slice(ski_bytes).unwrap();
        let sid_ski = SignerIdentifier::SubjectKeyIdentifier(ski_av);

        let mut buf2 = vec![0u8; 65536];
        let mut sbuf2 = SliceResponseBuffer::new(&mut buf2);
        let mut w2 = CertWriter::new(&mut sbuf2, DPE_PROFILE, true);
        let n2 = w2.encode_signer_info(&test_sig, &sid_ski).unwrap();

        let si2 = CmsSignerInfo::from_der(&buf2[..n2])
            .unwrap_or_else(|e| panic!("SignerInfo (SKI) parse failed (ecdsa): {:?}", e));

        assert_eq!(
            si2.version,
            CmsVersion::V3,
            "SubjectKeyIdentifier → version 3"
        );
        assert_eq!(
            si2.signature_algorithm.oid,
            ObjectIdentifier::new_unwrap(expected_sig_alg)
        );
        assert_eq!(
            si2.signature.as_bytes(),
            expected_ecdsa_sig_der().as_slice()
        );

        match &si2.sid {
            CmsSignerIdentifier::SubjectKeyIdentifier(ski) => {
                // Our encoder places the OCTET STRING TLV inside the [0] context tag
                // (tag 0x04 + 1-byte length + value bytes). Skip those 2 prefix bytes.
                let raw = ski.0.as_bytes();
                assert_eq!(&raw[2..], ski_bytes);
            }
            _ => panic!("expected SubjectKeyIdentifier SignerIdentifier"),
        }
    }

    #[cfg(any(feature = "p384", feature = "p256"))]
    #[test]
    fn test_encode_signer_info_ecdsa() {
        // Typical case: small issuer name that fits within MAX_ISSUER_NAME_SIZE=128
        let issuer_der_typical = encode_issuer_der(14, 20);
        let serial_typical = TEST_SERIAL.to_vec();
        let ski_typical = [0x11u8; MAX_KEY_IDENTIFIER_SIZE];
        run_encode_signer_info_ecdsa(&issuer_der_typical, &serial_typical, &ski_typical);

        // Max case: larger issuer name (still fits in 128), max-sized serial, max key-id
        // encode_issuer_der(40, 50) produces ~114 bytes DER < MAX_ISSUER_NAME_SIZE=128
        let issuer_der_max = encode_issuer_der(40, 50);
        let serial_max = vec![0xFF; MAX_SN_SIZE];
        let ski_max = [0xFFu8; MAX_KEY_IDENTIFIER_SIZE];
        run_encode_signer_info_ecdsa(&issuer_der_max, &serial_max, &ski_max);
    }

    #[cfg(all(feature = "ml-dsa", not(feature = "p384"), not(feature = "p256")))]
    fn run_encode_signer_info_mldsa(
        issuer_der: &[u8],
        serial: &[u8],
        ski_bytes: &[u8; MAX_KEY_IDENTIFIER_SIZE],
    ) {
        const ALGORITHM: MldsaAlgorithm = match DPE_PROFILE.alg() {
            SignatureAlgorithm::Mldsa(a) => a,
            _ => panic!("non-ml-dsa profile in ml-dsa test"),
        };
        let test_sig = Signature::Mldsa(MldsaSignature([0xBBu8; ALGORITHM.signature_size()]));

        // -- IssuerAndSerialNumber variant --
        let mut isn_name = ArrayVec::new();
        isn_name.try_extend_from_slice(issuer_der).unwrap();
        let mut isn_serial = ArrayVec::new();
        isn_serial.try_extend_from_slice(serial).unwrap();
        let sid_isn = SignerIdentifier::IssuerAndSerialNumber {
            issuer_name: isn_name,
            serial_number: isn_serial,
        };

        let mut buf = vec![0u8; 1_048_576]; // MLDSA sig is large
        let mut sbuf = SliceResponseBuffer::new(&mut buf);
        let mut w = CertWriter::new(&mut sbuf, DPE_PROFILE, true);
        let n = w.encode_signer_info(&test_sig, &sid_isn).unwrap();

        let si = CmsSignerInfo::from_der(&buf[..n])
            .unwrap_or_else(|e| panic!("SignerInfo (ISN/mldsa) parse failed: {:?}", e));

        assert_eq!(si.version, CmsVersion::V1);
        assert_eq!(
            si.signature_algorithm.oid,
            ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19")
        );
        assert_eq!(
            si.signature.as_bytes(),
            &[0xBBu8; ALGORITHM.signature_size()][..]
        );

        match &si.sid {
            CmsSignerIdentifier::IssuerAndSerialNumber(isn) => {
                assert_eq!(
                    strip_der_int_leading_zero(isn.serial_number.as_bytes()),
                    serial,
                );
            }
            _ => panic!("expected IssuerAndSerialNumber for mldsa"),
        }

        // -- SubjectKeyIdentifier variant --
        let mut ski_av = ArrayVec::new();
        ski_av.try_extend_from_slice(ski_bytes).unwrap();
        let sid_ski = SignerIdentifier::SubjectKeyIdentifier(ski_av);

        let mut buf2 = vec![0u8; 1_048_576];
        let mut sbuf2 = SliceResponseBuffer::new(&mut buf2);
        let mut w2 = CertWriter::new(&mut sbuf2, DPE_PROFILE, true);
        let n2 = w2.encode_signer_info(&test_sig, &sid_ski).unwrap();

        let si2 = CmsSignerInfo::from_der(&buf2[..n2])
            .unwrap_or_else(|e| panic!("SignerInfo (SKI/mldsa) parse failed: {:?}", e));

        assert_eq!(si2.version, CmsVersion::V3);
        assert_eq!(
            si2.signature.as_bytes(),
            &[0xBBu8; ALGORITHM.signature_size()][..]
        );

        match &si2.sid {
            CmsSignerIdentifier::SubjectKeyIdentifier(ski) => {
                let raw = ski.0.as_bytes();
                assert_eq!(&raw[2..], ski_bytes);
            }
            _ => panic!("expected SubjectKeyIdentifier for mldsa"),
        }
    }

    #[cfg(all(feature = "ml-dsa", not(feature = "p384"), not(feature = "p256")))]
    #[test]
    fn test_encode_signer_info_mldsa() {
        let issuer_der_typical = encode_issuer_der(14, 20);
        let serial_typical = TEST_SERIAL.to_vec();
        let ski_typical = [0x11u8; MAX_KEY_IDENTIFIER_SIZE];
        run_encode_signer_info_mldsa(&issuer_der_typical, &serial_typical, &ski_typical);

        let issuer_der_max = encode_issuer_der(40, 60);
        let serial_max = vec![0xFF; MAX_SN_SIZE];
        let ski_max = [0xFFu8; MAX_KEY_IDENTIFIER_SIZE];
        run_encode_signer_info_mldsa(&issuer_der_max, &serial_max, &ski_max);
    }

    /// Golden X.509 / CSR regression smoke tests.
    ///
    /// A golden certificate and CSR are checked in as fixed, "known-good" DER
    /// artifacts under `src/x509_testdata/`. These are treated as immutable
    /// inputs: the tests only *parse* and *validate* them. They are never
    /// regenerated by tests; if a golden must ever change, it is produced by
    /// the independent OpenSSL-based xtask (see `src/x509_testdata/README.md`).
    ///
    /// The parsed certificate is self-signed with the subject's own key, so its
    /// signature can be verified against the public key embedded in the
    /// certificate itself.
    #[cfg(not(feature = "disable_x509"))]
    mod golden {
        use super::*;
        use caliptra_dpe_dice_asn1::{
            GoldenDefinitions, GoldenProfile, TcbInfo as DiceTcbInfo, Ueid as DiceUeid,
        };
        use std::str::FromStr;
        use x509_parser::oid_registry::asn1_rs::Oid;

        #[cfg(feature = "p256")]
        const GOLDEN_CERT_DER: &[u8] = include_bytes!("x509_testdata/golden_cert_p256.der");
        #[cfg(feature = "p384")]
        const GOLDEN_CERT_DER: &[u8] = include_bytes!("x509_testdata/golden_cert_p384.der");
        #[cfg(all(feature = "ml-dsa", not(feature = "p384"), not(feature = "p256")))]
        const GOLDEN_CERT_DER: &[u8] = include_bytes!("x509_testdata/golden_cert_mldsa87.der");

        #[cfg(feature = "p256")]
        const GOLDEN_CSR_DER: &[u8] = include_bytes!("x509_testdata/golden_csr_p256.der");
        #[cfg(feature = "p384")]
        const GOLDEN_CSR_DER: &[u8] = include_bytes!("x509_testdata/golden_csr_p384.der");
        #[cfg(all(feature = "ml-dsa", not(feature = "p384"), not(feature = "p256")))]
        const GOLDEN_CSR_DER: &[u8] = include_bytes!("x509_testdata/golden_csr_mldsa87.der");

        fn golden_definitions() -> GoldenDefinitions {
            #[cfg(feature = "p256")]
            let profile = GoldenProfile::P256;
            #[cfg(feature = "p384")]
            let profile = GoldenProfile::P384;
            #[cfg(all(feature = "ml-dsa", not(feature = "p384"), not(feature = "p256")))]
            let profile = GoldenProfile::Mldsa87;
            profile.into()
        }

        #[cfg(any(feature = "p256", feature = "p384"))]
        const X509_UNCOMPRESSED_HEADER: u8 = 0x04;

        fn golden_pubkey(cert: &X509Certificate) -> PubKey {
            let raw = cert.public_key().subject_public_key.data.as_ref();
            match DPE_PROFILE.alg() {
                #[cfg(any(feature = "p256", feature = "p384"))]
                SignatureAlgorithm::Ecdsa(_) => {
                    assert_eq!(raw[0], X509_UNCOMPRESSED_HEADER);

                    match DPE_PROFILE {
                        #[cfg(feature = "p256")]
                        DpeProfile::P256Sha256 => {
                            let cs = EcdsaAlgorithm::Bit256.curve_size();
                            PubKey::Ecdsa(EcdsaPubKey::Ecdsa256(EcdsaPub::from_slice(
                                raw[1..1 + cs].try_into().unwrap(),
                                raw[1 + cs..1 + cs + cs].try_into().unwrap(),
                            )))
                        }
                        #[cfg(feature = "p384")]
                        DpeProfile::P384Sha384 => {
                            let cs = EcdsaAlgorithm::Bit384.curve_size();
                            PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(EcdsaPub::from_slice(
                                raw[1..1 + cs].try_into().unwrap(),
                                raw[1 + cs..1 + cs + cs].try_into().unwrap(),
                            )))
                        }
                        #[allow(unreachable_patterns)]
                        _ => unreachable!(),
                    }
                }
                #[cfg(all(feature = "ml-dsa", not(feature = "p384"), not(feature = "p256")))]
                SignatureAlgorithm::Mldsa(MldsaAlgorithm::Mldsa87) => {
                    PubKey::Mldsa(MldsaPublicKey::from_slice(raw.try_into().unwrap()))
                }
                #[allow(unreachable_patterns)]
                _ => unreachable!(),
            }
        }

        fn golden_signature(cert: &X509Certificate) -> Signature {
            let raw = cert.signature_value.data.as_ref();
            #[cfg(any(feature = "p256", feature = "p384"))]
            if matches!(DPE_PROFILE.alg(), SignatureAlgorithm::Ecdsa(_)) {
                let parsed = openssl::ecdsa::EcdsaSig::from_der(raw).unwrap();
                let pad = |value: Vec<u8>, size: usize| {
                    let mut padded = vec![0u8; size];
                    padded[size - value.len()..].copy_from_slice(&value);
                    padded
                };
                return match DPE_PROFILE {
                    #[cfg(feature = "p256")]
                    DpeProfile::P256Sha256 => {
                        let r = pad(parsed.r().to_vec(), 32);
                        let s = pad(parsed.s().to_vec(), 32);
                        Signature::Ecdsa(
                            EcdsaSig::<32>::from_slice(
                                r.as_slice().try_into().unwrap(),
                                s.as_slice().try_into().unwrap(),
                            )
                            .into(),
                        )
                    }
                    #[cfg(feature = "p384")]
                    DpeProfile::P384Sha384 => {
                        let r = pad(parsed.r().to_vec(), 48);
                        let s = pad(parsed.s().to_vec(), 48);
                        Signature::Ecdsa(
                            EcdsaSig::<48>::from_slice(
                                r.as_slice().try_into().unwrap(),
                                s.as_slice().try_into().unwrap(),
                            )
                            .into(),
                        )
                    }
                    #[allow(unreachable_patterns)]
                    _ => unreachable!(),
                };
            }
            #[cfg(all(feature = "ml-dsa", not(feature = "p384"), not(feature = "p256")))]
            return Signature::Mldsa(MldsaSignature(raw.try_into().unwrap()));
            #[allow(unreachable_code)]
            {
                unreachable!()
            }
        }

        /// Parse the golden certificate, verify its self-signature, and assert
        /// on its structure and DICE / TCI extensions.
        #[test]
        #[cfg_attr(miri, ignore)]
        fn test_golden_cert() {
            let definitions = golden_definitions();
            // Parses as a valid X.509v3 certificate.
            let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
            let (_, cert) = parser
                .parse(GOLDEN_CERT_DER)
                .unwrap_or_else(|e| panic!("golden cert failed to parse: {e:?}"));
            assert_eq!(cert.version().0, definitions.certificate_version as u32);

            // Signature verifies against the certificate's own public key
            // (the golden cert is self-signed).
            let openssl_cert = openssl::x509::X509::from_der(GOLDEN_CERT_DER).unwrap();
            let pkey = openssl_cert.public_key().unwrap();
            assert!(
                openssl_cert.verify(&pkey).unwrap(),
                "golden certificate signature failed to verify",
            );

            // DICE UEID extension (tcg-dice-Ueid 2.23.133.5.4.4): critical, with
            // the fixed all-zero label.
            let ueid_oid = Oid::from_str(definitions.ueid.oid.dotted).unwrap();
            let ueid = cert
                .get_extension_unique(&ueid_oid)
                .unwrap()
                .expect("missing DICE UEID extension");
            assert_eq!(ueid.critical, definitions.ueid.critical);
            let parsed_ueid = asn1::parse_single::<DiceUeid>(ueid.value).unwrap();
            assert_eq!(parsed_ueid.ueid.len(), definitions.hash_size);
            assert!(parsed_ueid
                .ueid
                .iter()
                .all(|byte| *byte == definitions.ueid_fill));

            // DICE MultiTcbInfo extension (tcg-dice-MultiTcbInfo 2.23.133.5.4.5):
            // exactly one TcbInfo whose single FWID is the all-zero measurement.
            let tcb_oid = Oid::from_str(definitions.multi_tcb_info.oid.dotted).unwrap();
            let tcb = cert
                .get_extension_unique(&tcb_oid)
                .unwrap()
                .expect("missing DICE MultiTcbInfo extension");
            assert_eq!(tcb.critical, definitions.multi_tcb_info.critical);
            let tcb_infos = asn1::parse_single::<asn1::SequenceOf<DiceTcbInfo>>(tcb.value).unwrap();
            let expected_hash_oid =
                asn1::ObjectIdentifier::from_string(definitions.hash_oid.dotted).unwrap();
            let mut count = 0usize;
            for info in tcb_infos {
                count += 1;
                let fwids = info.fwids.expect("TcbInfo must carry FWIDs");
                let mut fwid_count = 0usize;
                for fwid in fwids {
                    fwid_count += 1;
                    assert_eq!(fwid.hash_alg, expected_hash_oid);
                    assert_eq!(fwid.digest.len(), definitions.hash_size);
                    assert!(fwid
                        .digest
                        .iter()
                        .all(|byte| *byte == definitions.fwid_digest_fill));
                }
                assert_eq!(fwid_count, definitions.fwids_per_tcb_info);
            }
            assert_eq!(count, definitions.tcb_info_count);
        }

        /// Rebuild the golden certificate with DPE's custom DER writer. The
        /// golden public key and signature are reused so this comparison tests
        /// the certificate encoding rather than a second crypto implementation.
        #[test]
        #[cfg_attr(miri, ignore)]
        fn test_encode_golden_cert() {
            let definitions = golden_definitions();
            let (_, golden) = X509CertificateParser::new()
                .with_deep_parse_extensions(true)
                .parse(GOLDEN_CERT_DER)
                .unwrap();
            let pub_key = golden_pubkey(&golden);
            let golden_sig = golden_signature(&golden);

            let subject = Name {
                cn: DirectoryString::Utf8String(definitions.subject_common_name.as_bytes()),
                serial: DirectoryString::PrintableString(definitions.csr_subject_serial.as_bytes()),
            };
            let mut issuer_der = [0u8; 128];
            let mut issuer_buf = SliceResponseBuffer::new(&mut issuer_der);
            let issuer_len = CertWriter::new(&mut issuer_buf, DPE_PROFILE, true)
                .encode_rdn(&subject)
                .unwrap();

            let mut context = Context {
                state: ContextState::Active,
                ..Context::default()
            };
            context.tci.svn = definitions.svn;
            context.tci.locality = definitions.locality;
            context.tci.tci_type = definitions.tci_type;
            let contexts = [context];

            let mut key_identifier = [0u8; MAX_KEY_IDENTIFIER_SIZE];
            let authority_key_identifier = golden
                .get_extension_unique(&oid!(2.5.29 .35))
                .unwrap()
                .expect("golden certificate must contain an authority key identifier");
            let ParsedExtension::AuthorityKeyIdentifier(authority_key_identifier) =
                authority_key_identifier.parsed_extension()
            else {
                panic!("golden authority key identifier has the wrong extension type");
            };
            key_identifier
                .copy_from_slice(authority_key_identifier.key_identifier.clone().unwrap().0);

            let label = vec![definitions.ueid_fill; definitions.hash_size];
            let measurements = MeasurementData {
                label: &label,
                tci_nodes: TciNodes::new(0, &contexts).unwrap(),
                is_ca: definitions.is_ca,
                supports_recursive: definitions.supports_recursive,
                subject_key_identifier: key_identifier,
                authority_key_identifier: key_identifier,
                subject_alt_name: None,
            };
            let mut not_before = ArrayVec::new();
            not_before
                .try_extend_from_slice(definitions.not_before.as_bytes())
                .unwrap();
            let mut not_after = ArrayVec::new();
            not_after
                .try_extend_from_slice(definitions.not_after.as_bytes())
                .unwrap();
            let validity = CertValidity {
                not_before,
                not_after,
            };

            let mut encoded = vec![0u8; GOLDEN_CERT_DER.len() + 32];
            let mut encoded_buf = SliceResponseBuffer::new(&mut encoded);
            let callback_sig = golden_sig.clone();
            let mut sign_cb = move |_buf: &dyn ResponseBuffer,
                                    _range: core::ops::Range<usize>,
                                    _is_csr: bool,
                                    output: &mut Signature| {
                *output = callback_sig.clone();
                Ok(())
            };
            let mut sig = golden_sig;
            let encoded_len = CertWriter::new(&mut encoded_buf, DPE_PROFILE, true)
                .encode_certificate(
                    &mut sign_cb,
                    &[0],
                    &issuer_der[..issuer_len],
                    &subject,
                    &pub_key,
                    &measurements,
                    &validity,
                    &mut sig,
                )
                .unwrap();

            assert_eq!(&encoded[..encoded_len], GOLDEN_CERT_DER);
        }

        /// Parse the golden CSR and verify its self-signature.
        #[test]
        #[cfg_attr(miri, ignore)]
        fn test_golden_csr() {
            let definitions = golden_definitions();
            // Parses as a valid PKCS#10 certification request.
            let (_, csr) = X509CertificationRequest::from_der(GOLDEN_CSR_DER)
                .unwrap_or_else(|e| panic!("golden CSR failed to parse: {e:?}"));
            assert_eq!(
                csr.certification_request_info.version.0,
                definitions.csr_version as u32
            );

            // Self-signature verifies against the CSR's own public key.
            let openssl_csr = openssl::x509::X509Req::from_der(GOLDEN_CSR_DER).unwrap();
            let pkey = openssl_csr.public_key().unwrap();
            assert!(
                openssl_csr.verify(&pkey).unwrap(),
                "golden CSR signature failed to verify",
            );

            // The CSR carries requested extensions (DICE data).
            assert!(
                csr.requested_extensions()
                    .map(|mut it| it.any(|_| true))
                    .unwrap_or(false),
                "golden CSR must have requested extensions",
            );
        }
    }
}
