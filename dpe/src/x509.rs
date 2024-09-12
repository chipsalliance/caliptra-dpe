// Licensed under the Apache-2.0 license;

//! Lightweight X.509 encoding routines for DPE
//!
//! DPE requires encoding variable-length certificates. This module provides
//! this functionality for a no_std environment.

use crate::{
    response::DpeErrorCode,
    tci::{TciMeasurement, TciNodeData},
    DpeProfile, DPE_PROFILE, MAX_HANDLES,
};
use bitflags::bitflags;
use core::cmp::Ordering;
use crypto::{EcdsaPub, EcdsaSig, EncodedEcdsaPub};
use der::{
    asn1, Choice, Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader,
    Sequence, Tag, ValueOrd, Writer,
};
#[cfg(not(feature = "disable_x509"))]
use platform::CertValidity;
#[cfg(not(feature = "disable_csr"))]
use platform::SignerIdentifier;
use platform::{SubjectAltName, MAX_KEY_IDENTIFIER_SIZE};
use zerocopy::AsBytes;

// For errors which come from lower layers, include the error code returned
// from platform libraries.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
pub enum X509Error {
    InvalidRawDer = 0x1,
    DerLengthError = 0x2,
    RangeError = 0x3,
    InvalidOid = 0x4,
    NonPrintableString = 0x5,
    Utf8Error = 0x6,
    IntError = 0x7,
}

impl X509Error {
    pub fn discriminant(&self) -> u16 {
        // SAFETY: Because `Self` is marked `repr(u16)`, its layout is a `repr(C)` `union`
        // between `repr(C)` structs, each of which has the `u16` discriminant as its first
        // field, so we can read the discriminant without offsetting the pointer.
        unsafe { *<*const _>::from(self).cast::<u16>() }
    }

    pub fn get_error_detail(&self) -> Option<u32> {
        None
    }
}

/// Type for specifying an X.509 RelativeDistinguisedName
///
/// `serial` is expected to hold a hex string of the hash of the public key
pub struct Name<'a> {
    pub cn: &'a [u8],
    pub serial: &'a [u8],
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
    offset: usize,
    crit_dice: bool,
}

/// TBSCertificate  ::=  SEQUENCE  {
///        version         [0]  EXPLICIT Version DEFAULT v1,
///        serialNumber         CertificateSerialNumber,
///        signature            AlgorithmIdentifier,
///        issuer               Name,
///        validity             Validity,
///        subject              Name,
///        subjectPublicKeyInfo SubjectPublicKeyInfo,
///        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
///                             -- If present, version MUST be v2 or v3
///        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
///                             -- If present, version MUST be v2 or v3
///        extensions      [3]  EXPLICIT Extensions OPTIONAL
///                             -- If present, version MUST be v3
///        }
#[derive(Sequence)]
pub struct EcdsaTbsCertificate<'a> {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "false")]
    pub version: u64,
    pub serial_number: asn1::UintRef<'a>,
    pub signature_alg: AlgorithmIdentifier,
    pub issuer_name: RawDerSequenceRef<'a>,
    pub validity: Validity<'a>,
    pub subject_name: RelativeDistinguishedName<'a>,
    pub subject_pubkey_info: SubjectPublicKeyInfo<'a>,
    // This DPE implementation currently supports 8 extensions
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub extensions: Option<DpeExtensions<'a>>,
}

pub struct RawDerSequenceRef<'a> {
    val: &'a [u8],
}

impl<'a> RawDerSequenceRef<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, DpeErrorCode> {
        // Skip header
        let mut reader = der::SliceReader::new(data)
            .map_err(|_| DpeErrorCode::from(X509Error::InvalidRawDer))?;
        let header = Header::decode(&mut reader)
            .map_err(|_| DpeErrorCode::from(X509Error::InvalidRawDer))?;
        let len: usize = header
            .length
            .try_into()
            .map_err(|_| DpeErrorCode::from(X509Error::InvalidRawDer))?;
        let offset = reader
            .position()
            .try_into()
            .map_err(|_| DpeErrorCode::from(X509Error::InvalidRawDer))?;

        Ok(Self {
            val: &data[offset..offset + len],
        })
    }
}

impl<'a> EncodeValue for RawDerSequenceRef<'a> {
    fn value_len(&self) -> Result<Length, der::Error> {
        self.val.len().try_into()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), der::Error> {
        writer.write(self.val)?;
        Ok(())
    }
}

impl<'a> DecodeValue<'a> for RawDerSequenceRef<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self, der::Error> {
        let val = reader.read_slice(header.length)?;
        // PANIC FREE: val is guaranteed to be 4 bytes
        Ok(Self { val })
    }
}

// In places where RawDerSequenceRef is used in a SetOf, it is the only entry
impl ValueOrd for RawDerSequenceRef<'_> {
    fn value_cmp(&self, _other: &Self) -> Result<Ordering, der::Error> {
        Ok(Ordering::Equal)
    }
}

impl<'a> FixedTag for RawDerSequenceRef<'a> {
    const TAG: Tag = Tag::Sequence;
}

pub struct DpeExtensions<'a>(pub asn1::SequenceOf<Extension<'a>, 8>);

impl<'a> Sequence<'a> for DpeExtensions<'a> {}

impl<'a> DecodeValue<'a> for DpeExtensions<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self, der::Error> {
        Ok(DpeExtensions(
            asn1::SequenceOf::<Extension<'a>, 8>::decode_value(reader, header)?,
        ))
    }
}

impl EncodeValue for DpeExtensions<'_> {
    // Required methods
    fn value_len(&self) -> Result<Length, der::Error> {
        self.0.value_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> Result<(), der::Error> {
        self.0.encode_value(encoder)
    }
}

// This is necessary because extensions are stored in a SetOf for PKCS#10 CSRs.
// However there will only ever be one extension, so it is okay to return a
// constant ordering.
impl ValueOrd for DpeExtensions<'_> {
    fn value_cmp(&self, _other: &Self) -> Result<Ordering, der::Error> {
        Ok(Ordering::Equal)
    }
}

#[derive(Sequence)]
pub struct Validity<'a> {
    not_before: RawGeneralizedTimeRef<'a>,
    not_after: RawGeneralizedTimeRef<'a>,
}

pub struct U32OctetString(u32);

impl U32OctetString {
    const LENGTH: usize = 4;
}

impl FixedTag for U32OctetString {
    const TAG: Tag = Tag::OctetString;
}

impl EncodeValue for U32OctetString {
    fn value_len(&self) -> Result<Length, der::Error> {
        Self::LENGTH.try_into()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), der::Error> {
        writer.write(&self.0.to_be_bytes())?;
        Ok(())
    }
}

impl<'a> DecodeValue<'a> for U32OctetString {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> Result<Self, der::Error> {
        let val = reader.read_slice(Self::LENGTH.try_into()?)?;
        // PANIC FREE: val is guaranteed to be 4 bytes
        Ok(Self(u32::from_be_bytes(val.try_into().unwrap())))
    }
}

struct RawGeneralizedTimeRef<'a> {
    time: &'a [u8],
}

impl<'a> RawGeneralizedTimeRef<'a> {
    /// Length of an RFC 5280-flavored ASN.1 DER-encoded [`GeneralizedTime`].
    const LENGTH: usize = 15;

    pub fn new(bytes: &'a [u8]) -> Result<Self, DpeErrorCode> {
        if bytes.len() != Self::LENGTH {
            return Err(DpeErrorCode::InternalError);
        }

        Ok(Self { time: bytes })
    }
}

impl EncodeValue for RawGeneralizedTimeRef<'_> {
    fn value_len(&self) -> Result<Length, der::Error> {
        self.time.len().try_into()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), der::Error> {
        writer.write(self.time)?;
        Ok(())
    }
}

impl<'a> DecodeValue<'a> for RawGeneralizedTimeRef<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> Result<Self, der::Error> {
        let time = reader.read_slice(Self::LENGTH.try_into()?)?;
        Ok(Self { time })
    }
}

impl FixedTag for RawGeneralizedTimeRef<'_> {
    const TAG: Tag = Tag::GeneralizedTime;
}

// Wraps any asn1 encodable/decodable type and encodes/decodes it as an octet
// sring
pub struct OctetStringContainer<T>(T);

impl<'a, T> EncodeValue for OctetStringContainer<T>
where
    T: der::Encode + der::Decode<'a>,
{
    fn value_len(&self) -> Result<Length, der::Error> {
        self.0.encoded_len()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), der::Error> {
        self.0.encode(writer)
    }
}

impl<'a, T> DecodeValue<'a> for OctetStringContainer<T>
where
    T: der::Encode + der::Decode<'a>,
{
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> Result<Self, der::Error> {
        Ok(OctetStringContainer::<T>(T::decode(reader)?))
    }
}

impl<'a, T> FixedTag for OctetStringContainer<T>
where
    T: der::Encode + der::Decode<'a>,
{
    const TAG: Tag = Tag::OctetString;
}

impl<T> ValueOrd for OctetStringContainer<T>
where
    T: der::ValueOrd,
{
    fn value_cmp(&self, other: &Self) -> Result<Ordering, der::Error> {
        self.0.value_cmp(&other.0)
    }
}

// Wraps any asn1 encodable/decodable type and encodes/decodes it as an octet
// sring
pub struct BitStringContainer<T>(T);

impl<'a, T> EncodeValue for BitStringContainer<T>
where
    T: der::Encode + der::Decode<'a>,
{
    fn value_len(&self) -> Result<Length, der::Error> {
        // Add 1 for unused bits
        Ok(self.0.encoded_len()?.saturating_add(Length::ONE))
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), der::Error> {
        // Write unused bits
        writer.write_byte(0u8)?;
        self.0.encode(writer)
    }
}

impl<'a, T> DecodeValue<'a> for BitStringContainer<T>
where
    T: der::Encode + der::Decode<'a>,
{
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> Result<Self, der::Error> {
        // Unused bits must be 0 for BitStringContainers. Skip unused bits byte.
        reader.read_byte()?;
        Ok(BitStringContainer::<T>(T::decode(reader)?))
    }
}

impl<'a, T> FixedTag for BitStringContainer<T>
where
    T: der::Encode + der::Decode<'a>,
{
    const TAG: Tag = Tag::BitString;
}

#[derive(Choice)]
pub enum GeneralName<'a> {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    OtherName(DerOtherName<'a>),
}

pub type DerSubjectAltName<'a> = asn1::SequenceOf<GeneralName<'a>, 1>;

#[derive(Choice)]
#[allow(clippy::large_enum_variant)]
pub enum ExtensionVal<'a> {
    AuthorityKeyIdentifier(OctetStringContainer<AuthorityKeyIdentifier<'a>>),
    OctetString(OctetStringContainer<asn1::OctetStringRef<'a>>),
    MultiTcbInfo(OctetStringContainer<MultiTcbInfo<'a>>),
    Ueid(OctetStringContainer<Ueid<'a>>),
    ExtendedKeyUsage(OctetStringContainer<ExtendedKeyUsage>),
    BasicConstraints(OctetStringContainer<BasicConstraints>),
    BitString(OctetStringContainer<asn1::BitStringRef<'a>>),
    OtherName(OctetStringContainer<DerSubjectAltName<'a>>),
}

#[derive(Sequence)]
pub struct Extension<'a> {
    pub oid: asn1::ObjectIdentifier,
    pub critical: bool,
    pub value: ExtensionVal<'a>,
}

#[derive(Sequence)]
pub struct Pkcs10CsrInfo<'a> {
    pub version: u64,
    pub subject: RelativeDistinguishedName<'a>,
    pub subject_pubkey_info: SubjectPublicKeyInfo<'a>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "false")]
    pub attributes: CsrAttributes<'a>,
}

/// CertificateRequest  ::=  SEQUENCE  {
///    certificationRequestInfo       CertificationRequestInfo,
///    signatureAlgorithm             AlgorithmIdentifier,
///    signatureValue                 BIT STRING
/// }
#[derive(Sequence)]
pub struct Pkcs10Csr<'a> {
    pub info: RawDerSequenceRef<'a>,
    pub sig_alg: AlgorithmIdentifier,
    pub sig: BitStringContainer<DerEcdsaSignature<'a>>,
}

/// SignedData  ::=  SEQUENCE  {
///    version CMSVersion,
///    digestAlgorithms DigestAlgorithmIdentifiers,
///    encapContentInfo EncapsulatedContentInfo,
///    certificates [0] IMPLICIT CertificateSet OPTIONAL,
///    crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
///    signerInfos SignerInfos
/// }
///
/// certificates and crls are not supported
#[derive(Sequence)]
pub struct CmsSignedData<'a> {
    version: u64,
    digest_algs: asn1::SetOf<AlgorithmIdentifier, 1>,
    encap_content_info: EncapContentInfo<'a>,
    signer_infos: asn1::SetOf<SignerInfo<'a>, 1>,
}

/// ContentInfo  ::=  SEQUENCE  {
///    contentType ContentType,
///    content [0] EXPLICIT ANY DEFINED BY contentType
/// }
#[derive(Sequence)]
pub struct CmsContentInfo<'a> {
    content_type: asn1::ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "false")]
    content: CmsSignedData<'a>,
}

/// SEQUENCE {
///     version CMSVersion,
///     sid SignerIdentifier,
///     digestAlgorithm DigestAlgorithmIdentifier,
///     signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
///     signatureAlgorithm SignatureAlgorithmIdentifier,
///     signature SignatureValue,
///     unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
///
/// The following are not supported
/// * signedAttrs
/// * unsigedAttrs
#[derive(Sequence, ValueOrd)]
pub struct SignerInfo<'a> {
    pub version: u64,
    pub sid: DerSignerIdentifier<'a>,
    pub digest_alg: AlgorithmIdentifier,
    pub sig_alg: AlgorithmIdentifier,
    pub signature: OctetStringContainer<DerEcdsaSignature<'a>>,
}

#[derive(Choice, ValueOrd)]
pub enum DerSignerIdentifier<'a> {
    IssuerAndSerialNumber(IssuerAndSerialNumber<'a>),
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "false")]
    SubjectKeyIdentifier(asn1::OctetStringRef<'a>),
}

/// IssuerAndSerialNumber ::= SEQUENCE {
///     issuer Name,
///     serialNumber CertificateSerialNumber }
#[derive(Sequence, ValueOrd)]
pub struct IssuerAndSerialNumber<'a> {
    pub issuer: RawDerSequenceRef<'a>,
    pub serial: asn1::UintRef<'a>,
}

#[derive(Sequence, ValueOrd)]
pub struct DerEcdsaSignature<'a> {
    pub r: asn1::UintRef<'a>,
    pub s: asn1::UintRef<'a>,
}

/// EncapsulatedContentInfo ::= SEQUENCE {
///     eContentType ContentType,
///     eContent [0] EXPLICIT OCTET STRING OPTIONAL }
#[derive(Sequence)]
pub struct EncapContentInfo<'a> {
    content_type: asn1::ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    content: Option<asn1::OctetStringRef<'a>>,
}

/// Attributes ::= SET OF Attribute
///
/// Attribute ::= SEQUENCE {
///    attrType OBJECT IDENTIFIER,
///    attrValues SET OF AttributeValue
/// }
///
/// AttributeValue ::= ANY -- Defined by attribute type
pub type CsrAttributes<'a> = asn1::SetOf<CsrAttribute<'a>, 1>;

#[derive(Choice, ValueOrd)]
pub enum CsrAttributeValue<'a> {
    Extensions(DpeExtensions<'a>),
}

#[derive(Sequence, ValueOrd)]
pub struct CsrAttribute<'a> {
    attr_type: asn1::ObjectIdentifier,
    // Only supported CSR attribute is X.509 Extensions
    attr_values: asn1::SetOf<CsrAttributeValue<'a>, 1>,
}

// DPE only supports one EKU OID
pub type ExtendedKeyUsage = asn1::SequenceOf<asn1::ObjectIdentifier, 1>;

pub type RelativeDistinguishedName<'a> =
    asn1::SequenceOf<asn1::SetOf<AttributeTypeAndValue<'a>, 1>, 2>;

#[derive(Sequence, ValueOrd)]
pub struct AttributeTypeAndValue<'a> {
    pub attr_type: asn1::ObjectIdentifier,
    pub value: asn1::PrintableStringRef<'a>,
}

///// Certificate  ::=  SEQUENCE  {
/////    tbsCertificate       TBSCertificate,
/////    signatureAlgorithm   AlgorithmIdentifier,
/////    signatureValue       BIT STRING  }
#[derive(Sequence)]
pub struct EcdsaCertificate<'a> {
    pub tbs: RawDerSequenceRef<'a>,
    pub alg_id: AlgorithmIdentifier,
    pub signature: BitStringContainer<DerEcdsaSignature<'a>>,
}

#[derive(Sequence)]
pub struct SubjectPublicKeyInfo<'a> {
    pub alg: AlgorithmIdentifier,
    pub pub_key: asn1::BitStringRef<'a>,
}

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
#[derive(Sequence, ValueOrd)]
pub struct AlgorithmIdentifier {
    pub algorithm: asn1::ObjectIdentifier,
    #[asn1(optional = "true")]
    pub parameters: Option<AlgorithmParameters>,
}

#[derive(Choice, ValueOrd)]
pub enum AlgorithmParameters {
    // Curve
    Ecdsa(asn1::ObjectIdentifier),
}

// DER structures for extensions

#[derive(Sequence)]
pub struct Ueid<'a> {
    pub ueid: asn1::OctetStringRef<'a>,
}

#[derive(Sequence)]
pub struct BasicConstraints {
    ca: bool,
    #[asn1(optional = "true")]
    pathlen: Option<u64>,
}

// Only supported option for SubjectAltName
#[derive(Sequence)]
pub struct DerOtherName<'a> {
    pub type_id: asn1::ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub value: Option<asn1::Utf8StringRef<'a>>,
}

#[derive(Sequence)]
pub struct DerFwid<'a> {
    pub hash_alg: asn1::ObjectIdentifier,
    pub digest: asn1::OctetStringRef<'a>,
}

pub type MultiTcbInfo<'a> = asn1::SequenceOf<DerTcbInfo<'a>, MAX_HANDLES>;

#[derive(Sequence)]
pub struct DerTcbInfo<'a> {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    _vendor: Option<asn1::Utf8StringRef<'a>>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    _model: Option<asn1::Utf8StringRef<'a>>,
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    _version: Option<asn1::Utf8StringRef<'a>>,
    #[asn1(context_specific = "3", tag_mode = "IMPLICIT", optional = "true")]
    _svn: Option<u64>,
    #[asn1(context_specific = "4", tag_mode = "IMPLICIT", optional = "true")]
    _layer: Option<u64>,
    #[asn1(context_specific = "5", tag_mode = "IMPLICIT", optional = "true")]
    _index: Option<u64>,
    #[asn1(context_specific = "6", tag_mode = "IMPLICIT", optional = "true")]
    pub fwids: Option<asn1::SequenceOf<DerFwid<'a>, 2>>,
    #[asn1(context_specific = "7", tag_mode = "IMPLICIT", optional = "true")]
    _flags: Option<asn1::BitStringRef<'a>>,
    #[asn1(context_specific = "8", tag_mode = "IMPLICIT", optional = "true")]
    pub vendor_info: Option<U32OctetString>,
    #[asn1(context_specific = "9", tag_mode = "IMPLICIT", optional = "true")]
    pub tci_type: Option<U32OctetString>,
}

impl<'a> DerTcbInfo<'a> {
    pub fn new(
        fwids: asn1::SequenceOf<DerFwid<'a>, 2>,
        vendor_info: u32,
        tci_type: u32,
    ) -> DerTcbInfo<'a> {
        Self {
            _vendor: None,
            _model: None,
            _version: None,
            _svn: None,
            _layer: None,
            _index: None,
            fwids: Some(fwids),
            _flags: None,
            vendor_info: Some(U32OctetString(vendor_info)),
            tci_type: Some(U32OctetString(tci_type)),
        }
    }
}

// Unsupported fields:
// * authorityCertIssuer
// * authorityCertSerialNumber
#[derive(Sequence)]
pub struct AuthorityKeyIdentifier<'a> {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    key_identifier: Option<asn1::OctetStringRef<'a>>,
}

#[derive(AsBytes)]
#[repr(C)]
pub struct KeyUsageFlags(u8);

bitflags! {
    impl KeyUsageFlags: u8 {
        const DIGITAL_SIGNATURE = 0b1000_0000;
        const KEY_CERT_SIGN = 0b0000_0100;

        // KeyCertSign | DigitalSignature
        const ECA_FLAGS = 0b1000_0000 | 0b0000_0100;
    }
}

impl CertWriter<'_> {
    const X509_V3: u64 = 2;
    #[cfg(not(feature = "disable_csr"))]
    const CMS_V1: u64 = 1;
    #[cfg(not(feature = "disable_csr"))]
    const CMS_V3: u64 = 3;
    #[cfg(not(feature = "disable_csr"))]
    const CSR_V0: u64 = 0;

    const ECDSA_OID: asn1::ObjectIdentifier = match DPE_PROFILE {
        // ECDSA with SHA256
        DpeProfile::P256Sha256 => asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
        // ECDSA with SHA384
        DpeProfile::P384Sha384 => asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"),
    };

    const EC_PUB_OID: asn1::ObjectIdentifier =
        asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

    const CURVE_OID: asn1::ObjectIdentifier = match DPE_PROFILE {
        // P256
        DpeProfile::P256Sha256 => asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7"),
        // P384
        DpeProfile::P384Sha384 => asn1::ObjectIdentifier::new_unwrap("1.3.132.0.34"),
    };

    const HASH_OID: asn1::ObjectIdentifier = match DPE_PROFILE {
        // SHA256
        DpeProfile::P256Sha256 => asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
        // SHA384
        DpeProfile::P384Sha384 => asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2"),
    };

    const RDN_COMMON_NAME_OID: asn1::ObjectIdentifier =
        asn1::ObjectIdentifier::new_unwrap("2.5.4.3");
    const RDN_SERIALNUMBER_OID: asn1::ObjectIdentifier =
        asn1::ObjectIdentifier::new_unwrap("2.5.4.5");

    // tcg-dice-MultiTcbInfo 2.23.133.5.4.5
    const MULTI_TCBINFO_OID: asn1::ObjectIdentifier =
        asn1::ObjectIdentifier::new_unwrap("2.23.133.5.4.5");

    // tcg-dice-Ueid 2.23.133.5.4.4
    const UEID_OID: asn1::ObjectIdentifier = asn1::ObjectIdentifier::new_unwrap("2.23.133.5.4.4");

    // tcg-dice-kp-eca 2.23.133.5.4.100.12
    const ECA_OID: asn1::ObjectIdentifier =
        asn1::ObjectIdentifier::new_unwrap("2.23.133.5.4.100.12");

    // tcg-dice-kp-attestLoc 2.23.133.5.4.100.9
    const ATTEST_LOC_OID: asn1::ObjectIdentifier =
        asn1::ObjectIdentifier::new_unwrap("2.23.133.5.4.100.9");

    // RFC 5280 2.5.29.19
    const BASIC_CONSTRAINTS_OID: asn1::ObjectIdentifier =
        asn1::ObjectIdentifier::new_unwrap("2.5.29.19");

    // RFC 5280 2.5.29.15
    const KEY_USAGE_OID: asn1::ObjectIdentifier = asn1::ObjectIdentifier::new_unwrap("2.5.29.15");

    // RFC 5280 2.5.29.37
    const EXTENDED_KEY_USAGE_OID: asn1::ObjectIdentifier =
        asn1::ObjectIdentifier::new_unwrap("2.5.29.37");

    // RFC 5280 2.5.29.14
    const SUBJECT_KEY_IDENTIFIER_OID: asn1::ObjectIdentifier =
        asn1::ObjectIdentifier::new_unwrap("2.5.29.14");

    // RFC 5280 2.5.29.35
    const AUTHORITY_KEY_IDENTIFIER_OID: asn1::ObjectIdentifier =
        asn1::ObjectIdentifier::new_unwrap("2.5.29.35");

    // RFC 5280 2.5.29.17
    const SUBJECT_ALTERNATIVE_NAME_OID: asn1::ObjectIdentifier =
        asn1::ObjectIdentifier::new_unwrap("2.5.29.17");

    // RFC 5652 1.2.840.113549.1.7.2
    #[cfg(not(feature = "disable_csr"))]
    const ID_SIGNED_DATA_OID: asn1::ObjectIdentifier =
        asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

    // RFC 5652 1.2.840.113549.1.7.1
    #[cfg(not(feature = "disable_csr"))]
    const ID_DATA_OID: asn1::ObjectIdentifier =
        asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

    // RFC 2985 1.2.840.113549.1.9.14
    #[cfg(not(feature = "disable_csr"))]
    const EXTENSION_REQUEST_OID: asn1::ObjectIdentifier =
        asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.14");

    /// Build new CertWriter that writes output to `cert`
    ///
    /// If `crit_dice`, all tcg-dice-* extensions will be marked as critical.
    /// Else they will be marked as non-critical.
    pub fn new(cert: &mut [u8], crit_dice: bool) -> CertWriter {
        CertWriter {
            certificate: cert,
            offset: 0,
            crit_dice,
        }
    }

    pub fn encode_der(&mut self, val: &impl Encode) -> Result<usize, DpeErrorCode> {
        // PANIC FREE: Full cert length is always less than usize max
        let size: usize = val
            .encoded_len()
            .map_err(|_| X509Error::DerLengthError)?
            .try_into()
            .unwrap();
        val.encode_to_slice(
            self.certificate
                .get_mut(self.offset..self.offset + size)
                .ok_or(X509Error::RangeError)?,
        )
        .map_err(|_| X509Error::RangeError)?;
        self.offset += size;

        Ok(size)
    }

    pub fn get_rdn<'a>(name: &'a Name) -> Result<RelativeDistinguishedName<'a>, DpeErrorCode> {
        let cn = AttributeTypeAndValue {
            attr_type: Self::RDN_COMMON_NAME_OID,
            value: asn1::PrintableStringRef::new(name.cn)
                .map_err(|_| X509Error::NonPrintableString)?,
        };
        let sn = AttributeTypeAndValue {
            attr_type: Self::RDN_SERIALNUMBER_OID,
            value: asn1::PrintableStringRef::new(name.serial)
                .map_err(|_| X509Error::NonPrintableString)?,
        };

        // PANIC FREE: Sets/sequences are fixed size and number of additions are
        // hard-coded
        let mut cn_set = asn1::SetOf::<AttributeTypeAndValue, 1>::new();
        cn_set.insert(cn).unwrap();
        let mut sn_set = asn1::SetOf::<AttributeTypeAndValue, 1>::new();
        sn_set.insert(sn).unwrap();
        let mut rdn = RelativeDistinguishedName::new();
        rdn.add(cn_set).unwrap();
        rdn.add(sn_set).unwrap();

        Ok(rdn)
    }

    // Encode ASN.1 Validity according to Platform
    #[cfg(not(feature = "disable_x509"))]
    fn get_validity<'a>(
        &mut self,
        validity: &'a CertValidity,
    ) -> Result<Validity<'a>, DpeErrorCode> {
        let nb = RawGeneralizedTimeRef::new(validity.not_before.as_slice())
            .map_err(|_| DpeErrorCode::InternalError)?;
        let na = RawGeneralizedTimeRef::new(validity.not_after.as_slice())
            .map_err(|_| DpeErrorCode::InternalError)?;

        Ok(Validity {
            not_before: nb,
            not_after: na,
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
    fn get_ecdsa_subject_pubkey_info(
        pubkey: &EncodedEcdsaPub,
    ) -> Result<SubjectPublicKeyInfo, DpeErrorCode> {
        let alg_id = AlgorithmIdentifier {
            algorithm: Self::EC_PUB_OID,
            parameters: Some(AlgorithmParameters::Ecdsa(Self::CURVE_OID)),
        };

        Ok(SubjectPublicKeyInfo {
            alg: alg_id,
            pub_key: asn1::BitStringRef::new(0, pubkey.0.as_slice())
                .map_err(|_| X509Error::RangeError)?,
        })
    }

    fn get_fwid(tci: &TciMeasurement) -> Result<DerFwid, DpeErrorCode> {
        Ok(DerFwid {
            hash_alg: Self::HASH_OID,
            digest: asn1::OctetStringRef::new(&tci.0).map_err(|_| X509Error::RangeError)?,
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
    fn get_tcb_info<'a>(
        node: &'a TciNodeData,
        supports_recursive: bool,
    ) -> Result<DerTcbInfo<'a>, DpeErrorCode> {
        // PANIC FREE: Number of SequenceOf additions is hard-coded
        let mut fwids = asn1::SequenceOf::<DerFwid<'a>, 2>::new();

        // fwid[0] current measurement
        fwids.add(Self::get_fwid(&node.tci_current)?).unwrap();

        // fwid[1] journey measurement
        // Omit fwid[1] from tcb_info if DPE_PROFILE does not support recursive
        if supports_recursive {
            fwids.add(Self::get_fwid(&node.tci_cumulative)?).unwrap();
        }

        Ok(DerTcbInfo::new(fwids, node.locality, node.tci_type))
    }

    /// Get a tcg-dice-MultiTcbInfo extension
    ///
    /// https://trustedcomputinggroup.org/wp-content/uploads/TCG_DICE_Attestation_Architecture_r22_02dec2020.pdf
    fn get_multi_tcb_info<'a>(
        &self,
        measurements: &'a MeasurementData,
    ) -> Result<Extension<'a>, DpeErrorCode> {
        let mut mti = MultiTcbInfo::new();
        for node in measurements.tci_nodes {
            mti.add(Self::get_tcb_info(node, measurements.supports_recursive)?)
                .map_err(|_| DpeErrorCode::InternalError)?;
        }

        Ok(Extension {
            oid: Self::MULTI_TCBINFO_OID,
            critical: self.crit_dice,
            value: ExtensionVal::MultiTcbInfo(OctetStringContainer::<MultiTcbInfo>(mti)),
        })
    }

    /// Encode a tcg-dice-Ueid extension
    ///
    /// https://trustedcomputinggroup.org/wp-content/uploads/TCG_DICE_Attestation_Architecture_r22_02dec2020.pdf
    fn get_ueid<'a>(
        &self,
        measurements: &'a MeasurementData,
    ) -> Result<Extension<'a>, DpeErrorCode> {
        let ueid = Ueid {
            ueid: asn1::OctetStringRef::new(measurements.label)
                .map_err(|_| X509Error::RangeError)?,
        };
        Ok(Extension {
            oid: Self::UEID_OID,
            critical: self.crit_dice,
            value: ExtensionVal::Ueid(OctetStringContainer(ueid)),
        })
    }

    /// Encode a BasicConstraints extension
    ///
    /// https://datatracker.ietf.org/doc/html/rfc5280
    fn get_basic_constraints<'a>(
        measurements: &MeasurementData,
    ) -> Result<Extension<'a>, DpeErrorCode> {
        let bc = BasicConstraints {
            ca: measurements.is_ca,
            pathlen: None,
        };

        Ok(Extension {
            oid: Self::BASIC_CONSTRAINTS_OID,
            critical: true,
            value: ExtensionVal::BasicConstraints(OctetStringContainer(bc)),
        })
    }

    /// Encode a KeyUsage extension
    ///
    /// https://datatracker.ietf.org/doc/html/rfc5280
    fn get_key_usage<'a>(is_ca: bool) -> Result<Extension<'a>, DpeErrorCode> {
        // Count trailing bits in KeyUsage byte as unused
        let bitstring = if is_ca {
            asn1::BitStringRef::new(2, KeyUsageFlags::ECA_FLAGS.as_bytes())
                .map_err(|_| X509Error::RangeError)?
        } else {
            asn1::BitStringRef::new(7, KeyUsageFlags::DIGITAL_SIGNATURE.as_bytes())
                .map_err(|_| X509Error::RangeError)?
        };

        Ok(Extension {
            oid: Self::KEY_USAGE_OID,
            critical: true,
            value: ExtensionVal::BitString(OctetStringContainer(bitstring)),
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
    fn get_extended_key_usage<'a>(
        measurements: &MeasurementData,
    ) -> Result<Extension<'a>, DpeErrorCode> {
        let policy_oid = if measurements.is_ca {
            Self::ECA_OID
        } else {
            Self::ATTEST_LOC_OID
        };

        // PANIC FREE: Number of additions hard-coded
        let mut eku = ExtendedKeyUsage::new();
        eku.add(policy_oid).unwrap();

        Ok(Extension {
            oid: Self::EXTENDED_KEY_USAGE_OID,
            critical: true,
            value: ExtensionVal::ExtendedKeyUsage(OctetStringContainer(eku)),
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
    fn get_subject_alt_name_extension<'a>(
        measurements: &'a MeasurementData,
    ) -> Result<Extension<'a>, DpeErrorCode> {
        match &measurements.subject_alt_name {
            None => Err(DpeErrorCode::InternalError),
            Some(SubjectAltName::OtherName(other_name)) => {
                let mut san = DerSubjectAltName::new();
                // PANIC FREE: number of SequenceOf additions are hard-coded
                san.add(GeneralName::OtherName(DerOtherName {
                    type_id: asn1::ObjectIdentifier::from_bytes(other_name.oid)
                        .map_err(|_| X509Error::InvalidOid)?,
                    value: Some(
                        asn1::Utf8StringRef::new(other_name.other_name.as_slice())
                            .map_err(|_| X509Error::Utf8Error)?,
                    ),
                }))
                .unwrap();
                Ok(Extension {
                    oid: Self::SUBJECT_ALTERNATIVE_NAME_OID,
                    critical: false,
                    value: ExtensionVal::OtherName(OctetStringContainer(san)),
                })
            }
        }
    }

    /// AuthorityKeyIdentifier ::= SEQUENCE {
    ///     keyIdentifier             [0] KeyIdentifier           OPTIONAL,
    ///     authorityCertIssuer       [1] GeneralNames            OPTIONAL,
    ///     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL
    /// }
    fn get_authority_key_identifier_extension<'a>(
        measurements: &'a MeasurementData,
    ) -> Result<Extension<'a>, DpeErrorCode> {
        Ok(Extension {
            oid: Self::AUTHORITY_KEY_IDENTIFIER_OID,
            critical: false,
            value: ExtensionVal::AuthorityKeyIdentifier(OctetStringContainer(
                AuthorityKeyIdentifier {
                    key_identifier: Some(
                        asn1::OctetStringRef::new(&measurements.authority_key_identifier)
                            .map_err(|_| X509Error::RangeError)?,
                    ),
                },
            )),
        })
    }

    fn get_subject_key_identifier_extension<'a>(
        measurements: &'a MeasurementData,
    ) -> Result<Extension<'a>, DpeErrorCode> {
        Ok(Extension {
            oid: Self::SUBJECT_KEY_IDENTIFIER_OID,
            critical: false,
            value: ExtensionVal::OctetString(OctetStringContainer(
                asn1::OctetStringRef::new(&measurements.subject_key_identifier)
                    .map_err(|_| X509Error::RangeError)?,
            )),
        })
    }

    fn get_extensions<'a>(
        &mut self,
        measurements: &'a MeasurementData,
        is_x509: bool,
    ) -> Result<DpeExtensions<'a>, DpeErrorCode> {
        // PANIC FREE: Number of SequenceOf additions hard-coded
        let mut extensions = DpeExtensions(asn1::SequenceOf::<Extension, 8>::new());
        extensions
            .0
            .add(self.get_multi_tcb_info(measurements)?)
            .unwrap();
        extensions
            .0
            .add(Self::get_extended_key_usage(measurements)?)
            .unwrap();
        extensions.0.add(self.get_ueid(measurements)?).unwrap();
        extensions
            .0
            .add(Self::get_basic_constraints(measurements)?)
            .unwrap();
        extensions
            .0
            .add(Self::get_key_usage(measurements.is_ca)?)
            .unwrap();

        if measurements.is_ca && is_x509 {
            extensions
                .0
                .add(Self::get_subject_key_identifier_extension(measurements)?)
                .unwrap();
            extensions
                .0
                .add(Self::get_authority_key_identifier_extension(measurements)?)
                .unwrap();
        }

        match &measurements.subject_alt_name {
            Some(SubjectAltName::OtherName(_)) => {
                extensions
                    .0
                    .add(Self::get_subject_alt_name_extension(measurements)?)
                    .unwrap();
            }
            None => { /* do nothing */ }
        }

        Ok(extensions)
    }

    /// Gets an integer representing the CMS version which is dependent on the SignerIdentifier
    ///
    /// If the SignerIdentifier is IssuerAndSerialNumber the version is 1, otherwise it is 3.
    #[cfg(not(feature = "disable_csr"))]
    fn get_cms_version(sid: &SignerIdentifier) -> u64 {
        match sid {
            SignerIdentifier::IssuerAndSerialNumber {
                issuer_name: _,
                serial_number: _,
            } => Self::CMS_V1,
            SignerIdentifier::SubjectKeyIdentifier(_) => Self::CMS_V3,
        }
    }

    /// Encode a SignedData
    ///
    /// This function does not populate the certificates or crls fields.
    ///
    /// SignedData  ::=  SEQUENCE  {
    ///    version CMSVersion,
    ///    digestAlgorithms DigestAlgorithmIdentifiers,
    ///    encapContentInfo EncapsulatedContentInfo,
    ///    certificates [0] IMPLICIT CertificateSet OPTIONAL,
    ///    crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
    ///    signerInfos SignerInfos
    /// }
    #[allow(clippy::identity_op)]
    #[cfg(not(feature = "disable_csr"))]
    fn get_signed_data<'a>(
        &mut self,
        csr: &'a [u8],
        sig: &'a EcdsaSig,
        sid: &'a SignerIdentifier,
    ) -> Result<CmsSignedData<'a>, DpeErrorCode> {
        // PANIC FREE: SetOf and SequenceOf are fixed size and number of additions are
        // hard-coded
        let mut digest_algs = asn1::SetOf::<AlgorithmIdentifier, 1>::new();
        digest_algs
            .insert(AlgorithmIdentifier {
                algorithm: Self::HASH_OID,
                parameters: None,
            })
            .unwrap();

        let mut signer_infos = asn1::SetOf::<SignerInfo, 1>::new();
        signer_infos
            .insert(Self::get_signer_info(sig, sid)?)
            .unwrap();
        let encap_content_info = EncapContentInfo {
            content_type: Self::ID_DATA_OID,
            content: Some(asn1::OctetStringRef::new(csr).unwrap()),
        };

        Ok(CmsSignedData {
            version: Self::get_cms_version(sid),
            digest_algs,
            encap_content_info,
            signer_infos,
        })
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
    fn get_attributes<'a>(
        &mut self,
        measurements: &'a MeasurementData,
    ) -> Result<CsrAttributes<'a>, DpeErrorCode> {
        // Attributes is EXPLICIT field number 0
        let mut attrs = CsrAttributes::new();
        let mut extension_set = asn1::SetOf::<CsrAttributeValue, 1>::new();

        // PANIC FREE: Sets/sequences are fixed size and number of additions are
        // hard-coded
        let extensions = self.get_extensions(measurements, /*is_x509=*/ false)?;
        extension_set
            .insert(CsrAttributeValue::Extensions(extensions))
            .unwrap();

        let attr = CsrAttribute {
            attr_type: Self::EXTENSION_REQUEST_OID,
            attr_values: extension_set,
        };

        attrs.insert(attr).unwrap();

        Ok(attrs)
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
    pub fn get_signer_info<'a>(
        sig: &'a EcdsaSig,
        sid: &'a SignerIdentifier,
    ) -> Result<SignerInfo<'a>, DpeErrorCode> {
        let der_sig = DerEcdsaSignature {
            r: asn1::UintRef::new(sig.r.bytes()).map_err(|_| X509Error::IntError)?,
            s: asn1::UintRef::new(sig.s.bytes()).map_err(|_| X509Error::IntError)?,
        };
        Ok(SignerInfo {
            version: Self::get_cms_version(sid),
            sid: Self::get_signer_identifier(sid)?,
            digest_alg: AlgorithmIdentifier {
                algorithm: Self::HASH_OID,
                parameters: None,
            },
            sig_alg: AlgorithmIdentifier {
                algorithm: Self::ECDSA_OID,
                parameters: None,
            },
            signature: OctetStringContainer::<DerEcdsaSignature>(der_sig),
        })
    }

    /// Encode a SignerIdentifier
    ///
    /// SignerIdentifier ::= CHOICE {
    ///     issuerAndSerialNumber IssuerAndSerialNumber,
    ///     subjectKeyIdentifier [0] SubjectKeyIdentifier
    /// }
    #[cfg(not(feature = "disable_csr"))]
    fn get_signer_identifier(sid: &SignerIdentifier) -> Result<DerSignerIdentifier, DpeErrorCode> {
        match sid {
            SignerIdentifier::IssuerAndSerialNumber {
                issuer_name,
                serial_number,
            } => Ok(DerSignerIdentifier::IssuerAndSerialNumber(
                IssuerAndSerialNumber {
                    issuer: RawDerSequenceRef::new(issuer_name)?,
                    serial: asn1::UintRef::new(serial_number).map_err(|_| X509Error::IntError)?,
                },
            )),
            SignerIdentifier::SubjectKeyIdentifier(subject_key_identifier) => {
                Ok(DerSignerIdentifier::SubjectKeyIdentifier(
                    asn1::OctetStringRef::new(subject_key_identifier)
                        .map_err(|_| X509Error::RangeError)?,
                ))
            }
        }
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
    /// * `validity` - Time period in which certificate is valid.
    #[cfg(not(feature = "disable_x509"))]
    pub fn encode_ecdsa_tbs<'a>(
        &mut self,
        serial_number: &'a [u8],
        issuer_name: &'a [u8],
        subject_name: &'a Name,
        pubkey: &'a EcdsaPub,
        measurements: &'a MeasurementData,
        validity: &'a CertValidity,
    ) -> Result<usize, DpeErrorCode> {
        let encoded_pub = pubkey.into();
        let der_validity = self.get_validity(validity)?;
        let subject_rdn = Self::get_rdn(subject_name)?;
        let subject_pubkey = Self::get_ecdsa_subject_pubkey_info(&encoded_pub)?;
        let extensions = self.get_extensions(measurements, /*is_x509=*/ true)?;

        let tbs = EcdsaTbsCertificate {
            version: Self::X509_V3,
            serial_number: asn1::UintRef::new(serial_number).map_err(|_| X509Error::IntError)?,
            signature_alg: AlgorithmIdentifier {
                algorithm: Self::ECDSA_OID,
                parameters: None,
            },
            issuer_name: RawDerSequenceRef::new(issuer_name)?,
            validity: der_validity,
            subject_name: subject_rdn,
            subject_pubkey_info: subject_pubkey,
            extensions: Some(extensions),
        };
        self.encode_der(&tbs)
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
    pub fn encode_ecdsa_certificate(
        &mut self,
        tbs: &[u8],
        sig: &EcdsaSig,
    ) -> Result<usize, DpeErrorCode> {
        let der_sig = DerEcdsaSignature {
            r: asn1::UintRef::new(sig.r.bytes()).map_err(|_| X509Error::IntError)?,
            s: asn1::UintRef::new(sig.s.bytes()).map_err(|_| X509Error::IntError)?,
        };
        let cert = EcdsaCertificate {
            tbs: RawDerSequenceRef::new(tbs)?,
            alg_id: AlgorithmIdentifier {
                algorithm: Self::ECDSA_OID,
                parameters: None,
            },
            signature: BitStringContainer::<DerEcdsaSignature>(der_sig),
        };

        self.encode_der(&cert)
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
        pub_key: &EcdsaPub,
        subject_name: &Name,
        measurements: &MeasurementData,
    ) -> Result<usize, DpeErrorCode> {
        let pub_buf = pub_key.into();
        let csr_info = Pkcs10CsrInfo {
            version: Self::CSR_V0,
            subject: Self::get_rdn(subject_name)?,
            subject_pubkey_info: Self::get_ecdsa_subject_pubkey_info(&pub_buf)?,
            attributes: self.get_attributes(measurements)?,
        };
        self.encode_der(&csr_info)
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
        cert_req_info: &[u8],
        sig: &EcdsaSig,
    ) -> Result<usize, DpeErrorCode> {
        let der_sig = DerEcdsaSignature {
            r: asn1::UintRef::new(sig.r.bytes()).map_err(|_| X509Error::IntError)?,
            s: asn1::UintRef::new(sig.s.bytes()).map_err(|_| X509Error::IntError)?,
        };
        let csr = Pkcs10Csr {
            info: RawDerSequenceRef::new(cert_req_info)?,
            sig_alg: AlgorithmIdentifier {
                algorithm: Self::ECDSA_OID,
                parameters: None,
            },
            sig: BitStringContainer::<DerEcdsaSignature>(der_sig),
        };
        self.encode_der(&csr)
    }

    /// Encode a CMS ContentInfo message
    ///
    /// ContentInfo  ::=  SEQUENCE  {
    ///    contentType ContentType,
    ///    content [0] EXPLICIT ANY DEFINED BY contentType
    /// }
    #[cfg(not(feature = "disable_csr"))]
    pub fn encode_cms(
        &mut self,
        csr: &[u8],
        sig: &EcdsaSig,
        sid: &SignerIdentifier,
    ) -> Result<usize, DpeErrorCode> {
        let ci = CmsContentInfo {
            content_type: Self::ID_SIGNED_DATA_OID,
            content: self.get_signed_data(csr, sig, sid)?,
        };

        self.encode_der(&ci)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::tci::{TciMeasurement, TciNodeData};
    use crate::x509::{CertWriter, MeasurementData, Name};
    use crate::{DpeProfile, DPE_PROFILE};
    use crypto::{CryptoBuf, EcdsaPub, EcdsaSig};
    use openssl::hash::{Hasher, MessageDigest};
    use platform::{ArrayVec, CertValidity, OtherName, SubjectAltName, MAX_KEY_IDENTIFIER_SIZE};
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
    pub struct TcbInfo<'a> {
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
        pub fwids: Option<asn1::SequenceOf<'a, Fwid<'a>>>,
        #[implicit(7)]
        _flags: Option<asn1::BitString<'a>>,
        #[implicit(8)]
        pub vendor_info: Option<&'a [u8]>,
        #[implicit(9)]
        pub tci_type: Option<&'a [u8]>,
    }

    #[derive(asn1::Asn1Read)]
    struct Ueid<'a> {
        pub(crate) ueid: &'a [u8],
    }

    const TEST_ISSUER: Name = Name {
        cn: b"Caliptra Alias",
        serial: &[b'i'; DPE_PROFILE.get_hash_size() * 2],
    };

    fn encode_test_issuer() -> Vec<u8> {
        let mut issuer_der = vec![0u8; 256];
        let mut issuer_writer = CertWriter::new(&mut issuer_der, true);
        let issuer_rdn = CertWriter::get_rdn(&TEST_ISSUER).unwrap();
        let issuer_len = issuer_writer.encode_der(&issuer_rdn).unwrap();
        issuer_der.resize(issuer_len, 0);
        issuer_der
    }

    #[test]
    fn test_rdn() {
        let mut cert = [0u8; 256];
        let test_name = Name {
            cn: b"Caliptra Alias",
            serial: &[b'a'; DPE_PROFILE.get_hash_size() * 2],
        };

        let mut w = CertWriter::new(&mut cert, true);
        let rdn = CertWriter::get_rdn(&test_name).unwrap();
        let bytes_written = w.encode_der(&rdn).unwrap();

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
    }

    #[test]
    fn test_subject_pubkey() {
        let mut cert = [0u8; 256];
        let test_key = EcdsaPub::default(DPE_PROFILE.alg_len());

        let mut w = CertWriter::new(&mut cert, true);
        let pub_buf = (&test_key).into();
        let subject_pubkey = CertWriter::get_ecdsa_subject_pubkey_info(&pub_buf).unwrap();
        let bytes_written = w.encode_der(&subject_pubkey).unwrap();

        SubjectPublicKeyInfo::from_der(&cert[..bytes_written]).unwrap();
    }

    #[test]
    fn test_tcb_info() {
        let mut node = TciNodeData::new();

        node.tci_type = 0x11223344;
        node.tci_cumulative = TciMeasurement([0xaau8; DPE_PROFILE.get_hash_size()]);
        node.tci_current = TciMeasurement([0xbbu8; DPE_PROFILE.get_hash_size()]);
        node.locality = 0xFFFFFFFF;

        let mut cert = [0u8; 256];
        let mut w = CertWriter::new(&mut cert, true);
        let mut supports_recursive = true;
        let tcb_info = CertWriter::get_tcb_info(&node, supports_recursive).unwrap();
        let mut bytes_written = w.encode_der(&tcb_info).unwrap();

        let mut parsed_tcb_info = asn1::parse_single::<TcbInfo>(&cert[..bytes_written]).unwrap();

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

        // test tbs_info with supports_recursive = false
        supports_recursive = false;
        w = CertWriter::new(&mut cert, true);
        let tcb_info = CertWriter::get_tcb_info(&node, supports_recursive).unwrap();
        bytes_written = w.encode_der(&tcb_info).unwrap();

        parsed_tcb_info = asn1::parse_single::<TcbInfo>(&cert[..bytes_written]).unwrap();

        // Check that only FWID[0] is present
        let mut fwid_itr = parsed_tcb_info.fwids.unwrap();
        let expected_current = fwid_itr.next().unwrap().digest;
        assert!(fwid_itr.next().is_none());
        assert_eq!(expected_current, node.tci_current.0);
    }

    fn get_test_key_usage(is_ca: bool) -> KeyUsage {
        let mut cert = [0u8; 32];
        let mut w = CertWriter::new(&mut cert, true);
        let ku = CertWriter::get_key_usage(is_ca).unwrap();
        let bytes_written = w.encode_der(&ku).unwrap();

        let mut parser = X509ExtensionParser::new().with_deep_parse_extensions(false);
        let ext = parser.parse(&cert[..bytes_written]).unwrap().1;
        KeyUsage::from_der(ext.value).unwrap().1
    }

    #[test]
    fn test_key_usage() {
        // Make sure leaf keyUsage is only digitalSignature
        let leaf_key_usage = get_test_key_usage(/*is_ca=*/ false);
        let expected = 1u16;
        assert!(leaf_key_usage.flags | expected == expected);

        // Make sure leaf keyUsage is digitalSignature | keyCertSign
        let ca_key_usage = get_test_key_usage(/*is_ca=*/ true);
        let expected = (1u16 << 5) | 1u16;
        assert!(ca_key_usage.flags | expected == expected);
    }

    #[test]
    fn test_tbs() {
        let mut cert = [0u8; 4096];
        let mut w = CertWriter::new(&mut cert, true);

        let test_serial = [0x1F; 20];
        let issuer_der = encode_test_issuer();

        let test_subject_name = Name {
            cn: b"DPE Leaf",
            serial: &[b's'; DPE_PROFILE.get_hash_size() * 2],
        };

        const ECC_INT_SIZE: usize = DPE_PROFILE.get_ecc_int_size();
        let test_pub = EcdsaPub {
            x: CryptoBuf::new(&[0xAA; ECC_INT_SIZE]).unwrap(),
            y: CryptoBuf::new(&[0xBB; ECC_INT_SIZE]).unwrap(),
        };

        let node = TciNodeData::new();

        let measurements = MeasurementData {
            label: &[0xCC; DPE_PROFILE.get_hash_size()],
            tci_nodes: &[node],
            is_ca: false,
            supports_recursive: true,
            subject_key_identifier: [0u8; MAX_KEY_IDENTIFIER_SIZE],
            authority_key_identifier: [0u8; MAX_KEY_IDENTIFIER_SIZE],
            subject_alt_name: None,
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

        let bytes_written = w
            .encode_ecdsa_tbs(
                &test_serial,
                &issuer_der,
                &test_subject_name,
                &test_pub,
                &measurements,
                &validity,
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

    const TEST_SERIAL: &[u8] = &[0x1F; 20];
    const TEST_ISSUER_NAME: Name = Name {
        cn: b"Caliptra Alias",
        serial: &[b'i'; DPE_PROFILE.get_hash_size() * 2],
    };
    const TEST_SUBJECT_NAME: Name = Name {
        cn: b"DPE Leaf",
        serial: &[b's'; DPE_PROFILE.get_hash_size() * 2],
    };

    const ECC_INT_SIZE: usize = DPE_PROFILE.get_ecc_int_size();

    const DEFAULT_OTHER_NAME_OID: &'static [u8] = &[0, 0, 0];
    const DEFAULT_OTHER_NAME_VALUE: &str = "default-other-name";

    fn build_test_tbs<'a>(is_ca: bool, cert_buf: &'a mut [u8]) -> (usize, TbsCertificate<'a>) {
        let mut issuer_der = [0u8; 1024];
        let mut issuer_writer = CertWriter::new(&mut issuer_der, true);
        let rdn = CertWriter::get_rdn(&TEST_ISSUER_NAME).unwrap();
        let issuer_len = issuer_writer.encode_der(&rdn).unwrap();

        let test_pub = EcdsaPub {
            x: CryptoBuf::new(&[0xAA; ECC_INT_SIZE]).unwrap(),
            y: CryptoBuf::new(&[0xBB; ECC_INT_SIZE]).unwrap(),
        };

        let node = TciNodeData::new();

        let mut hasher = match DPE_PROFILE {
            DpeProfile::P256Sha256 => Hasher::new(MessageDigest::sha256()).unwrap(),
            DpeProfile::P384Sha384 => Hasher::new(MessageDigest::sha384()).unwrap(),
        };
        hasher.update(&[0x04]).unwrap();
        hasher.update(test_pub.x.bytes()).unwrap();
        hasher.update(test_pub.y.bytes()).unwrap();
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
            label: &[0; DPE_PROFILE.get_hash_size()],
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

        let mut tbs_writer = CertWriter::new(cert_buf, true);
        let bytes_written = tbs_writer
            .encode_ecdsa_tbs(
                &TEST_SERIAL,
                &issuer_der[..issuer_len],
                &TEST_SUBJECT_NAME,
                &test_pub,
                &measurements,
                &validity,
            )
            .unwrap();

        let mut parser = TbsCertificateParser::new().with_deep_parse_extensions(true);
        (
            bytes_written,
            parser.parse(&cert_buf[..bytes_written]).unwrap().1,
        )
    }

    fn build_test_cert<'a>(is_ca: bool, cert_buf: &'a mut [u8]) -> (usize, X509Certificate<'a>) {
        let mut tbs_buf = [0u8; 1024];
        let (tbs_written, _) = build_test_tbs(is_ca, &mut tbs_buf);

        let test_sig = EcdsaSig {
            r: CryptoBuf::new(&[0xCC; ECC_INT_SIZE]).unwrap(),
            s: CryptoBuf::new(&[0xDD; ECC_INT_SIZE]).unwrap(),
        };

        let mut w = CertWriter::new(cert_buf, true);
        let bytes_written = w
            .encode_ecdsa_certificate(&mut tbs_buf[..tbs_written], &test_sig)
            .unwrap();

        let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
        let cert = match parser.parse(&cert_buf[..bytes_written]) {
            Ok((_, parsed_cert)) => {
                assert_eq!(parsed_cert.version(), X509Version::V3);
                parsed_cert
            }
            Err(e) => panic!("x509 parsing failed: {:?}", e),
        };

        (bytes_written, cert)
    }

    #[test]
    fn test_full_leaf() {
        let mut cert_buf = [0u8; 1024];
        let (_, cert) = build_test_cert(false, &mut cert_buf);

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

        match cert.get_extension_unique(&oid!(2.5.29 .35)) {
            Ok(Some(_)) => {
                panic!("authority key identifier extensions found for non CA certificate")
            }
            Err(_) => panic!("multiple authority key identifier extensions found"),
            _ => (),
        }

        match cert.subject_alternative_name() {
            Ok(Some(ext)) => {
                assert!(!ext.critical);
                let san = ext.value;
                assert_eq!(san.general_names.len(), 1);
                let general_name = san.general_names.get(0).unwrap();
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
            Err(e) => panic!("Error {} parsing SubjectAltName extension", e.to_string()),
        }
    }

    #[test]
    fn test_full_ca() {
        let mut cert_buf = [0u8; 1024];
        let (_, cert) = build_test_cert(/*is_ca=*/ true, &mut cert_buf);

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
