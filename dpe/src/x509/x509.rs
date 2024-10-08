use crate::x509::asn1::*;
use der::{
    asn1::{
        BitStringRef, OctetStringRef, SequenceOf, UintRef, Utf8StringRef},
    Choice, Encode, Sequence};
use zerocopy::AsBytes;

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
    pub serial_number: UintRef<'a>,
    pub signature_alg: AlgorithmIdentifier<'a>,
    pub issuer_name: RawDerSequenceRef<'a>,
    pub validity: Validity<'a>,
    pub subject_name: RelativeDistinguishedName<'a>,
    pub subject_pubkey_info: SubjectPublicKeyInfo<'a>,
    // This DPE implementation currently supports 8 extensions
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub extensions: Option<DpeExtensions<'a>>,
}

pub type DpeExtensions<'a> = SequenceOf<Extension<'a>, 8>;

#[derive(Sequence)]
pub struct Validity<'a> {
    not_before: RawGeneralizedTimeRef<'a>,
    not_after: RawGeneralizedTimeRef<'a>,
}

#[derive(Choice)]
pub enum GeneralName<'a> {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    OtherName(DerOtherName<'a>),
}

pub type DerSubjectAltName<'a> = SequenceOf<GeneralName<'a>, 1>;

#[derive(Choice)]
#[allow(clippy::large_enum_variant)]
pub enum ExtensionVal<'a> {
    AuthorityKeyIdentifier(OctetStringContainer<AuthorityKeyIdentifier<'a>>),
    OctetString(OctetStringContainer<OctetStringRef<'a>>),
    MultiTcbInfo(OctetStringContainer<MultiTcbInfo<'a>>),
    Ueid(OctetStringContainer<Ueid<'a>>),
    ExtendedKeyUsage(OctetStringContainer<ExtendedKeyUsage<'a>>),
    BasicConstraints(OctetStringContainer<BasicConstraints>),
    BitString(OctetStringContainer<BitStringRef<'a>>),
    OtherName(OctetStringContainer<DerSubjectAltName<'a>>),
}

#[derive(Sequence)]
pub struct Extension<'a> {
    pub oid: OidRef<'a>,
    pub critical: bool,
    pub value: ExtensionVal<'a>,
}

#[derive(Sequence)]
pub struct DerEcdsaSignature<'a> {
    pub r: UintRef<'a>,
    pub s: UintRef<'a>,
}

// DPE only supports one EKU OID
pub type ExtendedKeyUsage<'a> = SequenceOf<OidRef<'a>, 1>;

pub type RelativeDistinguishedName<'a> =
    SequenceOf<FixedSetOf<AttributeTypeAndValue<'a>, 1>, 2>;

#[derive(Choice)]
pub enum DirectoryString<'a> {
    Utf8String(Utf8StringRef<'a>),
    PrintableString(UncheckedPrintableStringRef<'a>),
}

///// Certificate  ::=  SEQUENCE  {
/////    tbsCertificate       TBSCertificate,
/////    signatureAlgorithm   AlgorithmIdentifier,
/////    signatureValue       BIT STRING  }
#[derive(Sequence)]
pub struct EcdsaCertificate<'a> {
    pub tbs: RawDerSequenceRef<'a>,
    pub alg_id: AlgorithmIdentifier<'a>,
    pub signature: BitStringContainer<DerEcdsaSignature<'a>>,
}

#[derive(Sequence)]
pub struct SubjectPublicKeyInfo<'a> {
    pub alg: AlgorithmIdentifier<'a>,
    pub pub_key: BitStringRef<'a>,
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
#[derive(Sequence)]
pub struct AlgorithmIdentifier<'a> {
    pub algorithm: OidRef<'a>,
    #[asn1(optional = "true")]
    pub parameters: Option<AlgorithmParameters<'a>>,
}

#[derive(Choice)]
pub enum AlgorithmParameters<'a> {
    // Curve
    Ecdsa(OidRef<'a>),
}

// DER structures for extensions

pub type HashOctetStringRef<'a> = FixedOctetStringRef<'a, { DPE_PROFILE.get_hash_size() as u16}>;

#[derive(Sequence)]
pub struct Ueid<'a> {
    pub ueid: HashOctetStringRef<'a>,
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
    pub type_id: OidRef<'a>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub value: Option<Utf8StringRef<'a>>,
}

#[derive(Sequence)]
pub struct DerFwid<'a> {
    pub hash_alg: OidRef<'a>,
    pub digest: HashOctetStringRef<'a>,
}

pub type MultiTcbInfo<'a> = SequenceOf<DerTcbInfo<'a>, MAX_HANDLES>;

#[derive(Sequence)]
pub struct DerTcbInfo<'a> {
    #[asn1(context_specific = "6", tag_mode = "IMPLICIT", optional = "true")]
    pub fwids: Option<SequenceOf<DerFwid<'a>, 2>>,
    #[asn1(context_specific = "8", tag_mode = "IMPLICIT", optional = "true")]
    pub vendor_info: Option<U32OctetString>,
    #[asn1(context_specific = "9", tag_mode = "IMPLICIT", optional = "true")]
    pub tci_type: Option<U32OctetString>,
}

impl<'a> DerTcbInfo<'a> {
    pub fn new(
        fwids: SequenceOf<DerFwid<'a>, 2>,
        vendor_info: u32,
        tci_type: u32,
    ) -> DerTcbInfo<'a> {
        Self {
            fwids: Some(fwids),
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
    key_identifier: Option<OctetStringRef<'a>>,
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
