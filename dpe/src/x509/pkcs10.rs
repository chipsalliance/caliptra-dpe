use crate::x509::{
    AlgorithmIdentifier, BitStringContainer, DirectoryString, DerEcdsaSignature,
    DpeExtensions, FixedSetOf, OctetStringContainer, OidRef,
    RawDerSequenceRef, RelativeDistinguishedName, SubjectPublicKeyInfo,
};
use der::{
    asn1::{OctetStringRef, UintRef},
    Choice, Sequence
};

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
    pub sig_alg: AlgorithmIdentifier<'a>,
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
    pub version: u64,
    pub digest_algs: FixedSetOf<AlgorithmIdentifier<'a>, 1>,
    pub encap_content_info: EncapContentInfo<'a>,
    pub signer_infos: FixedSetOf<SignerInfo<'a>, 1>,
}

/// ContentInfo  ::=  SEQUENCE  {
///    contentType ContentType,
///    content [0] EXPLICIT ANY DEFINED BY contentType
/// }
#[derive(Sequence)]
pub struct CmsContentInfo<'a> {
    pub content_type: OidRef<'a>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "false")]
    pub content: CmsSignedData<'a>,
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
#[derive(Sequence)]
pub struct SignerInfo<'a> {
    pub version: u64,
    pub sid: DerSignerIdentifier<'a>,
    pub digest_alg: AlgorithmIdentifier<'a>,
    pub sig_alg: AlgorithmIdentifier<'a>,
    pub signature: OctetStringContainer<DerEcdsaSignature<'a>>,
}

#[derive(Choice)]
pub enum DerSignerIdentifier<'a> {
    IssuerAndSerialNumber(IssuerAndSerialNumber<'a>),
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "false")]
    SubjectKeyIdentifier(OctetStringRef<'a>),
}

/// IssuerAndSerialNumber ::= SEQUENCE {
///     issuer Name,
///     serialNumber CertificateSerialNumber }
#[derive(Sequence)]
pub struct IssuerAndSerialNumber<'a> {
    pub issuer: RawDerSequenceRef<'a>,
    pub serial: UintRef<'a>,
}

/// EncapsulatedContentInfo ::= SEQUENCE {
///     eContentType ContentType,
///     eContent [0] EXPLICIT OCTET STRING OPTIONAL }
#[derive(Sequence)]
pub struct EncapContentInfo<'a> {
    pub content_type: OidRef<'a>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub content: Option<OctetStringRef<'a>>,
}

/// Attributes ::= SET OF Attribute
///
/// Attribute ::= SEQUENCE {
///    attrType OBJECT IDENTIFIER,
///    attrValues SET OF AttributeValue
/// }
///
/// AttributeValue ::= ANY -- Defined by attribute type
pub type CsrAttributes<'a> = FixedSetOf<CsrAttribute<'a>, 1>;

#[derive(Choice)]
pub enum CsrAttributeValue<'a> {
    Extensions(DpeExtensions<'a>),
}

#[derive(Sequence)]
pub struct CsrAttribute<'a> {
    pub attr_type: OidRef<'a>,
    // Only supported CSR attribute is X.509 Extensions
    pub attr_values: FixedSetOf<CsrAttributeValue<'a>, 1>,
}

#[derive(Sequence)]
pub struct AttributeTypeAndValue<'a> {
    pub attr_type: OidRef<'a>,
    pub value: DirectoryString<'a>,
}
