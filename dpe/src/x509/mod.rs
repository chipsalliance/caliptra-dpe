// Licensed under the Apache-2.0 license;

//! Lightweight X.509 encoding routines for DPE
//!
//! DPE requires encoding variable-length certificates. This module provides
//! this functionality for a no_std environment.

mod asn1;
mod pkcs10;

use crate::x509::asn1::*;
use crate::x509::pkcs10::*;
use crate::x509::x509::*;
use crate::{
    oid,
    DPE_PROFILE,
    response::DpeErrorCode,
    tci::{TciMeasurement, TciNodeData},
    MAX_HANDLES,
};
use bitflags::bitflags;
use crypto::{EcdsaPub, EcdsaSig, EncodedEcdsaPub};
use der::{
    asn1::{
        BitStringRef, OctetStringRef, SequenceOf, UintRef, Utf8StringRef},
    Choice, Encode, Sequence};
#[cfg(not(feature = "disable_x509"))]
use platform::CertValidity;
#[cfg(not(feature = "disable_csr"))]
use platform::SignerIdentifier;
use platform::{SubjectAltName, MAX_KEY_IDENTIFIER_SIZE};

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

impl CertWriter<'_> {
    const X509_V3: u64 = 2;
    #[cfg(not(feature = "disable_csr"))]
    const CMS_V1: u64 = 1;
    #[cfg(not(feature = "disable_csr"))]
    const CMS_V3: u64 = 3;
    #[cfg(not(feature = "disable_csr"))]
    const CSR_V0: u64 = 0;

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
            attr_type: OidRef::new(oid::RDN_COMMON_NAME_OID),
            value: DirectoryString::PrintableString(UncheckedPrintableStringRef::new(name.cn)),
        };
        let sn = AttributeTypeAndValue {
            attr_type: OidRef::new(oid::RDN_SERIALNUMBER_OID),
            value: DirectoryString::PrintableString(UncheckedPrintableStringRef::new(name.serial)),
        };

        // PANIC FREE: Sets/sequences are fixed size and number of additions are
        // hard-coded
        let cn_set = FixedSetOf::<AttributeTypeAndValue, 1>::new([cn]);
        let sn_set = FixedSetOf::<AttributeTypeAndValue, 1>::new([sn]);
        let mut rdn = RelativeDistinguishedName::new();
        rdn.add(cn_set).unwrap();
        rdn.add(sn_set).unwrap();

        Ok(rdn)
    }

    // Encode ASN.1 Validity according to Platform
    #[cfg(not(feature = "disable_x509"))]
    fn get_validity<'a>(validity: &'a CertValidity) -> Result<Validity<'a>, DpeErrorCode> {
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
            algorithm: OidRef::new(oid::EC_PUB_OID),
            parameters: Some(AlgorithmParameters::Ecdsa(OidRef::new(oid::CURVE_OID))),
        };

        Ok(SubjectPublicKeyInfo {
            alg: alg_id,
            pub_key: BitStringRef::new(0, pubkey.0.as_slice())
                .map_err(|_| X509Error::RangeError)?,
        })
    }

    fn get_fwid(tci: &TciMeasurement) -> Result<DerFwid, DpeErrorCode> {
        Ok(DerFwid {
            hash_alg: OidRef::new(oid::HASH_OID),
            digest: HashOctetStringRef::new(&tci.0)?,
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
        let mut fwids = SequenceOf::<DerFwid<'a>, 2>::new();

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
            oid: OidRef::new(oid::MULTI_TCBINFO_OID),
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
            ueid: HashOctetStringRef::new(measurements.label)?,
        };
        Ok(Extension {
            oid: OidRef::new(oid::UEID_OID),
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
            oid: OidRef::new(oid::BASIC_CONSTRAINTS_OID),
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
            BitStringRef::new(2, KeyUsageFlags::ECA_FLAGS.as_bytes())
                .map_err(|_| X509Error::RangeError)?
        } else {
            BitStringRef::new(7, KeyUsageFlags::DIGITAL_SIGNATURE.as_bytes())
                .map_err(|_| X509Error::RangeError)?
        };

        Ok(Extension {
            oid: OidRef::new(oid::KEY_USAGE_OID),
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
            OidRef::new(oid::ECA_OID)
        } else {
            OidRef::new(oid::ATTEST_LOC_OID)
        };

        // PANIC FREE: Number of additions hard-coded
        let mut eku = ExtendedKeyUsage::new();
        eku.add(policy_oid).unwrap();

        Ok(Extension {
            oid: OidRef::new(oid::EXTENDED_KEY_USAGE_OID),
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
                    type_id: OidRef::new(other_name.oid),
                    value: Some(
                        Utf8StringRef::new(other_name.other_name.as_slice())
                            .map_err(|_| X509Error::Utf8Error)?,
                    ),
                }))
                .unwrap();
                Ok(Extension {
                    oid: OidRef::new(oid::SUBJECT_ALTERNATIVE_NAME_OID),
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
            oid: OidRef::new(oid::AUTHORITY_KEY_IDENTIFIER_OID),
            critical: false,
            value: ExtensionVal::AuthorityKeyIdentifier(OctetStringContainer(
                AuthorityKeyIdentifier {
                    key_identifier: Some(
                        OctetStringRef::new(&measurements.authority_key_identifier)
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
            oid: OidRef::new(oid::SUBJECT_KEY_IDENTIFIER_OID),
            critical: false,
            value: ExtensionVal::OctetString(OctetStringContainer(
                OctetStringRef::new(&measurements.subject_key_identifier)
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
        let mut extensions = DpeExtensions::new();
        extensions
            .add(self.get_multi_tcb_info(measurements)?)
            .unwrap();
        extensions
            .add(Self::get_extended_key_usage(measurements)?)
            .unwrap();
        extensions.add(self.get_ueid(measurements)?).unwrap();
        extensions
            .add(Self::get_basic_constraints(measurements)?)
            .unwrap();
        extensions
            .add(Self::get_key_usage(measurements.is_ca)?)
            .unwrap();

        if measurements.is_ca && is_x509 {
            extensions
                .add(Self::get_subject_key_identifier_extension(measurements)?)
                .unwrap();
            extensions
                .add(Self::get_authority_key_identifier_extension(measurements)?)
                .unwrap();
        }

        match &measurements.subject_alt_name {
            Some(SubjectAltName::OtherName(_)) => {
                extensions
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
        let digest_algs = FixedSetOf::<AlgorithmIdentifier, 1>::new([AlgorithmIdentifier {
            algorithm: OidRef::new(oid::HASH_OID),
            parameters: None,
        }]);

        let signer_infos = FixedSetOf::<SignerInfo, 1>::new([Self::get_signer_info(sig, sid)?]);
        let encap_content_info = EncapContentInfo {
            content_type: OidRef::new(oid::ID_DATA_OID),
            content: Some(OctetStringRef::new(csr).unwrap()),
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

        // PANIC FREE: Sets/sequences are fixed size and number of additions are
        // hard-coded
        let extensions = self.get_extensions(measurements, /*is_x509=*/ false)?;
        let extension_set =
            FixedSetOf::<CsrAttributeValue, 1>::new([CsrAttributeValue::Extensions(
                extensions,
            )]);
        let attr = CsrAttribute {
            attr_type: OidRef::new(oid::EXTENSION_REQUEST_OID),
            attr_values: extension_set,
        };

        Ok(CsrAttributes::new([attr]))
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
            r: UintRef::new(sig.r.bytes()).map_err(|_| X509Error::IntError)?,
            s: UintRef::new(sig.s.bytes()).map_err(|_| X509Error::IntError)?,
        };
        Ok(SignerInfo {
            version: Self::get_cms_version(sid),
            sid: Self::get_signer_identifier(sid)?,
            digest_alg: AlgorithmIdentifier {
                algorithm: OidRef::new(oid::HASH_OID),
                parameters: None,
            },
            sig_alg: AlgorithmIdentifier {
                algorithm: OidRef::new(oid::ECDSA_OID),
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
                    serial: UintRef::new(serial_number).map_err(|_| X509Error::IntError)?,
                },
            )),
            SignerIdentifier::SubjectKeyIdentifier(subject_key_identifier) => {
                Ok(DerSignerIdentifier::SubjectKeyIdentifier(
                    OctetStringRef::new(subject_key_identifier)
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
        let der_validity = Self::get_validity(validity)?;
        let subject_rdn = Self::get_rdn(subject_name)?;
        let subject_pubkey = Self::get_ecdsa_subject_pubkey_info(&encoded_pub)?;
        let extensions = self.get_extensions(measurements, /*is_x509=*/ true)?;

        let tbs = EcdsaTbsCertificate {
            version: Self::X509_V3,
            serial_number: UintRef::new(serial_number).map_err(|_| X509Error::IntError)?,
            signature_alg: AlgorithmIdentifier {
                algorithm: OidRef::new(oid::ECDSA_OID),
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
            r: UintRef::new(sig.r.bytes()).map_err(|_| X509Error::IntError)?,
            s: UintRef::new(sig.s.bytes()).map_err(|_| X509Error::IntError)?,
        };
        let cert = EcdsaCertificate {
            tbs: RawDerSequenceRef::new(tbs)?,
            alg_id: AlgorithmIdentifier {
                algorithm: OidRef::new(oid::ECDSA_OID),
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
            r: UintRef::new(sig.r.bytes()).map_err(|_| X509Error::IntError)?,
            s: UintRef::new(sig.s.bytes()).map_err(|_| X509Error::IntError)?,
        };
        let csr = Pkcs10Csr {
            info: RawDerSequenceRef::new(cert_req_info)?,
            sig_alg: AlgorithmIdentifier {
                algorithm: OidRef::new(oid::ECDSA_OID),
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
            content_type: OidRef::new(oid::ID_SIGNED_DATA_OID),
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
