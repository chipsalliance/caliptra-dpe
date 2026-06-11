// Licensed under the Apache-2.0 license

//! Lightweight X.509 encoding routines for DPE
//!
//! DPE requires encoding variable-length certificates. This module provides
//! this functionality for a no_std environment.

mod internal;

use crate::{okref, response::DpeErrorCode, tci::TciNodeData, DpeProfile};
use bitflags::bitflags;
use caliptra_dpe_crypto::{CryptoError, PubKey, Signature};
#[cfg(not(feature = "disable_x509"))]
use caliptra_dpe_platform::CertValidity;
#[cfg(not(feature = "disable_csr"))]
use caliptra_dpe_platform::SignerIdentifier;
use caliptra_dpe_platform::{ArrayVec, SubjectAltName, MAX_KEY_IDENTIFIER_SIZE};
use internal::CertWriterInternal;
use internal::SIZE_TAG_OFFSET;

#[cfg(not(feature = "disable_csr"))]
pub(crate) use internal::create_dpe_csr;
pub(crate) use internal::{
    create_dpe_cert, create_exported_dpe_cert, CreateDpeCertArgs, CreateDpeCertResult,
};

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

/// The public facing CertWriter.  It is responsible for ensuring all buffers returned to users
/// are either well-formed or error via the `check_not_truncated`.
pub struct CertWriter<'a> {
    internal: CertWriterInternal<'a>,
}

pub struct KeyUsageFlags(u8);

bitflags! {
    impl KeyUsageFlags: u8 {
        const DIGITAL_SIGNATURE = 0b1000_0000;
        const KEY_CERT_SIGN = 0b0000_0100;
    }
}

impl CertWriter<'_> {
    /// Build new CertWriter that writes output to `cert`
    ///
    /// If `crit_dice`, all tcg-dice-* extensions will be marked as critical.
    /// Else they will be marked as non-critical.
    pub fn new(cert: &mut [u8], profile: DpeProfile, crit_dice: bool) -> CertWriter {
        CertWriter {
            internal: CertWriterInternal {
                certificate: cert,
                profile,
                offset: 0,
                crit_dice,
                csr_range: None,
                backtracks: ArrayVec::new(),
                saved_offset: None,
            },
        }
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
            CertWriterInternal::get_structure_size(
                CertWriterInternal::RDN_COMMON_NAME_OID.len(),
                /*tagged=*/ true,
            ) + CertWriterInternal::get_structure_size(name.cn.len(), /*tagged=*/ true);
        let serialnumber_size =
            CertWriterInternal::get_structure_size(
                CertWriterInternal::RDN_SERIALNUMBER_OID.len(),
                /*tagged=*/ true,
            ) + CertWriterInternal::get_structure_size(name.serial.len(), /*tagged=*/ true);

        let rdn_name_set_size =
            CertWriterInternal::get_structure_size(cn_size, /*tagged=*/ true);
        let rnd_serial_set_size =
            CertWriterInternal::get_structure_size(serialnumber_size, /*tagged=*/ true);
        let rdn_seq_size =
            CertWriterInternal::get_structure_size(rdn_name_set_size, /*tagged=*/ true)
                + CertWriterInternal::get_structure_size(
                    rnd_serial_set_size,
                    /*tagged=*/ true,
                );

        let mut bytes_written = self
            .internal
            .encode_tag_field(CertWriterInternal::SEQUENCE_OF_TAG);
        bytes_written += self.internal.encode_size_field(rdn_seq_size);

        bytes_written += self
            .internal
            .encode_tag_field(CertWriterInternal::SET_OF_TAG);
        bytes_written += self.internal.encode_size_field(rdn_name_set_size);

        bytes_written += self
            .internal
            .encode_tag_field(CertWriterInternal::SEQUENCE_TAG);
        bytes_written += self.internal.encode_size_field(cn_size);
        bytes_written += self
            .internal
            .encode_oid(&CertWriterInternal::RDN_COMMON_NAME_OID);
        bytes_written += self.internal.encode_rdn_string(&name.cn);

        bytes_written += self
            .internal
            .encode_tag_field(CertWriterInternal::SET_OF_TAG);
        bytes_written += self.internal.encode_size_field(rnd_serial_set_size);

        bytes_written += self
            .internal
            .encode_tag_field(CertWriterInternal::SEQUENCE_TAG);
        bytes_written += self.internal.encode_size_field(serialnumber_size);
        bytes_written += self
            .internal
            .encode_oid(&CertWriterInternal::RDN_SERIALNUMBER_OID);
        bytes_written += self.internal.encode_rdn_string(&name.serial);

        self.internal.check_not_truncated()?;
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
        let signer_info_size = self
            .internal
            .get_signer_info_size(sig, sid, /*tagged=*/ false)?;

        let mut bytes_written = self
            .internal
            .encode_tag_field(CertWriterInternal::SEQUENCE_TAG);
        bytes_written += self.internal.encode_size_field(signer_info_size);
        bytes_written += self.internal.encode_cms_version(sid);
        bytes_written += self.internal.encode_signer_identifier(sid);
        bytes_written += self.internal.encode_hash_alg_id()?;
        bytes_written += self.internal.encode_signature_octet_string(sig)?;

        self.internal.check_not_truncated()?;
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
        let tbs_size = self.internal.get_tbs_size(
            serial_number,
            issuer_name,
            subject_name,
            pubkey,
            measurements,
            validity,
            /*tagged=*/ false,
        )?;

        let mut bytes_written = self
            .internal
            .encode_tag_field(CertWriterInternal::SEQUENCE_TAG);
        bytes_written += self.internal.encode_size_field(tbs_size);
        bytes_written += self.internal.encode_version();
        bytes_written += self.internal.encode_integer_bytes(serial_number, true);
        bytes_written += match pubkey {
            PubKey::Ecdsa(_) => self.internal.encode_ecdsa_sig_alg_id()?,
            #[cfg(feature = "ml-dsa")]
            PubKey::Mldsa(_) => self.internal.encode_mldsa_sig_alg_id()?,
        };
        bytes_written += self.internal.encode_bytes(issuer_name);
        bytes_written += self.internal.encode_validity(validity);
        bytes_written += self.encode_rdn(subject_name)?;
        bytes_written += match pubkey {
            PubKey::Ecdsa(pub_key) => self.internal.encode_ecdsa_subject_pubkey_info(pub_key)?,
            #[cfg(feature = "ml-dsa")]
            PubKey::Mldsa(pub_key) => self.internal.encode_mldsa_subject_pubkey_info(pub_key)?,
        };
        bytes_written += self
            .internal
            .encode_extensions(measurements, /*is_x509=*/ true)?;

        self.internal.check_not_truncated()?;
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
        sign_cb: &mut (impl FnMut(&[u8], bool) -> Result<Signature, CryptoError> + ?Sized),
        serial_number: &[u8],
        issuer_name: &[u8],
        subject_name: &Name,
        pubkey: &PubKey,
        measurements: &MeasurementData,
        validity: &CertValidity,
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
        )?;
        self.internal.check_not_truncated()?;
        Ok(bytes_written)
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
        let cert_req_info_size = self.internal.get_certification_request_info_size(
            subject_name,
            pub_key,
            measurements,
            /*tagged=*/ false,
        )?;

        let mut bytes_written = self
            .internal
            .encode_tag_field(CertWriterInternal::SEQUENCE_TAG);
        bytes_written += self.internal.encode_size_field(cert_req_info_size);
        bytes_written += self
            .internal
            .encode_integer(CertWriterInternal::CSR_V0, true);
        bytes_written += self.encode_rdn(subject_name)?;
        match pub_key {
            PubKey::Ecdsa(pub_key) => {
                bytes_written += self.internal.encode_ecdsa_subject_pubkey_info(pub_key)?;
            }
            #[cfg(feature = "ml-dsa")]
            PubKey::Mldsa(pub_key) => {
                bytes_written += self.internal.encode_mldsa_subject_pubkey_info(pub_key)?;
            }
        }
        bytes_written += self.internal.encode_attributes(measurements)?;

        self.internal.check_not_truncated()?;
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
        sign_cb: &mut (impl FnMut(&[u8], bool) -> Result<Signature, CryptoError> + ?Sized),
        pub_key: &PubKey,
        subject_name: &Name,
        measurements: &MeasurementData,
    ) -> Result<usize, DpeErrorCode> {
        let bytes_written = self.encode_signed_payload(
            sign_cb,
            SignedPayload::CertReqInfo {
                pub_key,
                subject_name,
                measurements,
            },
        )?;
        self.internal.check_not_truncated()?;
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
        sign_cb: &mut (impl FnMut(&[u8], bool) -> Result<Signature, CryptoError> + ?Sized),
        pub_key: &PubKey,
        subject_name: &Name,
        measurements: &MeasurementData,
        sid: &SignerIdentifier,
    ) -> Result<usize, DpeErrorCode> {
        let mut size_bytes_written = self.internal.encode_byte(CertWriterInternal::SEQUENCE_TAG);
        let _ = self.internal.push_backtrack(SIZE_TAG_OFFSET)?;

        let mut bytes_written = self
            .internal
            .encode_oid(CertWriterInternal::ID_SIGNED_DATA_OID);

        bytes_written += self.internal.encode_byte(
            CertWriterInternal::CONTEXT_SPECIFIC | CertWriterInternal::CONSTRUCTED | 0x0,
        );
        let _ = self.internal.push_backtrack(SIZE_TAG_OFFSET)?;

        bytes_written += self
            .internal
            .encode_tag_field(CertWriterInternal::SEQUENCE_TAG);
        let _ = self.internal.push_backtrack(SIZE_TAG_OFFSET)?;

        bytes_written += self.internal.encode_cms_version(sid);

        bytes_written += self
            .internal
            .encode_tag_field(CertWriterInternal::SET_OF_TAG);
        let hash_alg_id_size = self.internal.get_hash_alg_id_size(/*tagged=*/ true)?;
        bytes_written += self.internal.encode_size_field(hash_alg_id_size);
        bytes_written += self.internal.encode_hash_alg_id()?;

        bytes_written +=
            self.encode_encapsulated_content_info(sign_cb, pub_key, subject_name, measurements)?;

        let csr = {
            let Some(csr_range) = self.internal.csr_range else {
                Err(DpeErrorCode::X509CsrUnset)?
            };
            self.internal
                .certificate
                .get(csr_range.0..csr_range.1)
                .ok_or(DpeErrorCode::InternalError)?
        };

        let sig = sign_cb(csr, false)?;

        let signed_data_field_0 = self.internal.get_signed_data_size(
            csr, &sig, sid, /*tagged=*/ true, /*explicit=*/ false,
        )?;

        let signed_data_field_1 = self.internal.get_signed_data_size(
            csr, &sig, sid, /*tagged=*/ false, /*explicit=*/ false,
        )?;

        bytes_written += self
            .internal
            .encode_tag_field(CertWriterInternal::SET_OF_TAG);
        let signer_info_size = self
            .internal
            .get_signer_info_size(&sig, sid, /*tagged=*/ true)?;
        bytes_written += self.internal.encode_size_field(signer_info_size);
        bytes_written += self.encode_signer_info(&sig, sid)?;

        {
            self.internal.start_backtrack()?;
            self.internal
                .pop_backtrack(CertWriterInternal::get_size_width(signed_data_field_1))?;
            bytes_written += self.internal.encode_size_field(signed_data_field_1);

            self.internal
                .pop_backtrack(CertWriterInternal::get_size_width(signed_data_field_0))?;
            bytes_written += self.internal.encode_size_field(signed_data_field_0);

            self.internal
                .pop_backtrack(CertWriterInternal::get_size_width(bytes_written))?;
            size_bytes_written += self.internal.encode_size_field(bytes_written);

            self.internal.end_backtrack()?;
        }

        if !self.internal.backtracks.is_empty() {
            return Err(DpeErrorCode::X509InvalidState);
        }

        self.internal.check_not_truncated()?;
        Ok(bytes_written + size_bytes_written)
    }

    #[cfg(not(feature = "disable_csr"))]
    #[allow(clippy::identity_op)]
    fn encode_encapsulated_content_info(
        &mut self,
        sign_cb: &mut (impl FnMut(&[u8], bool) -> Result<Signature, CryptoError> + ?Sized),
        pub_key: &PubKey,
        subject_name: &Name,
        measurements: &MeasurementData,
    ) -> Result<usize, DpeErrorCode> {
        let mut size_bytes_written = self.internal.encode_byte(CertWriterInternal::SEQUENCE_TAG);
        self.internal.push_backtrack(SIZE_TAG_OFFSET)?;

        let mut bytes_written = self.internal.encode_oid(CertWriterInternal::ID_DATA_OID);

        bytes_written += self.internal.encode_byte(
            CertWriterInternal::CONTEXT_SPECIFIC | CertWriterInternal::CONSTRUCTED | 0x0,
        );
        self.internal.push_backtrack(SIZE_TAG_OFFSET)?;

        bytes_written += self
            .internal
            .encode_byte(CertWriterInternal::OCTET_STRING_TAG);
        let offset = self.internal.push_backtrack(SIZE_TAG_OFFSET)?;

        let csr_bytes_written = self.encode_signed_payload(
            sign_cb,
            SignedPayload::CertReqInfo {
                pub_key,
                subject_name,
                measurements,
            },
        )?;
        self.internal.csr_range = Some((offset, offset + csr_bytes_written));

        let econtent_1_size = CertWriterInternal::get_econtent_size(
            csr_bytes_written,
            /*tagged=*/ false,
            /*explicit=*/ false,
        );

        let econtent_0_size = CertWriterInternal::get_econtent_size(
            csr_bytes_written,
            /*tagged=*/ true,
            /*explicit=*/ false,
        );

        {
            self.internal.start_backtrack()?;
            self.internal
                .pop_backtrack(CertWriterInternal::get_size_width(econtent_1_size))?;
            bytes_written += self.internal.encode_size_field(econtent_1_size);

            self.internal
                .pop_backtrack(CertWriterInternal::get_size_width(econtent_0_size))?;
            bytes_written += self.internal.encode_size_field(econtent_0_size);

            self.internal
                .pop_backtrack(CertWriterInternal::get_size_width(
                    bytes_written + csr_bytes_written,
                ))?;
            size_bytes_written += self
                .internal
                .encode_size_field(bytes_written + csr_bytes_written);
            self.internal.end_backtrack()?;
        }

        Ok(bytes_written + csr_bytes_written + size_bytes_written)
    }

    #[cfg(any(not(feature = "disable_x509"), not(feature = "disable_csr")))]
    fn encode_signed_payload(
        &mut self,
        sign_cb: &mut (impl FnMut(&[u8], bool) -> Result<Signature, CryptoError> + ?Sized),
        payload: SignedPayload,
    ) -> Result<usize, DpeErrorCode> {
        let mut prefix_bytes_written = self
            .internal
            .encode_tag_field(CertWriterInternal::SEQUENCE_TAG);
        let offset = self.internal.push_backtrack(SIZE_TAG_OFFSET)?;

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
                self.encode_tbs(
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
                self.encode_certification_request_info(pub_key, subject_name, measurements)?,
                true,
            ),
        };

        let sig = {
            let signed = self
                .internal
                .certificate
                .get(offset..payload_bytes_written + offset)
                .ok_or(DpeErrorCode::InternalError)?;
            sign_cb(signed, is_csr)
        };
        let sig = okref(&sig)?;

        let sig_bytes_written = self.internal.encode_signature_bit_string(sig)?;

        let body_size = payload_bytes_written + sig_bytes_written;

        {
            self.internal.start_backtrack()?;
            self.internal
                .pop_backtrack(CertWriterInternal::get_size_width(body_size))?;

            prefix_bytes_written += self.internal.encode_size_field(body_size);

            self.internal.end_backtrack()?;
        }

        Ok(body_size + prefix_bytes_written)
    }
}

/// The signed payload variants handled by [`CertWriter::encode_signed_payload`]:
/// an X.509 TBSCertificate or a PKCS #10 CertificationRequestInfo.
enum SignedPayload<'a> {
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

#[cfg(test)]
pub(crate) mod tests {
    use crate::dpe_instance::tests::DPE_PROFILE;
    use crate::tci::{TciMeasurement, TciNodeData};
    use crate::x509::internal::tests::{
        DEFAULT_OTHER_NAME_OID, DEFAULT_OTHER_NAME_VALUE, ECC_INT_SIZE, TEST_ISSUER_NAME,
        TEST_SERIAL, TEST_SUBJECT_NAME,
    };
    use crate::x509::internal::CertWriterInternal;
    use crate::x509::{CertWriter, DirectoryString, MeasurementData, Name};
    use crate::DpeErrorCode;
    use crate::DpeProfile;
    use caliptra_dpe_crypto::ecdsa::{EcdsaAlgorithm, EcdsaSig};
    use caliptra_dpe_crypto::ecdsa::{EcdsaPub, EcdsaPubKey};
    #[cfg(feature = "ml-dsa")]
    use caliptra_dpe_crypto::ml_dsa::MldsaPublicKey;
    #[cfg(feature = "ml-dsa")]
    use caliptra_dpe_crypto::ml_dsa::{MldsaAlgorithm, MldsaSignature};
    use caliptra_dpe_crypto::{PubKey, Signature, SignatureAlgorithm};
    use caliptra_dpe_platform::{
        ArrayVec, CertValidity, OtherName, SignerIdentifier, SubjectAltName,
        MAX_KEY_IDENTIFIER_SIZE,
    };
    use openssl::hash::{Hasher, MessageDigest};
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
            CertWriterInternal::get_rdn_size(&test_name, true),
            bytes_written
        );
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
        let exact = encode(&mut CertWriter::new(&mut big, DPE_PROFILE, true))
            .expect("encoding into a large buffer should succeed");

        let mut buf = vec![0u8; exact];
        assert_eq!(
            encode(&mut CertWriter::new(&mut buf, DPE_PROFILE, true)),
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
                encode(&mut CertWriter::new(writable, DPE_PROFILE, true)),
                Err(DpeErrorCode::InternalError),
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
        let issuer_len = CertWriter::new(&mut issuer_der, DPE_PROFILE, true)
            .encode_rdn(&TEST_ISSUER_NAME)
            .unwrap();
        let issuer = &issuer_der[..issuer_len];

        let node = TciNodeData::new();
        let subject_key_identifier = [0u8; MAX_KEY_IDENTIFIER_SIZE];
        let mut other_name = ArrayVec::new();
        other_name
            .try_extend_from_slice(DEFAULT_OTHER_NAME_VALUE.as_bytes())
            .unwrap();
        let measurements = MeasurementData {
            label: &[0; DPE_PROFILE.hash_size()],
            tci_nodes: &[node],
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
        #[cfg(not(feature = "ml-dsa"))]
        let (pub_key, test_sig) = {
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
                _ => panic!("Missing signature"),
            };
            let sig = Signature::Ecdsa(
                EcdsaSig::from_slice(&[0xCC; ECC_INT_SIZE], &[0xDD; ECC_INT_SIZE]).into(),
            );
            (pub_key, sig)
        };
        #[cfg(feature = "ml-dsa")]
        let (pub_key, test_sig) = {
            const ALGORITHM: MldsaAlgorithm = match DPE_PROFILE.alg() {
                SignatureAlgorithm::Mldsa(a) => a,
                _ => panic!("non ml-dsa profile"),
            };
            (
                PubKey::Mldsa(MldsaPublicKey::from_slice(
                    &[0xAA; ALGORITHM.public_key_size()],
                )),
                Signature::Mldsa(MldsaSignature([0xBB; ALGORITHM.signature_size()])),
            )
        };

        let mut sign_cb = |_data: &[u8], _use_derived: bool| Ok(test_sig.clone());

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
            )
        });
        assert_overflow_detected(|w| {
            w.encode_csr(&mut sign_cb, &pub_key, &TEST_SUBJECT_NAME, &measurements)
        });
        assert_overflow_detected(|w| {
            w.encode_cms(
                &mut sign_cb,
                &pub_key,
                &TEST_SUBJECT_NAME,
                &measurements,
                &sid,
            )
        });
    }
}
