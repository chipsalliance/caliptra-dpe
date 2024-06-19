// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::ContextHandle,
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{CertifyKeyResp, DpeErrorCode, Response, ResponseHdr},
    tci::TciNodeData,
    x509::{CertWriter, DirectoryString, MeasurementData, Name},
    DPE_PROFILE, MAX_CERT_SIZE, MAX_HANDLES,
};
use bitflags::bitflags;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::cfi_launder;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq};
use cfg_if::cfg_if;
use crypto::{Crypto, Hasher};
#[cfg(not(feature = "disable_x509"))]
use platform::MAX_ISSUER_NAME_SIZE;
use platform::{Platform, PlatformError, MAX_KEY_IDENTIFIER_SIZE};

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::FromBytes, zerocopy::AsBytes)]
pub struct CertifyKeyFlags(u32);

bitflags! {
    impl CertifyKeyFlags: u32 {
        const IS_CA = 1u32 << 30;
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::FromBytes, zerocopy::AsBytes)]
pub struct CertifyKeyCmd {
    pub handle: ContextHandle,
    pub flags: CertifyKeyFlags,
    pub format: u32,
    pub label: [u8; DPE_PROFILE.get_hash_size()],
}

impl CertifyKeyCmd {
    pub const FORMAT_X509: u32 = 0;
    pub const FORMAT_CSR: u32 = 1;

    const fn uses_is_ca(&self) -> bool {
        self.flags.contains(CertifyKeyFlags::IS_CA)
    }
}

impl CommandExecution for CertifyKeyCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        let idx = dpe.get_active_context_pos(&self.handle, locality)?;
        let context = &dpe.contexts[idx];

        if self.uses_is_ca() && !dpe.support.is_ca() {
            return Err(DpeErrorCode::ArgumentNotSupported);
        }
        if self.uses_is_ca() && !context.allow_ca() {
            return Err(DpeErrorCode::InvalidArgument);
        }

        if self.format == Self::FORMAT_X509 {
            if !dpe.support.x509() {
                return Err(DpeErrorCode::ArgumentNotSupported);
            }
            if !context.allow_x509() {
                return Err(DpeErrorCode::InvalidArgument);
            }
        } else if self.format == Self::FORMAT_CSR && !dpe.support.csr() {
            return Err(DpeErrorCode::ArgumentNotSupported);
        }

        // Make sure the command is coming from the right locality.
        if context.locality != locality {
            return Err(DpeErrorCode::InvalidLocality);
        }

        cfg_if! {
            if #[cfg(not(feature = "no-cfi"))] {
                cfi_assert!(!self.uses_is_ca() || dpe.support.is_ca());
                cfi_assert!(!self.uses_is_ca() || context.allow_ca());
                cfi_assert!(self.format != Self::FORMAT_X509 || dpe.support.x509());
                cfi_assert!(self.format != Self::FORMAT_X509 || context.allow_x509());
                cfi_assert!(self.format != Self::FORMAT_CSR || dpe.support.csr());
                cfi_assert_eq(context.locality, locality);
            }
        }

        let algs = DPE_PROFILE.alg_len();
        let digest = dpe.compute_measurement_hash(env, idx)?;
        let cdi = env
            .crypto
            .derive_cdi(DPE_PROFILE.alg_len(), &digest, b"DPE")?;
        let key_pair = env.crypto.derive_key_pair(algs, &cdi, &self.label, b"ECC");
        if cfi_launder(key_pair.is_ok()) {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(key_pair.is_ok());
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(key_pair.is_err());
        }
        #[allow(unused_variables)]
        let (priv_key, pub_key) = key_pair?;

        let mut subj_serial = [0u8; DPE_PROFILE.get_hash_size() * 2];
        env.crypto
            .get_pubkey_serial(DPE_PROFILE.alg_len(), &pub_key, &mut subj_serial)?;
        // The serial number of the subject can be at most 64 bytes
        let truncated_subj_serial = &subj_serial[..64];

        let subject_name = Name {
            cn: DirectoryString::PrintableString(b"DPE Leaf"),
            serial: DirectoryString::PrintableString(truncated_subj_serial),
        };

        // Get TCI Nodes
        const INITIALIZER: TciNodeData = TciNodeData::new();
        let mut nodes = [INITIALIZER; MAX_HANDLES];
        let tcb_count = dpe.get_tcb_nodes(idx, &mut nodes)?;
        if tcb_count > MAX_HANDLES {
            return Err(DpeErrorCode::InternalError);
        }

        let mut subject_key_identifier = [0u8; MAX_KEY_IDENTIFIER_SIZE];
        // compute key identifier as SHA hash of the DER encoded subject public key
        let mut hasher = env.crypto.hash_initialize(DPE_PROFILE.alg_len())?;
        hasher.update(&[0x04])?;
        hasher.update(pub_key.x.bytes())?;
        hasher.update(pub_key.y.bytes())?;
        let hashed_pub_key = hasher.finish()?;
        if hashed_pub_key.len() < MAX_KEY_IDENTIFIER_SIZE {
            return Err(DpeErrorCode::InternalError);
        }
        // truncate key identifier to 20 bytes
        subject_key_identifier.copy_from_slice(&hashed_pub_key.bytes()[..MAX_KEY_IDENTIFIER_SIZE]);

        let mut authority_key_identifier = [0u8; MAX_KEY_IDENTIFIER_SIZE];
        env.platform
            .get_issuer_key_identifier(&mut authority_key_identifier)?;

        let subject_alt_name = match env.platform.get_subject_alternative_name() {
            Ok(subject_alt_name) => Some(subject_alt_name),
            Err(PlatformError::NotImplemented) => None,
            Err(e) => Err(DpeErrorCode::Platform(e))?,
        };

        let measurements = MeasurementData {
            label: &self.label,
            tci_nodes: &nodes[..tcb_count],
            is_ca: self.uses_is_ca(),
            supports_recursive: dpe.support.recursive(),
            subject_key_identifier,
            authority_key_identifier,
            subject_alt_name,
        };

        let mut cert = [0u8; MAX_CERT_SIZE];
        let cert_size = match self.format {
            Self::FORMAT_X509 => {
                cfg_if! {
                    if #[cfg(not(feature = "disable_x509"))] {
                        let mut issuer_name = [0u8; MAX_ISSUER_NAME_SIZE];
                        let issuer_len = env.platform.get_issuer_name(&mut issuer_name)?;
                        #[cfg(not(feature = "no-cfi"))]
                        cfi_assert_eq(self.format, Self::FORMAT_X509);
                        let mut tbs_buffer = [0u8; MAX_CERT_SIZE];
                        let mut tbs_writer = CertWriter::new(&mut tbs_buffer, true);
                        if issuer_len > MAX_ISSUER_NAME_SIZE {
                            return Err(DpeErrorCode::InternalError);
                        }
                        let cert_validity = env.platform.get_cert_validity()?;
                        let mut bytes_written = tbs_writer.encode_ecdsa_tbs(
                            /*serial=*/
                            &subject_name.serial.bytes()[..20], // Serial number must be truncated to 20 bytes
                            &issuer_name[..issuer_len],
                            &subject_name,
                            &pub_key,
                            &measurements,
                            &cert_validity,
                        )?;
                        if bytes_written > MAX_CERT_SIZE {
                            return Err(DpeErrorCode::InternalError);
                        }

                        let tbs_digest = env
                            .crypto
                            .hash(DPE_PROFILE.alg_len(), &tbs_buffer[..bytes_written])?;
                        let sig = env
                            .crypto
                            .ecdsa_sign_with_alias(DPE_PROFILE.alg_len(), &tbs_digest)?;

                        let mut cert_writer = CertWriter::new(&mut cert, true);
                        bytes_written =
                            cert_writer.encode_ecdsa_certificate(&tbs_buffer[..bytes_written], &sig)?;
                        u32::try_from(bytes_written).map_err(|_| DpeErrorCode::InternalError)?
                    } else {
                        Err(DpeErrorCode::ArgumentNotSupported)?
                    }
                }
            }
            Self::FORMAT_CSR => {
                cfg_if! {
                    if #[cfg(not(feature = "disable_csr"))] {
                        #[cfg(not(feature = "no-cfi"))]
                        cfi_assert_eq(self.format, Self::FORMAT_CSR);
                        let mut cert_req_info_buffer = [0u8; MAX_CERT_SIZE];
                        let mut cert_req_info_writer = CertWriter::new(&mut cert_req_info_buffer, true);
                        let mut bytes_written = cert_req_info_writer
                            .encode_certification_request_info(
                                &pub_key,
                                &subject_name,
                                &measurements,
                            )?;
                        if bytes_written > MAX_CERT_SIZE {
                            return Err(DpeErrorCode::InternalError);
                        }

                        let cert_req_info_digest = env.crypto.hash(
                            DPE_PROFILE.alg_len(),
                            &cert_req_info_buffer[..bytes_written],
                        )?;
                        // The PKCS#10 CSR is self-signed so the private key signs it instead of the alias key.
                        let cert_req_info_sig = env.crypto.ecdsa_sign_with_derived(
                            DPE_PROFILE.alg_len(),
                            &cert_req_info_digest,
                            &priv_key,
                            &pub_key,
                        )?;

                        let mut csr_buffer = [0u8; MAX_CERT_SIZE];
                        let mut csr_writer = CertWriter::new(&mut csr_buffer, true);
                        bytes_written = csr_writer
                            .encode_csr(&cert_req_info_buffer[..bytes_written], &cert_req_info_sig)?;
                        if bytes_written > MAX_CERT_SIZE {
                            return Err(DpeErrorCode::InternalError);
                        }

                        let csr_digest = env
                            .crypto
                            .hash(DPE_PROFILE.alg_len(), &csr_buffer[..bytes_written])?;
                        let csr_sig = env
                            .crypto
                            .ecdsa_sign_with_alias(DPE_PROFILE.alg_len(), &csr_digest)?;
                        let sid = env.platform.get_signer_identifier()?;

                        let mut cms_writer = CertWriter::new(&mut cert, true);
                        bytes_written =
                            cms_writer.encode_cms(&csr_buffer[..bytes_written], &csr_sig, &sid)?;
                        u32::try_from(bytes_written).map_err(|_| DpeErrorCode::InternalError)?
                    } else {
                        Err(DpeErrorCode::ArgumentNotSupported)?
                    }
                }
            }
            _ => return Err(DpeErrorCode::InvalidArgument),
        };

        let derived_pubkey_x: [u8; DPE_PROFILE.get_ecc_int_size()] =
            pub_key
                .x
                .bytes()
                .try_into()
                .map_err(|_| DpeErrorCode::InternalError)?;
        let derived_pubkey_y: [u8; DPE_PROFILE.get_ecc_int_size()] =
            pub_key
                .y
                .bytes()
                .try_into()
                .map_err(|_| DpeErrorCode::InternalError)?;

        // Rotate handle if it isn't the default
        dpe.roll_onetime_use_handle(env, idx)?;

        Ok(Response::CertifyKey(CertifyKeyResp {
            new_context_handle: dpe.contexts[idx].handle,
            derived_pubkey_x,
            derived_pubkey_y,
            cert_size,
            cert,
            resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{Command, CommandHdr, DeriveContextCmd, DeriveContextFlags, InitCtxCmd},
        dpe_instance::tests::{TestTypes, SIMULATION_HANDLE, TEST_LOCALITIES},
        support::Support,
        x509::tests::TcbInfo,
        DpeProfile,
    };
    use caliptra_cfi_lib_git::CfiCounter;
    use cms::{
        content_info::{CmsVersion, ContentInfo},
        signed_data::{SignedData, SignerIdentifier},
    };
    use crypto::{AlgLen, CryptoBuf, EcdsaPub, OpensslCrypto};
    use der::{Decode, Encode};
    use openssl::{
        bn::BigNum,
        ec::{EcGroup, EcKey},
        ecdsa::EcdsaSig,
        hash::{Hasher, MessageDigest},
        nid::*,
    };
    use platform::default::DefaultPlatform;
    use spki::ObjectIdentifier;
    use std::str;
    use x509_parser::nom::Parser;
    use x509_parser::oid_registry::asn1_rs::oid;
    use x509_parser::prelude::public_key::PublicKey;
    use x509_parser::prelude::X509CertificateParser;
    use x509_parser::prelude::X509CertificationRequest;
    use x509_parser::prelude::*;
    use zerocopy::AsBytes;

    const TEST_CERTIFY_KEY_CMD: CertifyKeyCmd = CertifyKeyCmd {
        handle: SIMULATION_HANDLE,
        flags: CertifyKeyFlags(0x1234_5678),
        label: [0xaa; DPE_PROFILE.get_hash_size()],
        format: CertifyKeyCmd::FORMAT_X509,
    };

    #[test]
    fn test_deserialize_certify_key() {
        CfiCounter::reset_for_test();
        let mut command = CommandHdr::new_for_test(Command::CERTIFY_KEY)
            .as_bytes()
            .to_vec();
        command.extend(TEST_CERTIFY_KEY_CMD.as_bytes());
        assert_eq!(
            Ok(Command::CertifyKey(TEST_CERTIFY_KEY_CMD)),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_certify_key_x509() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::X509).unwrap();

        let init_resp = match InitCtxCmd::new_use_default()
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap()
        {
            Response::InitCtx(resp) => resp,
            _ => panic!("Incorrect return type."),
        };
        let certify_cmd = CertifyKeyCmd {
            handle: init_resp.handle,
            flags: CertifyKeyFlags::empty(),
            label: [0; DPE_PROFILE.get_hash_size()],
            format: CertifyKeyCmd::FORMAT_X509,
        };

        let certify_resp = match certify_cmd
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap()
        {
            Response::CertifyKey(resp) => resp,
            _ => panic!("Wrong response type."),
        };
        assert_ne!(certify_resp.cert_size, 0);

        let mut parser = X509CertificateParser::new().with_deep_parse_extensions(false);
        match parser.parse(&certify_resp.cert[..certify_resp.cert_size.try_into().unwrap()]) {
            Ok((_, cert)) => {
                assert_eq!(cert.version(), X509Version::V3);
            }
            Err(e) => panic!("x509 parsing failed: {:?}", e),
        };
    }

    #[test]
    fn test_is_ca() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::X509 | Support::IS_CA).unwrap();

        let init_resp = match InitCtxCmd::new_use_default()
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap()
        {
            Response::InitCtx(resp) => resp,
            _ => panic!("Incorrect return type."),
        };
        let certify_cmd_ca = CertifyKeyCmd {
            handle: init_resp.handle,
            flags: CertifyKeyFlags::IS_CA,
            label: [0; DPE_PROFILE.get_hash_size()],
            format: CertifyKeyCmd::FORMAT_X509,
        };

        let certify_resp_ca = match certify_cmd_ca
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap()
        {
            Response::CertifyKey(resp) => resp,
            _ => panic!("Wrong response type."),
        };

        let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
        match parser.parse(&certify_resp_ca.cert[..certify_resp_ca.cert_size.try_into().unwrap()]) {
            Ok((_, cert)) => {
                match cert.basic_constraints() {
                    Ok(Some(basic_constraints)) => {
                        assert!(basic_constraints.value.ca);
                    }
                    Ok(None) => panic!("basic constraints extension not found"),
                    Err(_) => panic!("multiple basic constraints extensions found"),
                }

                let pub_key = &cert.tbs_certificate.subject_pki.subject_public_key.data;
                let mut hasher = match DPE_PROFILE {
                    DpeProfile::P256Sha256 => Hasher::new(MessageDigest::sha256()).unwrap(),
                    DpeProfile::P384Sha384 => Hasher::new(MessageDigest::sha384()).unwrap(),
                };
                hasher.update(pub_key).unwrap();
                let expected_ski: &[u8] = &hasher.finish().unwrap();
                match cert.get_extension_unique(&oid!(2.5.29 .14)) {
                    Ok(Some(subject_key_identifier_ext)) => {
                        if let ParsedExtension::SubjectKeyIdentifier(key_identifier) =
                            subject_key_identifier_ext.parsed_extension()
                        {
                            assert_eq!(key_identifier.0, &expected_ski[..MAX_KEY_IDENTIFIER_SIZE]);
                        } else {
                            panic!("Extension has wrong type");
                        }
                    }
                    Ok(None) => panic!("subject key identifier extension not found"),
                    Err(_) => panic!("multiple subject key identifier extensions found"),
                }

                let mut expected_aki = [0u8; MAX_KEY_IDENTIFIER_SIZE];
                env.platform
                    .get_issuer_key_identifier(&mut expected_aki)
                    .unwrap();
                match cert.get_extension_unique(&oid!(2.5.29 .35)) {
                    Ok(Some(extension)) => {
                        if let ParsedExtension::AuthorityKeyIdentifier(aki) =
                            extension.parsed_extension()
                        {
                            let key_identifier = aki.key_identifier.clone().unwrap();
                            assert_eq!(&key_identifier.0, &expected_aki,);
                        } else {
                            panic!("Extension has wrong type");
                        }
                    }
                    Ok(None) => panic!("authority key identifier extension not found"),
                    Err(_) => panic!("multiple authority key identifier extensions found"),
                }
            }
            Err(e) => panic!("x509 parsing failed: {:?}", e),
        };

        let certify_cmd_non_ca = CertifyKeyCmd {
            handle: init_resp.handle,
            flags: CertifyKeyFlags::empty(),
            label: [0; DPE_PROFILE.get_hash_size()],
            format: CertifyKeyCmd::FORMAT_X509,
        };

        let certify_resp_non_ca = match certify_cmd_non_ca
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap()
        {
            Response::CertifyKey(resp) => resp,
            _ => panic!("Wrong response type."),
        };

        match parser
            .parse(&certify_resp_non_ca.cert[..certify_resp_non_ca.cert_size.try_into().unwrap()])
        {
            Ok((_, cert)) => match cert.basic_constraints() {
                Ok(Some(basic_constraints)) => {
                    assert!(!basic_constraints.value.ca);
                }
                Ok(None) => panic!("basic constraints extension not found"),
                Err(_) => panic!("multiple basic constraints extensions found"),
            },
            Err(e) => panic!("x509 parsing failed: {:?}", e),
        };
    }

    #[test]
    fn test_certify_key_csr() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::CSR).unwrap();

        let init_resp = match InitCtxCmd::new_use_default()
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap()
        {
            Response::InitCtx(resp) => resp,
            _ => panic!("Incorrect return type."),
        };
        let certify_cmd = CertifyKeyCmd {
            handle: init_resp.handle,
            flags: CertifyKeyFlags::empty(),
            label: [0; DPE_PROFILE.get_hash_size()],
            format: CertifyKeyCmd::FORMAT_CSR,
        };

        let certify_resp = match certify_cmd
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap()
        {
            Response::CertifyKey(resp) => resp,
            _ => panic!("Wrong response type."),
        };
        assert_ne!(certify_resp.cert_size, 0);

        // parse CMS ContentInfo
        let content_info =
            ContentInfo::from_der(&certify_resp.cert[..certify_resp.cert_size.try_into().unwrap()])
                .unwrap();
        // parse SignedData
        let mut signed_data =
            SignedData::from_der(&content_info.content.to_der().unwrap()).unwrap();
        assert_eq!(signed_data.version, CmsVersion::V1);

        // optional field certificates is not populated
        assert!(signed_data.certificates.is_none());
        // optional field crls is not populated
        assert!(signed_data.crls.is_none());

        // validate hash algorithm OID
        assert_eq!(signed_data.digest_algorithms.len(), 1);
        let digest_alg = &signed_data.digest_algorithms.get(0).unwrap();
        let hash_alg_oid = match DPE_PROFILE.alg_len() {
            AlgLen::Bit256 => "2.16.840.1.101.3.4.2.1",
            AlgLen::Bit384 => "2.16.840.1.101.3.4.2.2",
        };
        assert!(digest_alg
            .assert_algorithm_oid(ObjectIdentifier::new_unwrap(hash_alg_oid))
            .is_ok());

        // validate signer infos
        let signer_infos = signed_data.signer_infos.0;
        // ensure there is only 1 signer info
        assert_eq!(signer_infos.len(), 1);
        let signer_info = signer_infos.get(0).unwrap();
        assert_eq!(signer_info.version, CmsVersion::V1);

        // optional field signed_attrs is not populated
        assert!(signer_info.signed_attrs.is_none());

        // optional field unsigned_attrs is not populated
        assert!(signer_info.unsigned_attrs.is_none());

        // validate hash algorithm OID
        assert!(signer_info
            .digest_alg
            .assert_algorithm_oid(ObjectIdentifier::new_unwrap(hash_alg_oid))
            .is_ok());

        // validate signature algorithm OID
        let sig_alg_oid = match DPE_PROFILE.alg_len() {
            AlgLen::Bit256 => "1.2.840.10045.4.3.2",
            AlgLen::Bit384 => "1.2.840.10045.4.3.3",
        };
        assert!(signer_info
            .signature_algorithm
            .assert_algorithm_oid(ObjectIdentifier::new_unwrap(sig_alg_oid))
            .is_ok());

        // validate signer identifier
        let sid = &signer_info.sid;
        match sid {
            SignerIdentifier::IssuerAndSerialNumber(issuer_and_serial_number) => {
                let cert_serial_number = &issuer_and_serial_number.serial_number;
                let cert_issuer_name = &issuer_and_serial_number.issuer.to_der().unwrap();

                let platform::SignerIdentifier::IssuerAndSerialNumber {
                    issuer_name,
                    serial_number,
                } = env.platform.get_signer_identifier().unwrap()
                else {
                    panic!("Error: Signer Identifier is not IssuerAndSerialNumber in default platform!")
                };

                assert_eq!(serial_number.as_bytes(), cert_serial_number.as_bytes());
                assert_eq!(issuer_name.as_bytes(), cert_issuer_name.as_bytes())
            }
            _ => panic!("Error: Signer Identifier is not IssuerAndSerialNumber!"),
        };

        // parse encapsulated content info
        let econtent_info = &mut signed_data.encap_content_info;
        assert_eq!(
            econtent_info.econtent_type.to_string(),
            "1.2.840.113549.1.7.1"
        );
        // skip first 4 explicit encoding bytes
        let econtent = &econtent_info.econtent.as_mut().unwrap().to_der().unwrap()[4..];

        // validate csr signature with the alias key
        let csr_digest = env.crypto.hash(DPE_PROFILE.alg_len(), &econtent).unwrap();
        let priv_key = match DPE_PROFILE.alg_len() {
            AlgLen::Bit256 => EcKey::private_key_from_der(include_bytes!(
                "../../../platform/src/test_data/key_256.der"
            )),
            AlgLen::Bit384 => EcKey::private_key_from_der(include_bytes!(
                "../../../platform/src/test_data/key_384.der"
            )),
        }
        .unwrap();
        let curve = match DPE_PROFILE.alg_len() {
            AlgLen::Bit256 => Nid::X9_62_PRIME256V1,
            AlgLen::Bit384 => Nid::SECP384R1,
        };
        let group = &EcGroup::from_curve_name(curve).unwrap();
        let alias_key = EcKey::from_public_key(group, priv_key.public_key()).unwrap();
        let csr_sig = EcdsaSig::from_der(signer_info.signature.as_bytes()).unwrap();
        assert!(csr_sig.verify(csr_digest.bytes(), &alias_key).unwrap());

        // validate csr
        let (_, csr) = X509CertificationRequest::from_der(&econtent).unwrap();
        let cri = csr.certification_request_info;
        assert_eq!(cri.version.0, 0);
        assert_eq!(
            csr.signature_algorithm.algorithm.to_id_string(),
            sig_alg_oid
        );

        // validate certification request info signature
        let cri_sig = EcdsaSig::from_der(csr.signature_value.data.as_ref()).unwrap();

        // validate certification request info subject pki
        let PublicKey::EC(ec_point) = cri.subject_pki.parsed().unwrap() else {
            panic!("Error: Failed to parse public key correctly.");
        };
        let pub_key_der = ec_point.data();
        // skip first 0x04 der encoding byte
        let x = BigNum::from_slice(&pub_key_der[1..DPE_PROFILE.get_ecc_int_size() + 1]).unwrap();
        let y = BigNum::from_slice(&pub_key_der[DPE_PROFILE.get_ecc_int_size() + 1..]).unwrap();
        let pub_key = EcKey::from_public_key_affine_coordinates(group, &x, &y).unwrap();

        let cri_digest = env.crypto.hash(DPE_PROFILE.alg_len(), &cri.raw).unwrap();
        assert!(cri_sig.verify(cri_digest.bytes(), &pub_key).unwrap());

        // validate subject_name
        let mut subj_serial = [0u8; DPE_PROFILE.get_hash_size() * 2];
        let pub_key = EcdsaPub {
            x: CryptoBuf::new(&certify_resp.derived_pubkey_x).unwrap(),
            y: CryptoBuf::new(&certify_resp.derived_pubkey_y).unwrap(),
        };
        env.crypto
            .get_pubkey_serial(DPE_PROFILE.alg_len(), &pub_key, &mut subj_serial)
            .unwrap();
        let truncated_subj_serial = &subj_serial[..64];
        let subject_name = Name {
            cn: DirectoryString::PrintableString(b"DPE Leaf"),
            serial: DirectoryString::PrintableString(truncated_subj_serial),
        };
        let expected_subject_name = format!(
            "CN={}, serialNumber={}",
            str::from_utf8(subject_name.cn.bytes()).unwrap(),
            str::from_utf8(&subject_name.serial.bytes()).unwrap()
        );
        let actual_subject_name = cri.subject.to_string_with_registry(oid_registry()).unwrap();
        assert_eq!(expected_subject_name, actual_subject_name);

        // validate attributes/extensions
        let attributes = cri.attributes();
        assert_eq!(attributes.len(), 1);
        let attribute = attributes[0].parsed_attribute();
        let ParsedCriAttribute::ExtensionRequest(extension_req) = attribute else {
            panic!(
                "Error: Certification Request Info does not have the Extension Request attribute!"
            );
        };
        for extension in &extension_req.extensions {
            match extension.parsed_extension() {
                ParsedExtension::BasicConstraints(basic_constraints) => {
                    // IS_CA not set so this will be false
                    assert!(!basic_constraints.ca);
                }
                ParsedExtension::KeyUsage(key_usage) => {
                    assert!(KeyUsage::digital_signature(key_usage));
                    assert!(!KeyUsage::key_cert_sign(key_usage));
                }
                ParsedExtension::ExtendedKeyUsage(extended_key_usage) => {
                    // Expect tcg-dice-kp-eca OID (2.23.133.5.4.100.9)
                    assert_eq!(extended_key_usage.other, [oid!(2.23.133 .5 .4 .100 .9)]);
                }
                ParsedExtension::UnsupportedExtension { oid } => {
                    // Must be a UEID or MultiTcbInfo extension
                    if *oid != oid!(2.23.133 .5 .4 .5) && *oid != oid!(2.23.133 .5 .4 .4) {
                        panic!("Error: Unparsed extension has unexpected OID: {:?}", oid);
                    }
                }
                _ => panic!(
                    "Error: Unexpected extension found {:?}",
                    extension.parsed_extension()
                ),
            };
            assert!(extension.critical);
        }
    }

    #[test]
    fn test_certify_key_order() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::X509 | Support::AUTO_INIT).unwrap();

        // Derive context twice with different types
        let derive_cmd = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [1; DPE_PROFILE.get_tci_size()],
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INPUT_ALLOW_X509,
            tci_type: 1,
            target_locality: 0,
        };

        derive_cmd
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap();

        let certify_cmd = CertifyKeyCmd {
            handle: ContextHandle::default(),
            flags: CertifyKeyFlags(0),
            label: [0; DPE_PROFILE.get_hash_size()],
            format: CertifyKeyCmd::FORMAT_X509,
        };

        let certify_resp = match certify_cmd
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap()
        {
            Response::CertifyKey(resp) => resp,
            _ => panic!("Wrong response type."),
        };

        let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
        let (_, cert) = parser
            .parse(&certify_resp.cert[..certify_resp.cert_size.try_into().unwrap()])
            .unwrap();

        let multi_tcb_info = cert
            .get_extension_unique(&oid!(2.23.133 .5 .4 .5))
            .unwrap()
            .unwrap();
        let mut parsed_tcb_infos =
            asn1::parse_single::<asn1::SequenceOf<TcbInfo>>(multi_tcb_info.value).unwrap();

        let first = parsed_tcb_infos.next().unwrap();
        let second = parsed_tcb_infos.next().unwrap();

        assert_eq!(first.tci_type.unwrap(), &[0, 0, 0, 0]);
        assert_eq!(second.tci_type.unwrap(), &[0, 0, 0, 1]);
        assert!(parsed_tcb_infos.next().is_none());
    }
}
