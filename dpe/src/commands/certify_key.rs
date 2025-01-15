// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::ContextHandle,
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{CertifyKeyResp, DpeErrorCode, Response, ResponseHdr},
    x509::{create_dpe_cert, create_dpe_csr, CreateDpeCertArgs, CreateDpeCertResult},
    DPE_PROFILE, MAX_CERT_SIZE,
};
use bitflags::bitflags;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq};
use cfg_if::cfg_if;
#[cfg(not(feature = "disable_x509"))]
#[repr(C)]
#[derive(
    Debug,
    PartialEq,
    Eq,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
pub struct CertifyKeyFlags(u32);

bitflags! {
    impl CertifyKeyFlags: u32 {}
}

#[repr(C)]
#[derive(
    Debug,
    PartialEq,
    Eq,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
pub struct CertifyKeyCmd {
    pub handle: ContextHandle,
    pub flags: CertifyKeyFlags,
    pub format: u32,
    pub label: [u8; DPE_PROFILE.get_hash_size()],
}

impl CertifyKeyCmd {
    pub const FORMAT_X509: u32 = 0;
    pub const FORMAT_CSR: u32 = 1;
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
                cfi_assert!(self.format != Self::FORMAT_X509 || dpe.support.x509());
                cfi_assert!(self.format != Self::FORMAT_X509 || context.allow_x509());
                cfi_assert!(self.format != Self::FORMAT_CSR || dpe.support.csr());
                cfi_assert_eq(context.locality, locality);
            }
        }

        let args = CreateDpeCertArgs {
            handle: &self.handle,
            locality,
            cdi_label: b"DPE",
            key_label: &self.label,
            context: b"ECC",
        };
        let mut cert = [0; MAX_CERT_SIZE];

        let CreateDpeCertResult {
            cert_size, pub_key, ..
        } = match self.format {
            Self::FORMAT_X509 => {
                cfg_if! {
                    if #[cfg(not(feature = "disable_x509"))] {
                        #[cfg(not(feature = "no-cfi"))]
                        cfi_assert_eq(self.format, Self::FORMAT_X509);
                        create_dpe_cert(&args, dpe, env, &mut cert)
                    } else {
                        Err(DpeErrorCode::ArgumentNotSupported)
                    }
                }
            }
            Self::FORMAT_CSR => {
                cfg_if! {
                    if #[cfg(not(feature = "disable_csr"))] {
                        #[cfg(not(feature = "no-cfi"))]
                        cfi_assert_eq(self.format, Self::FORMAT_CSR);
                        create_dpe_csr(&args, dpe, env, &mut cert)
                    } else {
                        Err(DpeErrorCode::ArgumentNotSupported)
                    }
                }
            }
            _ => return Err(DpeErrorCode::InvalidArgument),
        }?;

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
        x509::{tests::TcbInfo, DirectoryString, Name},
    };
    use caliptra_cfi_lib_git::CfiCounter;
    use cms::{
        content_info::{CmsVersion, ContentInfo},
        signed_data::{SignedData, SignerIdentifier},
    };
    use crypto::{AlgLen, Crypto, CryptoBuf, EcdsaPub, OpensslCrypto};
    use der::{Decode, Encode};
    use openssl::{
        bn::BigNum,
        ec::{EcGroup, EcKey},
        ecdsa::EcdsaSig,
        nid::*,
    };
    use platform::{default::DefaultPlatform, Platform};
    use spki::ObjectIdentifier;
    use std::str;
    use x509_parser::nom::Parser;
    use x509_parser::oid_registry::asn1_rs::oid;
    use x509_parser::prelude::public_key::PublicKey;
    use x509_parser::prelude::X509CertificateParser;
    use x509_parser::prelude::X509CertificationRequest;
    use x509_parser::prelude::*;
    use zerocopy::IntoBytes;

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
            Ok(Command::CertifyKey(&TEST_CERTIFY_KEY_CMD)),
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
        assert_eq!(second.tci_type.unwrap(), &[1, 0, 0, 0]);
        assert!(parsed_tcb_infos.next().is_none());
    }
}
