// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::ContextHandle,
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{CertifyKeyResp, DpeErrorCode, Response},
    x509::{create_dpe_cert, create_dpe_csr, CreateDpeCertArgs, CreateDpeCertResult},
    DpeFlags, DpeProfile, MAX_CERT_SIZE,
};
use bitflags::bitflags;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq};
use cfg_if::cfg_if;
use crypto::{ecdsa::EcdsaPubKey, PubKey};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[cfg(not(feature = "disable_x509"))]
#[repr(C)]
#[derive(Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct CertifyKeyFlags(pub u32);

bitflags! {
    impl CertifyKeyFlags: u32 {}
}

#[derive(Debug, PartialEq, Eq)]
pub enum CertifyKeyCommand<'a> {
    #[cfg(feature = "dpe_profile_p256_sha256")]
    P256(&'a CertifyKeyP256Cmd),
    #[cfg(feature = "dpe_profile_p384_sha384")]
    P384(&'a CertifyKeyP384Cmd),
    #[cfg(feature = "ml-dsa")]
    ExternalMu87(&'a CertifyKeyMldsaExternalMu87Cmd),
}

impl CertifyKeyCommand<'_> {
    pub const FORMAT_X509: u32 = 0;
    pub const FORMAT_CSR: u32 = 1;

    pub fn deserialize(
        profile: DpeProfile,
        bytes: &[u8],
    ) -> Result<CertifyKeyCommand, DpeErrorCode> {
        match profile {
            #[cfg(feature = "dpe_profile_p256_sha256")]
            DpeProfile::P256Sha256 => {
                CertifyKeyCommand::parse_command(CertifyKeyCommand::P256, bytes)
            }
            #[cfg(feature = "dpe_profile_p384_sha384")]
            DpeProfile::P384Sha384 => {
                CertifyKeyCommand::parse_command(CertifyKeyCommand::P384, bytes)
            }
            #[cfg(feature = "ml-dsa")]
            DpeProfile::Mldsa87ExternalMu => {
                CertifyKeyCommand::parse_command(CertifyKeyCommand::ExternalMu87, bytes)
            }
            _ => Err(DpeErrorCode::InvalidArgument)?,
        }
    }

    pub fn parse_command<'a, T: FromBytes + KnownLayout + Immutable + 'a>(
        build: impl FnOnce(&'a T) -> CertifyKeyCommand<'a>,
        bytes: &'a [u8],
    ) -> Result<CertifyKeyCommand<'a>, DpeErrorCode> {
        let (prefix, _remaining_bytes) =
            T::ref_from_prefix(bytes).map_err(|_| DpeErrorCode::InvalidArgument)?;
        Ok(build(prefix))
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            #[cfg(feature = "dpe_profile_p256_sha256")]
            CertifyKeyCommand::P256(cmd) => cmd.as_bytes(),
            #[cfg(feature = "dpe_profile_p384_sha384")]
            CertifyKeyCommand::P384(cmd) => cmd.as_bytes(),
            #[cfg(feature = "ml-dsa")]
            CertifyKeyCommand::ExternalMu87(cmd) => cmd.as_bytes(),
        }
    }
}

#[cfg(feature = "dpe_profile_p256_sha256")]
impl<'a> From<&'a CertifyKeyP256Cmd> for CertifyKeyCommand<'a> {
    fn from(value: &'a CertifyKeyP256Cmd) -> Self {
        CertifyKeyCommand::P256(value)
    }
}

#[cfg(feature = "dpe_profile_p384_sha384")]
impl<'a> From<&'a CertifyKeyP384Cmd> for CertifyKeyCommand<'a> {
    fn from(value: &'a CertifyKeyP384Cmd) -> Self {
        CertifyKeyCommand::P384(value)
    }
}

#[cfg(feature = "ml-dsa")]
impl<'a> From<&'a CertifyKeyMldsaExternalMu87Cmd> for CertifyKeyCommand<'a> {
    fn from(value: &'a CertifyKeyMldsaExternalMu87Cmd) -> Self {
        CertifyKeyCommand::ExternalMu87(value)
    }
}

impl CommandExecution for CertifyKeyCommand<'_> {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        let (handle, format, label) = match *self {
            #[cfg(feature = "dpe_profile_p256_sha256")]
            CertifyKeyCommand::P256(cmd) => (&cmd.handle, cmd.format, cmd.label.as_slice()),
            #[cfg(feature = "dpe_profile_p384_sha384")]
            CertifyKeyCommand::P384(cmd) => (&cmd.handle, cmd.format, cmd.label.as_slice()),
            #[cfg(feature = "ml-dsa")]
            CertifyKeyCommand::ExternalMu87(cmd) => (&cmd.handle, cmd.format, cmd.label.as_slice()),
        };
        let idx = env.state.get_active_context_pos(handle, locality)?;
        let context = &env.state.contexts[idx];

        if format == Self::FORMAT_X509 {
            if !env.state.support.x509() {
                return Err(DpeErrorCode::ArgumentNotSupported);
            }
        } else if format == Self::FORMAT_CSR && !env.state.support.csr() {
            return Err(DpeErrorCode::ArgumentNotSupported);
        }

        // Make sure the command is coming from the right locality.
        if context.locality != locality {
            return Err(DpeErrorCode::InvalidLocality);
        }

        cfg_if! {
            if #[cfg(not(feature = "no-cfi"))] {
                cfi_assert!(format != Self::FORMAT_X509 || env.state.support.x509());
                cfi_assert!(format != Self::FORMAT_CSR || env.state.support.csr());
                cfi_assert_eq(context.locality, locality);
            }
        }

        let args = CreateDpeCertArgs {
            handle,
            locality,
            cdi_label: b"DPE",
            key_label: label,
            context: b"ECC",
            ueid: label,
            dice_extensions_are_critical: env
                .state
                .flags
                .contains(DpeFlags::MARK_DICE_EXTENSIONS_CRITICAL),
        };
        let mut cert = [0; MAX_CERT_SIZE];

        let CreateDpeCertResult {
            cert_size, pub_key, ..
        } = match format {
            Self::FORMAT_X509 => {
                cfg_if! {
                    if #[cfg(not(feature = "disable_x509"))] {
                        #[cfg(not(feature = "no-cfi"))]
                        cfi_assert_eq(format, Self::FORMAT_X509);
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
                        cfi_assert_eq(format, Self::FORMAT_CSR);
                        create_dpe_csr(&args, dpe, env, &mut cert)
                    } else {
                        Err(DpeErrorCode::ArgumentNotSupported)
                    }
                }
            }
            _ => return Err(DpeErrorCode::InvalidArgument),
        }?;

        let mut response = match pub_key {
            #[cfg(feature = "dpe_profile_p256_sha256")]
            PubKey::Ecdsa(EcdsaPubKey::Ecdsa256(pub_key)) => {
                let (x, y) = pub_key.as_slice();
                CertifyKeyResp::P256(crate::response::CertifyKeyP256Resp {
                    new_context_handle: ContextHandle::new_invalid(),
                    derived_pubkey_x: *x,
                    derived_pubkey_y: *y,
                    cert_size,
                    cert,
                    resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
                })
            }
            #[cfg(feature = "dpe_profile_p384_sha384")]
            PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(pub_key)) => {
                let (x, y) = pub_key.as_slice();
                CertifyKeyResp::P384(crate::response::CertifyKeyP384Resp {
                    new_context_handle: ContextHandle::new_invalid(),
                    derived_pubkey_x: *x,
                    derived_pubkey_y: *y,
                    cert_size,
                    cert,
                    resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
                })
            }
            #[cfg(feature = "ml-dsa")]
            PubKey::MlDsa(crypto::ml_dsa::MldsaPublicKey(pubkey)) => {
                CertifyKeyResp::MldsaExternalMu87(
                    crate::response::CertifyKeyMldsaExternalMu87Resp {
                        new_context_handle: ContextHandle::new_invalid(),
                        pubkey,
                        cert_size,
                        cert,
                        resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
                    },
                )
            }
            _ => Err(DpeErrorCode::InvalidArgument)?,
        };

        // Rotate handle if it isn't the default
        dpe.roll_onetime_use_handle(env, idx)?;
        response.set_handle(&env.state.contexts[idx].handle);

        Ok(Response::CertifyKey(response))
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct CertifyKeyP256Cmd {
    pub handle: ContextHandle,
    pub flags: CertifyKeyFlags,
    pub format: u32,
    pub label: [u8; 32],
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct CertifyKeyP384Cmd {
    pub handle: ContextHandle,
    pub flags: CertifyKeyFlags,
    pub format: u32,
    pub label: [u8; 48],
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct CertifyKeyMldsaExternalMu87Cmd {
    pub handle: ContextHandle,
    pub flags: CertifyKeyFlags,
    pub format: u32,
    pub label: [u8; 48],
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "dpe_profile_p256_sha256")]
    use crate::commands::CertifyKeyP256Cmd as CertifyKeyCmd;
    #[cfg(feature = "dpe_profile_p384_sha384")]
    use crate::commands::CertifyKeyP384Cmd as CertifyKeyCmd;
    use crate::{
        commands::{Command, CommandHdr, DeriveContextCmd, DeriveContextFlags, InitCtxCmd},
        dpe_instance::tests::{test_env, SIMULATION_HANDLE, TEST_LOCALITIES},
        support::Support,
        x509::{tests::TcbInfo, DirectoryString, Name},
        State, DPE_PROFILE,
    };
    use caliptra_cfi_lib_git::CfiCounter;
    use cms::{
        content_info::{CmsVersion, ContentInfo},
        signed_data::{SignedData, SignerIdentifier},
    };
    #[cfg(feature = "ml-dsa")]
    use crypto::ml_dsa::{MldsaAlgorithm, MldsaPublicKey};
    use crypto::{
        ecdsa::{EcdsaAlgorithm, EcdsaPub},
        Crypto, CryptoSuite, PubKey, SignatureAlgorithm,
    };
    use der::{Decode, Encode};
    use openssl::{
        bn::BigNum,
        ec::{EcGroup, EcKey},
        ecdsa::EcdsaSig,
        nid::*,
    };
    use platform::Platform;
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
        label: [0xaa; DPE_PROFILE.hash_size()],
        format: CertifyKeyCommand::FORMAT_X509,
    };

    #[test]
    fn test_deserialize_certify_key() {
        CfiCounter::reset_for_test();
        let mut command = CommandHdr::new(DPE_PROFILE, Command::CERTIFY_KEY)
            .as_bytes()
            .to_vec();
        command.extend(TEST_CERTIFY_KEY_CMD.as_bytes());
        assert_eq!(
            Ok(Command::CertifyKey(CertifyKeyCommand::from(
                &TEST_CERTIFY_KEY_CMD
            ))),
            Command::deserialize(DPE_PROFILE, &command)
        );
    }

    #[test]
    fn test_certify_key_x509() {
        for mark_dice_extensions_critical in [true, false] {
            CfiCounter::reset_for_test();
            let flags = {
                let mut flags = DpeFlags::empty();
                flags.set(
                    DpeFlags::MARK_DICE_EXTENSIONS_CRITICAL,
                    mark_dice_extensions_critical,
                );
                flags
            };
            let mut state = State::new(Support::X509, flags);
            let mut env = test_env(&mut state);
            let mut dpe = DpeInstance::new(&mut env).unwrap();

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
                label: [0; DPE_PROFILE.hash_size()],
                format: CertifyKeyCommand::FORMAT_X509,
            };

            let certify_resp = match CertifyKeyCommand::from(&certify_cmd)
                .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
                .unwrap()
            {
                Response::CertifyKey(resp) => resp,
                _ => panic!("Wrong response type."),
            };
            let cert = certify_resp.cert().unwrap();
            assert_ne!(cert.len(), 0);

            let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
            match parser.parse(cert) {
                Ok((_, cert)) => {
                    assert_eq!(cert.version(), X509Version::V3);
                    for ext in cert.iter_extensions() {
                        if ext.parsed_extension().unsupported() {
                            assert_eq!(ext.critical, mark_dice_extensions_critical);
                        }
                    }
                }
                Err(e) => panic!("x509 parsing failed: {:?}", e),
            };
        }
    }

    #[test]
    fn test_certify_key_csr() {
        // Verify that certify_key csr DICE extensions criticality matches the dpe_instance.
        for mark_dice_extensions_critical in [true, false] {
            CfiCounter::reset_for_test();
            let flags = {
                let mut flags = DpeFlags::empty();
                flags.set(
                    DpeFlags::MARK_DICE_EXTENSIONS_CRITICAL,
                    mark_dice_extensions_critical,
                );
                flags
            };
            let mut state = State::new(Support::CSR, flags);
            let mut env = test_env(&mut state);
            let mut dpe = DpeInstance::new(&mut env).unwrap();

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
                label: [0; DPE_PROFILE.hash_size()],
                format: CertifyKeyCommand::FORMAT_CSR,
            };

            let certify_resp = match CertifyKeyCommand::from(&certify_cmd)
                .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
                .unwrap()
            {
                Response::CertifyKey(resp) => resp,
                _ => panic!("Wrong response type."),
            };
            let cert = certify_resp.cert().unwrap();
            assert_ne!(cert.len(), 0);

            // parse CMS ContentInfo
            let content_info = ContentInfo::from_der(cert).unwrap();
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
            let hash_alg_oid = match DPE_PROFILE.alg() {
                SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => "2.16.840.1.101.3.4.2.1",
                SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => "2.16.840.1.101.3.4.2.2",
                #[cfg(feature = "ml-dsa")]
                SignatureAlgorithm::MlDsa(MldsaAlgorithm::ExternalMu87) => {
                    "2.16.840.1.101.3.4.3.19"
                }
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
            let sig_alg_oid = match DPE_PROFILE.alg() {
                SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => "1.2.840.10045.4.3.2",
                SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => "1.2.840.10045.4.3.3",
                #[cfg(feature = "ml-dsa")]
                SignatureAlgorithm::MlDsa(MldsaAlgorithm::ExternalMu87) => {
                    "2.16.840.1.101.3.4.3.19"
                }
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
            let csr_digest = env.crypto.hash(econtent).unwrap();
            let priv_key = match DPE_PROFILE.alg() {
                SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => EcKey::private_key_from_der(
                    include_bytes!("../../../platform/src/test_data/key_256.der"),
                ),
                SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => EcKey::private_key_from_der(
                    include_bytes!("../../../platform/src/test_data/key_384.der"),
                ),
                #[cfg(feature = "ml-dsa")]
                SignatureAlgorithm::MlDsa(MldsaAlgorithm::ExternalMu87) => {
                    todo!("Add MLDSA for OpenSSL?")
                }
            }
            .unwrap();
            let curve = match DPE_PROFILE.alg() {
                SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => Nid::X9_62_PRIME256V1,
                SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => Nid::SECP384R1,
                #[cfg(feature = "ml-dsa")]
                SignatureAlgorithm::MlDsa(MldsaAlgorithm::ExternalMu87) => {
                    todo!("Add MLDSA for OpenSSL?")
                }
            };
            let group = &EcGroup::from_curve_name(curve).unwrap();
            let alias_key = EcKey::from_public_key(group, priv_key.public_key()).unwrap();
            let csr_sig = EcdsaSig::from_der(signer_info.signature.as_bytes()).unwrap();
            assert!(csr_sig.verify(csr_digest.as_slice(), &alias_key).unwrap());

            // validate csr
            let (_, csr) = X509CertificationRequest::from_der(econtent).unwrap();
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
            let x = BigNum::from_slice(&pub_key_der[1..DPE_PROFILE.ecc_int_size() + 1]).unwrap();
            let y = BigNum::from_slice(&pub_key_der[DPE_PROFILE.ecc_int_size() + 1..]).unwrap();
            let pub_key = EcKey::from_public_key_affine_coordinates(group, &x, &y).unwrap();

            let cri_digest = env.crypto.hash(cri.raw).unwrap();
            assert!(cri_sig.verify(cri_digest.as_slice(), &pub_key).unwrap());

            // validate subject_name
            let mut subj_serial = [0u8; DPE_PROFILE.hash_size() * 2];
            let pub_key = match certify_resp {
                #[cfg(feature = "dpe_profile_p256_sha256")]
                CertifyKeyResp::P256(r) => PubKey::Ecdsa(
                    EcdsaPub::from_slice(&r.derived_pubkey_x, &r.derived_pubkey_y).into(),
                ),
                #[cfg(feature = "dpe_profile_p384_sha384")]
                CertifyKeyResp::P384(r) => PubKey::Ecdsa(
                    EcdsaPub::from_slice(&r.derived_pubkey_x, &r.derived_pubkey_y).into(),
                ),
                #[cfg(feature = "ml-dsa")]
                CertifyKeyResp::MldsaExternalMu87(r) => {
                    PubKey::MlDsa(MldsaPublicKey::from_slice(&r.pubkey))
                }
            };
            env.crypto
                .get_pubkey_serial(&pub_key, &mut subj_serial)
                .unwrap();
            let truncated_subj_serial = &subj_serial[..64];
            let subject_name = Name {
                cn: DirectoryString::PrintableString(b"DPE Leaf"),
                serial: DirectoryString::PrintableString(truncated_subj_serial),
            };
            let expected_subject_name = format!(
                "CN={}, serialNumber={}",
                str::from_utf8(subject_name.cn.bytes()).unwrap(),
                str::from_utf8(subject_name.serial.bytes()).unwrap()
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
                        assert!(extension.critical);
                    }
                    ParsedExtension::KeyUsage(key_usage) => {
                        assert!(KeyUsage::digital_signature(key_usage));
                        assert!(!KeyUsage::key_cert_sign(key_usage));
                        assert!(extension.critical);
                    }
                    ParsedExtension::ExtendedKeyUsage(extended_key_usage) => {
                        // Expect tcg-dice-kp-eca OID (2.23.133.5.4.100.9)
                        assert_eq!(extended_key_usage.other, [oid!(2.23.133 .5 .4 .100 .9)]);
                        assert!(extension.critical);
                    }
                    ParsedExtension::UnsupportedExtension { oid } => {
                        // Must be a UEID or MultiTcbInfo extension
                        if *oid != oid!(2.23.133 .5 .4 .5) && *oid != oid!(2.23.133 .5 .4 .4) {
                            panic!("Error: Unparsed extension has unexpected OID: {:?}", oid);
                        }
                        assert_eq!(extension.critical, mark_dice_extensions_critical);
                    }
                    _ => panic!(
                        "Error: Unexpected extension found {:?}",
                        extension.parsed_extension()
                    ),
                };
            }
        }
    }

    #[test]
    fn test_certify_key_order() {
        CfiCounter::reset_for_test();
        let mut state = State::new(Support::X509 | Support::AUTO_INIT, DpeFlags::empty());
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env).unwrap();

        // Derive context twice with different types
        let derive_cmd = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [1; DPE_PROFILE.tci_size()],
            flags: DeriveContextFlags::MAKE_DEFAULT,
            tci_type: 1,
            target_locality: 0,
            svn: 0,
        };

        derive_cmd
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap();

        let certify_cmd = CertifyKeyCmd {
            handle: ContextHandle::default(),
            flags: CertifyKeyFlags(0),
            label: [0; DPE_PROFILE.hash_size()],
            format: CertifyKeyCommand::FORMAT_X509,
        };

        let certify_resp = match CertifyKeyCommand::from(&certify_cmd)
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap()
        {
            Response::CertifyKey(resp) => resp,
            _ => panic!("Wrong response type."),
        };

        let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
        let (_, cert) = parser.parse(certify_resp.cert().unwrap()).unwrap();

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
