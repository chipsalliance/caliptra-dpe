// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::ContextHandle,
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{CertifyKeyResp, DpeErrorCode, Response, ResponseHdr},
    tci::TciNodeData,
    x509::{MeasurementData, Name, X509CertWriter},
    DPE_PROFILE, MAX_CERT_SIZE, MAX_HANDLES,
};
use crypto::Crypto;

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::FromBytes, zerocopy::AsBytes)]
pub struct CertifyKeyCmd {
    pub handle: ContextHandle,
    pub flags: u32,
    pub label: [u8; DPE_PROFILE.get_hash_size()],
    pub format: u32,
}

impl CertifyKeyCmd {
    pub const IS_CA: u32 = 1 << 31;

    pub const FORMAT_X509: u32 = 0;
    pub const FORMAT_CSR: u32 = 1;

    const fn uses_is_ca(&self) -> bool {
        self.flags & Self::IS_CA != 0
    }
}

impl CommandExecution for CertifyKeyCmd {
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        let idx = dpe.get_active_context_pos(&self.handle, locality)?;
        let context = &dpe.contexts[idx];

        if self.uses_is_ca() && !dpe.support.is_ca {
            return Err(DpeErrorCode::ArgumentNotSupported);
        }
        if self.uses_is_ca() && !context.allow_ca {
            return Err(DpeErrorCode::InvalidArgument);
        }

        if self.format == Self::FORMAT_X509 {
            if !dpe.support.x509 {
                return Err(DpeErrorCode::ArgumentNotSupported);
            }
            if !context.allow_x509 {
                return Err(DpeErrorCode::InvalidArgument);
            }
        }

        // Make sure the command is coming from the right locality.
        if context.locality != locality {
            return Err(DpeErrorCode::InvalidLocality);
        }

        let algs = DPE_PROFILE.alg_len();
        let digest = dpe.compute_measurement_hash(env, idx)?;
        let cdi = env
            .crypto
            .derive_cdi(DPE_PROFILE.alg_len(), &digest, b"DPE")
            .map_err(|_| DpeErrorCode::CryptoError)?;
        let priv_key = env
            .crypto
            .derive_private_key(algs, &cdi, &self.label, b"ECC")
            .map_err(|_| DpeErrorCode::CryptoError)?;

        let pub_key = env
            .crypto
            .derive_ecdsa_pub(DPE_PROFILE.alg_len(), &priv_key)
            .map_err(|_| DpeErrorCode::CryptoError)?;

        let mut issuer_name = Name {
            cn: dpe.issuer_cn,
            serial: [0u8; DPE_PROFILE.get_hash_size() * 2],
        };
        env.crypto
            .get_ecdsa_alias_serial(DPE_PROFILE.alg_len(), &mut issuer_name.serial)
            .map_err(|_| DpeErrorCode::CryptoError)?;

        let mut subject_name = Name {
            cn: b"DPE Leaf",
            serial: [0u8; DPE_PROFILE.get_hash_size() * 2],
        };
        env.crypto
            .get_pubkey_serial(DPE_PROFILE.alg_len(), &pub_key, &mut subject_name.serial)
            .map_err(|_| DpeErrorCode::CryptoError)?;

        // Get TCI Nodes
        const INITIALIZER: TciNodeData = TciNodeData::new();
        let mut nodes = [INITIALIZER; MAX_HANDLES];
        let tcb_count = dpe.get_tcb_nodes(idx, &mut nodes)?;

        let measurements = MeasurementData {
            label: &self.label,
            tci_nodes: &nodes[..tcb_count],
            is_ca: self.uses_is_ca(),
        };

        let mut cert = [0u8; MAX_CERT_SIZE];
        let cert_size = match self.format {
            Self::FORMAT_X509 => {
                let mut tbs_buffer = [0u8; MAX_CERT_SIZE];
                let mut tbs_writer = X509CertWriter::new(&mut tbs_buffer, true);
                let mut bytes_written = tbs_writer.encode_ecdsa_tbs(
                    /*serial=*/
                    &subject_name.serial[..20], // Serial number must be truncated to 20 bytes
                    &issuer_name,
                    &subject_name,
                    &pub_key,
                    &measurements,
                )?;

                let tbs_digest = env
                    .crypto
                    .hash(DPE_PROFILE.alg_len(), &tbs_buffer[..bytes_written])
                    .map_err(|_| DpeErrorCode::HashError)?;
                let sig = env
                    .crypto
                    .ecdsa_sign_with_alias(DPE_PROFILE.alg_len(), &tbs_digest)
                    .map_err(|_| DpeErrorCode::CryptoError)?;

                let mut cert_writer = X509CertWriter::new(&mut cert, true);
                bytes_written =
                    cert_writer.encode_ecdsa_certificate(&tbs_buffer[..bytes_written], &sig)?;
                u32::try_from(bytes_written).map_err(|_| DpeErrorCode::InternalError)?
            }
            Self::FORMAT_CSR => {
                if !dpe.support.csr {
                    return Err(DpeErrorCode::ArgumentNotSupported);
                }
                return Err(DpeErrorCode::ArgumentNotSupported);
            }
            _ => return Err(DpeErrorCode::InvalidArgument),
        };

        // Rotate handle if it isn't the default
        dpe.roll_onetime_use_handle(env, idx)?;

        Ok(Response::CertifyKey(CertifyKeyResp {
            new_context_handle: dpe.contexts[idx].handle,
            derived_pubkey_x: pub_key.x.bytes().try_into().unwrap(),
            derived_pubkey_y: pub_key.y.bytes().try_into().unwrap(),
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
        commands::{Command, CommandHdr, InitCtxCmd},
        dpe_instance::tests::{TestTypes, SIMULATION_HANDLE, TEST_LOCALITIES},
        support::Support,
    };
    use crypto::OpensslCrypto;
    use platform::DefaultPlatform;
    use x509_parser::nom::Parser;
    use x509_parser::prelude::X509CertificateParser;
    use x509_parser::prelude::*;
    use zerocopy::AsBytes;

    const TEST_CERTIFY_KEY_CMD: CertifyKeyCmd = CertifyKeyCmd {
        handle: SIMULATION_HANDLE,
        flags: 0x1234_5678,
        label: [0xaa; DPE_PROFILE.get_hash_size()],
        format: CertifyKeyCmd::FORMAT_X509,
    };

    #[test]
    fn test_deserialize_certify_key() {
        let mut command = CommandHdr::new_for_test(Command::CertifyKey(TEST_CERTIFY_KEY_CMD))
            .as_bytes()
            .to_vec();
        command.extend(TEST_CERTIFY_KEY_CMD.as_bytes());
        assert_eq!(
            Ok(Command::CertifyKey(TEST_CERTIFY_KEY_CMD)),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_certify_key() {
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new_for_test(
            &mut env,
            Support {
                x509: true,
                ..Support::default()
            },
        )
        .unwrap();

        let init_resp = match InitCtxCmd::new_use_default()
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap()
        {
            Response::InitCtx(resp) => resp,
            _ => panic!("Incorrect return type."),
        };
        let certify_cmd = CertifyKeyCmd {
            handle: init_resp.handle,
            flags: 0,
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
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new_for_test(
            &mut env,
            Support {
                x509: true,
                is_ca: true,
                ..Support::default()
            },
        )
        .unwrap();

        let init_resp = match InitCtxCmd::new_use_default()
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap()
        {
            Response::InitCtx(resp) => resp,
            _ => panic!("Incorrect return type."),
        };
        let certify_cmd_ca = CertifyKeyCmd {
            handle: init_resp.handle,
            flags: CertifyKeyCmd::IS_CA,
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
            Ok((_, cert)) => match cert.basic_constraints() {
                Ok(Some(basic_constraints)) => {
                    assert!(basic_constraints.value.ca);
                }
                Ok(None) => panic!("basic constraints extension not found"),
                Err(_) => panic!("multiple basic constraints extensions found"),
            },
            Err(e) => panic!("x509 parsing failed: {:?}", e),
        };

        let certify_cmd_non_ca = CertifyKeyCmd {
            handle: init_resp.handle,
            flags: 0,
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
}
