// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::ContextHandle,
    dpe_instance::DpeInstance,
    response::{CertifyKeyResp, DpeErrorCode, Response},
    tci::TciNodeData,
    x509::{MeasurementData, Name, X509CertWriter},
    DPE_PROFILE, MAX_CERT_SIZE, MAX_HANDLES,
};
use crypto::Crypto;
use platform::Platform;

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::FromBytes)]
#[cfg_attr(test, derive(zerocopy::AsBytes))]
pub struct CertifyKeyCmd {
    pub handle: ContextHandle,
    pub flags: u32,
    pub label: [u8; DPE_PROFILE.get_hash_size()],
}

impl CertifyKeyCmd {
    pub const ND_DERIVATION: u32 = 1 << 31;

    // Uses non-deterministic derivation.
    const fn uses_nd_derivation(&self) -> bool {
        self.flags & Self::ND_DERIVATION != 0
    }
}

impl<C: Crypto, P: Platform> CommandExecution<C, P> for CertifyKeyCmd {
    fn execute(
        &self,
        dpe: &mut DpeInstance<C, P>,
        locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        // Make sure the operation is supported.
        if !dpe.support.nd_derivation && self.uses_nd_derivation() {
            return Err(DpeErrorCode::InvalidArgument);
        }

        let idx = dpe
            .get_active_context_pos(&self.handle, locality)
            .ok_or(DpeErrorCode::InvalidHandle)?;
        let context = &dpe.contexts[idx];

        // Make sure the command is coming from the right locality.
        if context.locality != locality {
            return Err(DpeErrorCode::InvalidHandle);
        }

        let algs = DPE_PROFILE.alg_len();
        let priv_key = if self.uses_nd_derivation() {
            if let Some(cached) = dpe.contexts[idx].cached_priv_key.take() {
                Ok(cached)
            } else {
                C::derive_private_key(algs, &dpe.derive_cdi(idx, true)?, &self.label, b"ECC")
                    .map_err(|_| DpeErrorCode::InternalError)
            }
        } else {
            let cdi = dpe.derive_cdi(idx, false)?;
            C::derive_private_key(algs, &cdi, &self.label, b"ECC")
                .map_err(|_| DpeErrorCode::InternalError)
        }?;

        let pub_key = C::derive_ecdsa_pub(DPE_PROFILE.alg_len(), &priv_key)
            .map_err(|_| DpeErrorCode::InternalError)?;
        // cache private key
        if self.uses_nd_derivation() {
            dpe.contexts[idx].cached_priv_key.replace(priv_key);
        }

        let mut issuer_name = Name {
            cn: dpe.issuer_cn,
            serial: [0u8; DPE_PROFILE.get_hash_size() * 2],
        };
        C::get_ecdsa_alias_serial(DPE_PROFILE.alg_len(), &mut issuer_name.serial)
            .map_err(|_| DpeErrorCode::InternalError)?;

        let mut subject_name = Name {
            cn: b"DPE Leaf",
            serial: [0u8; DPE_PROFILE.get_hash_size() * 2],
        };
        C::get_pubkey_serial(DPE_PROFILE.alg_len(), &pub_key, &mut subject_name.serial)
            .map_err(|_| DpeErrorCode::InternalError)?;

        // Get TCI Nodes
        const INITIALIZER: TciNodeData = TciNodeData::new();
        let mut nodes = [INITIALIZER; MAX_HANDLES];
        let tcb_count = dpe.get_tcb_nodes(idx, &mut nodes)?;

        let measurements = MeasurementData {
            label: &self.label,
            tci_nodes: &nodes[..tcb_count],
        };

        // Get certificate
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

        let tbs_digest = C::hash(DPE_PROFILE.alg_len(), &tbs_buffer[..bytes_written])
            .map_err(|_| DpeErrorCode::InternalError)?;
        let sig = C::ecdsa_sign_with_alias(DPE_PROFILE.alg_len(), &tbs_digest)
            .map_err(|_| DpeErrorCode::InternalError)?;

        let mut cert = [0u8; MAX_CERT_SIZE];
        let mut cert_writer = X509CertWriter::new(&mut cert, true);
        bytes_written = cert_writer.encode_ecdsa_certificate(&tbs_buffer[..bytes_written], &sig)?;
        let cert_size = u32::try_from(bytes_written).map_err(|_| DpeErrorCode::InternalError)?;

        // Rotate handle if it isn't the default
        dpe.roll_onetime_use_handle(idx)?;

        Ok(Response::CertifyKey(CertifyKeyResp {
            new_context_handle: dpe.contexts[idx].handle,
            derived_pubkey_x: pub_key.x.bytes().try_into().unwrap(),
            derived_pubkey_y: pub_key.y.bytes().try_into().unwrap(),
            cert_size,
            cert,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{Command, CommandHdr, InitCtxCmd},
        dpe_instance::tests::{SIMULATION_HANDLE, TEST_LOCALITIES},
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
    };

    #[test]
    fn test_deserialize_certify_key() {
        let mut command = CommandHdr::new(Command::CertifyKey(TEST_CERTIFY_KEY_CMD))
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
        let mut dpe = DpeInstance::<OpensslCrypto, DefaultPlatform>::new_for_test(
            Support::default(),
            &TEST_LOCALITIES,
        )
        .unwrap();

        let init_resp = match InitCtxCmd::new_use_default()
            .execute(&mut dpe, TEST_LOCALITIES[0])
            .unwrap()
        {
            Response::InitCtx(resp) => resp,
            _ => panic!("Incorrect return type."),
        };
        let certify_cmd = CertifyKeyCmd {
            handle: init_resp.handle,
            flags: 0,
            label: [0; DPE_PROFILE.get_hash_size()],
        };

        let certify_resp = match certify_cmd.execute(&mut dpe, TEST_LOCALITIES[0]).unwrap() {
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
}
