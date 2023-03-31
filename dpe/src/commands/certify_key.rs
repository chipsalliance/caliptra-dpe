// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    dpe_instance::{DpeInstance, TciNodeData},
    response::{CertifyKeyResp, DpeErrorCode, Response},
    x509::{EcdsaPub, EcdsaSignature, MeasurementData, Name, X509CertWriter},
    DPE_PROFILE, HANDLE_SIZE, MAX_CERT_SIZE, MAX_HANDLES,
};
use core::{
    fmt::{Error, Write},
    mem::size_of,
};
use crypto::Crypto;

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(zerocopy::AsBytes, zerocopy::FromBytes))]
pub struct CertifyKeyCmd {
    handle: [u8; HANDLE_SIZE],
    flags: u32,
    label: [u8; DPE_PROFILE.get_hash_size()],
}

impl CertifyKeyCmd {
    const fn new() -> CertifyKeyCmd {
        CertifyKeyCmd {
            handle: [0; HANDLE_SIZE],
            flags: 0,
            label: [0; DPE_PROFILE.get_hash_size()],
        }
    }
}

impl<C: Crypto> CommandExecution<C> for CertifyKeyCmd {
    fn execute(&self, dpe: &mut DpeInstance<C>, locality: u32) -> Result<Response, DpeErrorCode> {
        let idx = dpe
            .get_active_context_pos(&self.handle, locality)
            .ok_or(DpeErrorCode::InvalidHandle)?;

        // Make sure the command is coming from the right locality.
        if dpe.contexts[idx].locality != locality {
            return Err(DpeErrorCode::InvalidHandle);
        }

        // Get TCI Nodes
        const INITIALIZER: TciNodeData = TciNodeData::new();
        let mut nodes = [INITIALIZER; MAX_HANDLES];
        let tcb_count = dpe.get_tcb_nodes(&dpe.contexts[idx], &mut nodes)?;

        // Hash TCI Nodes
        let mut tci_bytes = [0u8; MAX_HANDLES * size_of::<TciNodeData>()];
        let mut tci_offset = 0;
        for n in &nodes[..tcb_count] {
            tci_offset += n.serialize(&mut tci_bytes[tci_offset..])?;
        }

        let mut digest = [0; DPE_PROFILE.get_hash_size()];
        C::hash(DPE_PROFILE.alg_len(), &tci_bytes[..tci_offset], &mut digest)
            .map_err(|_| DpeErrorCode::InternalError)?;

        // Derive CDI and public key
        let cdi = C::derive_cdi(DPE_PROFILE.alg_len(), &digest, b"DPE")
            .map_err(|_| DpeErrorCode::InternalError)?;
        let mut pub_key = EcdsaPub::default();
        C::derive_ecdsa_pub(
            DPE_PROFILE.alg_len(),
            &cdi,
            &self.label,
            b"ECC",
            &mut pub_key.x,
            &mut pub_key.y,
        )
        .map_err(|_| DpeErrorCode::InternalError)?;

        // Hash the public key for the serialNumber name field
        let mut pub_bytes = [0u8; size_of::<EcdsaPub>()];
        let pub_offset = pub_key.serialize(&mut pub_bytes)?;
        let mut pub_digest = [0u8; DPE_PROFILE.get_hash_size()];
        C::hash(
            DPE_PROFILE.alg_len(),
            &pub_bytes[..pub_offset],
            &mut pub_digest,
        )
        .map_err(|_| DpeErrorCode::InternalError)?;

        // TODO: Let the platform specify issuer name
        let issuer_name = Name {
            cn: b"DPE Issuer",
            serial: b"000000",
        };

        let mut subject_sn_str = [0u8; DPE_PROFILE.get_hash_size() * 2];
        let mut w = BufWriter {
            buf: &mut subject_sn_str,
            offset: 0,
        };
        w.write_hex_str(&pub_digest)?;

        let subject_name = Name {
            cn: b"DPE Leaf",
            serial: &subject_sn_str,
        };

        let measurements = MeasurementData {
            _label: &self.label,
            tci_nodes: &nodes[..tcb_count],
        };

        // Get certificate
        let mut tbs_buffer = [0u8; MAX_CERT_SIZE];
        let mut tbs_writer = X509CertWriter::new(&mut tbs_buffer);
        let mut bytes_written = tbs_writer.encode_ecdsa_tbs(
            /*serial=*/ &pub_digest,
            &issuer_name,
            &subject_name,
            &pub_key,
            &measurements,
        )?;

        let mut tbs_digest = [0u8; DPE_PROFILE.get_hash_size()];
        C::hash(
            DPE_PROFILE.alg_len(),
            &tbs_buffer[..bytes_written],
            &mut tbs_digest,
        )
        .map_err(|_| DpeErrorCode::InternalError)?;
        let mut sig = EcdsaSignature::default();
        C::ecdsa_sign_with_alias(DPE_PROFILE.alg_len(), &tbs_digest, &mut sig.r, &mut sig.s)
            .map_err(|_| DpeErrorCode::InternalError)?;

        let mut cert = [0u8; MAX_CERT_SIZE];
        let mut cert_writer = X509CertWriter::new(&mut cert);
        bytes_written = cert_writer.encode_ecdsa_certificate(&tbs_buffer[..bytes_written], &sig)?;
        let cert_size = u32::try_from(bytes_written).map_err(|_| DpeErrorCode::InternalError)?;

        // Rotate handle if it isn't the default
        dpe.roll_onetime_use_handle(idx)?;

        Ok(Response::CertifyKey(CertifyKeyResp {
            new_context_handle: dpe.contexts[idx].handle,
            derived_pubkey_x: pub_key.x,
            derived_pubkey_y: pub_key.y,
            cert_size,
            cert,
        }))
    }
}

struct BufWriter<'a> {
    buf: &'a mut [u8],
    offset: usize,
}

impl Write for BufWriter<'_> {
    fn write_str(&mut self, s: &str) -> Result<(), Error> {
        if s.len() > self.buf.len().saturating_sub(self.offset) {
            return Err(Error::default());
        }

        self.buf[self.offset..self.offset + s.len()].copy_from_slice(s.as_bytes());
        self.offset += s.len();

        Ok(())
    }
}

impl BufWriter<'_> {
    fn write_hex_str(&mut self, src: &[u8]) -> Result<(), DpeErrorCode> {
        for &b in src {
            write!(self, "{b:02x}").map_err(|_| DpeErrorCode::InternalError)?;
        }

        Ok(())
    }
}

impl TryFrom<&[u8]> for CertifyKeyCmd {
    type Error = DpeErrorCode;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < size_of::<CertifyKeyCmd>() {
            return Err(DpeErrorCode::InvalidArgument);
        }

        let mut cmd = CertifyKeyCmd::new();
        let mut offset: usize = 0;

        cmd.handle
            .copy_from_slice(&raw[offset..offset + HANDLE_SIZE]);
        offset += HANDLE_SIZE;

        cmd.flags = u32::from_le_bytes(raw[offset..offset + size_of::<u32>()].try_into().unwrap());
        offset += size_of::<u32>();

        cmd.label
            .copy_from_slice(&raw[offset..offset + DPE_PROFILE.get_hash_size()]);

        Ok(cmd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{Command, CommandHdr, InitCtxCmd},
        dpe_instance::{
            tests::{SIMULATION_HANDLE, TEST_LOCALITIES},
            Support,
        },
    };
    use crypto::OpensslCrypto;
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
    fn test_slice_to_certify_key() {
        let invalid_argument: Result<CertifyKeyCmd, DpeErrorCode> =
            Err(DpeErrorCode::InvalidArgument);

        // Test if too small.
        assert_eq!(
            invalid_argument,
            CertifyKeyCmd::try_from([0u8; size_of::<CertifyKeyCmd>() - 1].as_slice())
        );

        assert_eq!(
            TEST_CERTIFY_KEY_CMD,
            CertifyKeyCmd::try_from(TEST_CERTIFY_KEY_CMD.as_bytes()).unwrap()
        );
    }

    #[test]
    fn test_certify_key() {
        let mut dpe =
            DpeInstance::<OpensslCrypto>::new(Support::default(), &TEST_LOCALITIES).unwrap();

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
