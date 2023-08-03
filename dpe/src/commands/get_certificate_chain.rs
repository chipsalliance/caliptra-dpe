// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{DpeErrorCode, GetCertificateChainResp, Response, ResponseHdr},
    MAX_CERT_SIZE,
};
use platform::{Platform, PlatformError, MAX_CHUNK_SIZE};

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::FromBytes)]
#[cfg_attr(test, derive(zerocopy::AsBytes))]
pub struct GetCertificateChainCmd {
    pub offset: u32,
    pub size: u32,
}

impl CommandExecution for GetCertificateChainCmd {
    fn execute(
        &self,
        _dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        _locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        // Make sure the operation is supported.
        if self.size > MAX_CERT_SIZE as u32 {
            return Err(DpeErrorCode::InvalidArgument);
        }

        let mut cert_chunk = [0u8; MAX_CHUNK_SIZE];
        let len = env
            .platform
            .get_certificate_chain(self.offset, self.size, &mut cert_chunk)
            .map_err(|platform_error| match platform_error {
                PlatformError::CertificateChainError => DpeErrorCode::InvalidArgument,
                _ => DpeErrorCode::PlatformError,
            })?;
        Ok(Response::GetCertificateChain(GetCertificateChainResp {
            certificate_chain: cert_chunk,
            certificate_size: len,
            resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{Command, CommandHdr},
        dpe_instance::tests::{TestTypes, TEST_LOCALITIES},
        support::test::SUPPORT,
    };
    use crypto::OpensslCrypto;
    use platform::DefaultPlatform;
    use zerocopy::AsBytes;

    const TEST_GET_CERTIFICATE_CHAIN_CMD: GetCertificateChainCmd = GetCertificateChainCmd {
        offset: 0,
        size: MAX_CERT_SIZE as u32,
    };

    #[test]
    fn test_deserialize_get_certificate_chain() {
        let mut command =
            CommandHdr::new_for_test(Command::GetCertificateChain(TEST_GET_CERTIFICATE_CHAIN_CMD))
                .as_bytes()
                .to_vec();
        command.extend(TEST_GET_CERTIFICATE_CHAIN_CMD.as_bytes());
        assert_eq!(
            Ok(Command::GetCertificateChain(TEST_GET_CERTIFICATE_CHAIN_CMD)),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_fails_if_size_greater_than_max_cert_size() {
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new_for_test(&mut env, SUPPORT).unwrap();

        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            GetCertificateChainCmd {
                size: MAX_CERT_SIZE as u32 + 1,
                ..TEST_GET_CERTIFICATE_CHAIN_CMD
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
    }
}
