// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{DpeErrorCode, GetCertificateChainResp, Response},
};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
use platform::{Platform, MAX_CHUNK_SIZE};

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
pub struct GetCertificateChainCmd {
    pub offset: u32,
    pub size: u32,
}

impl CommandExecution for GetCertificateChainCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        _locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        // Make sure the operation is supported.
        if self.size > MAX_CHUNK_SIZE as u32 {
            return Err(DpeErrorCode::InvalidArgument);
        }

        let mut cert_chunk = [0u8; MAX_CHUNK_SIZE];
        let len = env
            .platform
            .get_certificate_chain(self.offset, self.size, &mut cert_chunk)?;
        Ok(Response::GetCertificateChain(GetCertificateChainResp {
            certificate_chain: cert_chunk,
            certificate_size: len,
            resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{tests::DEFAULT_PLATFORM, Command, CommandHdr},
        dpe_instance::{
            tests::{TestTypes, TEST_LOCALITIES},
            DpeInstanceFlags,
        },
        support::test::SUPPORT,
    };
    use caliptra_cfi_lib_git::CfiCounter;
    use crypto::OpensslCrypto;
    use zerocopy::IntoBytes;

    const TEST_GET_CERTIFICATE_CHAIN_CMD: GetCertificateChainCmd = GetCertificateChainCmd {
        offset: 0,
        size: MAX_CHUNK_SIZE as u32,
    };

    #[test]
    fn test_deserialize_get_certificate_chain() {
        CfiCounter::reset_for_test();
        let mut command = CommandHdr::new_for_test(Command::GET_CERTIFICATE_CHAIN)
            .as_bytes()
            .to_vec();
        command.extend(TEST_GET_CERTIFICATE_CHAIN_CMD.as_bytes());
        assert_eq!(
            Ok(Command::GetCertificateChain(
                &TEST_GET_CERTIFICATE_CHAIN_CMD
            )),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_fails_if_size_greater_than_max_chunk_size() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DEFAULT_PLATFORM,
        };
        let mut dpe = DpeInstance::new(&mut env, SUPPORT, DpeInstanceFlags::empty()).unwrap();

        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            GetCertificateChainCmd {
                size: MAX_CHUNK_SIZE as u32 + 1,
                ..TEST_GET_CERTIFICATE_CHAIN_CMD
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
    }
}
