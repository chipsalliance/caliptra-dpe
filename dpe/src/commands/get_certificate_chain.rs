// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    mutresp,
    response::{DpeErrorCode, GetCertificateChainResp},
};
#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_impl_fn;
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
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    fn execute_serialized(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        _locality: u32,
        out: &mut [u8],
    ) -> Result<usize, DpeErrorCode> {
        // Make sure the operation is supported.
        if self.size > MAX_CHUNK_SIZE as u32 {
            return Err(DpeErrorCode::InvalidArgument);
        }
        let response = mutresp::<GetCertificateChainResp>(dpe.profile, out)?;

        let mut cert_chunk = [0u8; MAX_CHUNK_SIZE];
        let len = env
            .platform
            .get_certificate_chain(self.offset, self.size, &mut cert_chunk)?;
        *response = GetCertificateChainResp {
            certificate_chain: cert_chunk,
            certificate_size: len,
            resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
        };
        Ok(size_of_val(response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{tests::PROFILES, Command, CommandHdr},
        dpe_instance::tests::{test_env, test_state, DPE_PROFILE, TEST_LOCALITIES},
    };
    use caliptra_cfi_lib::CfiCounter;
    use zerocopy::IntoBytes;

    const TEST_GET_CERTIFICATE_CHAIN_CMD: GetCertificateChainCmd = GetCertificateChainCmd {
        offset: 0,
        size: MAX_CHUNK_SIZE as u32,
    };

    #[test]
    fn test_deserialize_get_certificate_chain() {
        CfiCounter::reset_for_test();
        for p in PROFILES {
            let mut command = CommandHdr::new(p, Command::GET_CERTIFICATE_CHAIN)
                .as_bytes()
                .to_vec();
            command.extend(TEST_GET_CERTIFICATE_CHAIN_CMD.as_bytes());
            assert_eq!(
                Ok(Command::GetCertificateChain(
                    &TEST_GET_CERTIFICATE_CHAIN_CMD
                )),
                Command::deserialize(p, &command)
            );
        }
    }

    #[test]
    fn test_fails_if_size_greater_than_max_chunk_size() {
        CfiCounter::reset_for_test();
        let mut state = test_state();
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

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
