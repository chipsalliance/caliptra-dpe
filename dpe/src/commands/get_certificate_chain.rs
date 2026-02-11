// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    commands::Command,
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    okref,
    response::{DpeErrorCode, GetCertificateChainResp, GetCertificateChainRespFlags, Response},
    state::MultipartOperationState,
    OperationHandle, State,
};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
use crypto::{Crypto, Digest, Hasher};
use platform::{Platform, MAX_CHUNK_SIZE};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[repr(C)]
#[derive(Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct GetCertificateChainCmd {
    pub op_handle: OperationHandle,
}

impl GetCertificateChainCmd {
    fn command_hash(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
    ) -> Result<Digest, DpeErrorCode> {
        let mut hasher = env.crypto.hash_initialize()?;
        hasher.update(Command::GET_CERTIFICATE_CHAIN.as_bytes())?;
        hasher.update(dpe.profile.as_bytes())?;
        hasher.update(locality.as_bytes())?;
        let hash = hasher.finish()?;
        Ok(hash)
    }
}

impl CommandExecution for GetCertificateChainCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        let cmd_hash = self.command_hash(dpe, env, locality);
        let cmd_hash = okref(&cmd_hash)?;
        let op_handle = &self.op_handle;
        let multipart_state_idx = env.platform.multipart_state_index_from_locality(locality)?;
        if multipart_state_idx >= State::MAX_MULTIPART_OPERATIONS {
            return Err(DpeErrorCode::InternalError);
        }

        // Clear the state if the operation handle is blank.
        if op_handle.blank() {
            env.state.multipart_state[multipart_state_idx].clear();
        } else {
            // If continuing a multi-part operation, make sure it is the same command and has the
            // correct operation handle.
            if !env.state.multipart_state[multipart_state_idx]
                .is_continued_operation(op_handle, cmd_hash)
            {
                return Err(DpeErrorCode::InvalidOperationHandle);
            }
        }

        let offset = env.state.multipart_state[multipart_state_idx].offset;
        let mut chunk = [0u8; MAX_CHUNK_SIZE];
        let (len, last_chunk) = env.platform.get_certificate_chain(offset, &mut chunk)?;

        // If this is the last call, clear the state; otherwise generate a new operation handle and
        // update the running state.
        let op_handle = if last_chunk {
            env.state.multipart_state[multipart_state_idx].clear();
            OperationHandle::default()
        } else {
            let op_handle = OperationHandle::generate(env)?;
            env.state.multipart_state[multipart_state_idx] = MultipartOperationState {
                offset: offset + len,
                handle: op_handle,
                digest: cmd_hash.as_slice().try_into().unwrap(),
            };
            op_handle
        };

        Ok(Response::GetCertificateChain(GetCertificateChainResp {
            chunk,
            chunk_size: len,
            flags: GetCertificateChainRespFlags::empty(),
            op_handle,
            resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{tests::PROFILES, Command, CommandHdr},
        dpe_instance::tests::{test_env, DPE_PROFILE, TEST_LOCALITIES},
        support::Support,
        DpeFlags,
    };
    use caliptra_cfi_lib_git::CfiCounter;
    use zerocopy::IntoBytes;

    const TEST_GET_CERTIFICATE_CHAIN_CMD: GetCertificateChainCmd = GetCertificateChainCmd {
        op_handle: OperationHandle::default(),
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
    fn test_get_certificate_chain() {
        CfiCounter::reset_for_test();
        let mut state = State::new(Support::AUTO_INIT, DpeFlags::empty());
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

        let chain = dpe.get_certificate_chain(&mut env, 0).unwrap();
        assert!(!chain.is_empty());
    }

    #[test]
    fn test_restart_get_certificate_chain() {
        CfiCounter::reset_for_test();
        let mut state = State::new(Support::AUTO_INIT, DpeFlags::empty());
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();
        let op_handle = OperationHandle::default();
        let locality = 0;

        let Response::GetCertificateChain(resp) = GetCertificateChainCmd { op_handle }
            .execute(&mut dpe, &mut env, locality)
            .unwrap()
        else {
            panic!("Unexpected response type");
        };
        let first_call_chain = resp.chunk[..resp.chunk_size as usize].to_vec();

        // Can't restart an operation if the certificate chain can be handled in a single command.
        if resp.op_handle.blank() {
            return;
        }

        let chain = dpe.get_certificate_chain(&mut env, locality).unwrap();

        // The first response should be a subset of the total chain.
        assert!(first_call_chain.len() < chain.len());
        assert_eq!(first_call_chain, chain[..first_call_chain.len()].to_vec());
    }

    #[test]
    fn test_get_certificate_chain_wrong_handle() {
        CfiCounter::reset_for_test();
        let mut state = State::new(Support::AUTO_INIT, DpeFlags::empty());
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();
        let op_handle = OperationHandle([1; 16]);
        let locality = 0;

        let result = GetCertificateChainCmd { op_handle }.execute(&mut dpe, &mut env, locality);
        assert_eq!(result, Err(DpeErrorCode::InvalidOperationHandle));
    }

    #[test]
    fn test_get_certificate_chain_interleaved() {
        CfiCounter::reset_for_test();
        let mut state = State::new(Support::AUTO_INIT, DpeFlags::empty());
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();
        let op_handle = OperationHandle::default();
        let first_locality = TEST_LOCALITIES[0];
        let second_locality = TEST_LOCALITIES[1];

        let mut first_chain = vec![];
        let Response::GetCertificateChain(resp) = GetCertificateChainCmd { op_handle }
            .execute(&mut dpe, &mut env, first_locality)
            .unwrap()
        else {
            panic!("Unexpected response type");
        };
        first_chain.extend_from_slice(&resp.chunk[..resp.chunk_size as usize]);
        let original_length = first_chain.len();

        // Can't test interleaved if the cert chain can be retrieved in a single command.
        if resp.op_handle.blank() {
            return;
        }

        let second_chain = dpe
            .get_certificate_chain(&mut env, second_locality)
            .unwrap();
        assert!(!second_chain.is_empty());

        let mut op_handle = resp.op_handle;
        let mut finished = false;
        while !finished {
            let Response::GetCertificateChain(resp) = GetCertificateChainCmd { op_handle }
                .execute(&mut dpe, &mut env, first_locality)
                .unwrap()
            else {
                panic!("Unexpected response type");
            };

            first_chain.extend_from_slice(&resp.chunk[..resp.chunk_size as usize]);
            op_handle = resp.op_handle;
            finished = resp.op_handle.blank();
        }
        assert!(first_chain.len() > original_length);
        assert_eq!(first_chain, second_chain);
    }
}
