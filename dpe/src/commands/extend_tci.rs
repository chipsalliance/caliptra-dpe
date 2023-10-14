// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::{Context, ContextHandle},
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{DpeErrorCode, NewHandleResp, Response, ResponseHdr},
    tci::TciMeasurement,
    DPE_PROFILE,
};

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::FromBytes)]
#[cfg_attr(test, derive(zerocopy::AsBytes))]
pub struct ExtendTciCmd {
    pub handle: ContextHandle,
    pub data: [u8; DPE_PROFILE.get_hash_size()],
}

impl CommandExecution for ExtendTciCmd {
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        // Make sure this command is supported.
        if !dpe.support.extend_tci() {
            return Err(DpeErrorCode::InvalidCommand);
        }

        let idx = dpe.get_active_context_pos(&self.handle, locality)?;

        let mut tmp_context = dpe.contexts[idx];
        dpe.add_tci_measurement(env, &mut tmp_context, &TciMeasurement(self.data), locality)?;

        // Rotate the handle if it isn't the default context.
        dpe.roll_onetime_use_handle(env, idx)?;

        dpe.contexts[idx] = Context {
            handle: dpe.contexts[idx].handle,
            ..tmp_context
        };

        if dpe.contexts[idx].parent_idx == Context::ROOT_INDEX {
            dpe.root_has_measurement = true.into();
        }

        Ok(Response::ExtendTci(NewHandleResp {
            handle: dpe.contexts[idx].handle,
            resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{tests::TEST_DIGEST, Command, CommandHdr, InitCtxCmd},
        dpe_instance::tests::{TestTypes, RANDOM_HANDLE, SIMULATION_HANDLE, TEST_LOCALITIES},
        support::Support,
    };
    use crypto::OpensslCrypto;
    use platform::default::{DefaultPlatform, AUTO_INIT_LOCALITY};
    use zerocopy::AsBytes;

    const TEST_EXTEND_TCI_CMD: ExtendTciCmd = ExtendTciCmd {
        handle: SIMULATION_HANDLE,
        data: TEST_DIGEST,
    };

    #[test]
    fn test_deserialize_extend_tci() {
        let mut command = CommandHdr::new_for_test(Command::EXTEND_TCI)
            .as_bytes()
            .to_vec();
        command.extend(TEST_EXTEND_TCI_CMD.as_bytes());
        assert_eq!(
            Ok(Command::ExtendTci(TEST_EXTEND_TCI_CMD)),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_extend_tci() {
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::default()).unwrap();
        // Make sure it returns an error if the command is marked unsupported.
        assert_eq!(
            Err(DpeErrorCode::InvalidCommand),
            ExtendTciCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_hash_size()],
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // Turn on support.
        dpe.support = dpe.support | Support::EXTEND_TCI;
        InitCtxCmd::new_use_default()
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap();

        // Wrong locality.
        assert_eq!(
            Err(DpeErrorCode::InvalidLocality),
            ExtendTciCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_hash_size()],
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[1])
        );

        let locality = AUTO_INIT_LOCALITY;
        let default_handle = ContextHandle::default();
        let handle = dpe.contexts[dpe
            .get_active_context_pos(&default_handle, locality)
            .unwrap()]
        .handle;
        let data = [1; DPE_PROFILE.get_hash_size()];
        ExtendTciCmd {
            handle: ContextHandle::default(),
            data,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap();

        // Make sure extending the default TCI doesn't change the handle.
        let default_context = &dpe.contexts[dpe
            .get_active_context_pos(&default_handle, locality)
            .unwrap()];
        assert_eq!(handle, default_context.handle);
        // Make sure the current TCI was updated correctly.
        assert_eq!(data, default_context.tci.tci_current.0);
        // Make sure cached private key is invalidated

        let sim_local = TEST_LOCALITIES[1];
        dpe.support = dpe.support | Support::SIMULATION;
        InitCtxCmd::new_simulation()
            .execute(&mut dpe, &mut env, sim_local)
            .unwrap();

        // Give the simulation context another handle so we can prove the handle rotates when it
        // gets extended.
        let simulation_ctx = &mut dpe.contexts[dpe
            .get_active_context_pos(&RANDOM_HANDLE, sim_local)
            .unwrap()];
        let sim_tmp_handle = ContextHandle([0xff; ContextHandle::SIZE]);
        simulation_ctx.handle = sim_tmp_handle;
        assert!(dpe
            .get_active_context_pos(&RANDOM_HANDLE, sim_local)
            .is_err());

        match (ExtendTciCmd {
            handle: sim_tmp_handle,
            data,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[1]))
        {
            Ok(Response::ExtendTci(NewHandleResp { handle, .. })) => {
                // Make sure it rotated back to the deterministic simulation handle.
                assert!(dpe
                    .get_active_context_pos(&sim_tmp_handle, sim_local)
                    .is_err());
                assert!(dpe.get_active_context_pos(&handle, sim_local).is_ok());
            }
            _ => panic!("Extend TCI failed"),
        }
    }
}
