// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::ContextHandle,
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{DpeErrorCode, NewHandleResp, Response, ResponseHdr},
};

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::FromBytes)]
#[cfg_attr(test, derive(zerocopy::AsBytes))]
pub struct TagTciCmd {
    handle: ContextHandle,
    tag: u32,
}

impl CommandExecution for TagTciCmd {
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        // Make sure this command is supported.
        if !dpe.support.tagging() {
            return Err(DpeErrorCode::InvalidCommand);
        }
        // Make sure the tag isn't used by any other contexts.
        if dpe
            .contexts
            .iter()
            .any(|c| c.has_tag() && c.tag == self.tag)
        {
            return Err(DpeErrorCode::BadTag);
        }

        let idx = dpe.get_active_context_pos(&self.handle, locality)?;

        if dpe.contexts[idx].has_tag() {
            return Err(DpeErrorCode::BadTag);
        }

        // Because handles are one-time use, let's rotate the handle, if it isn't the default.
        dpe.roll_onetime_use_handle(env, idx)?;
        let context = &mut dpe.contexts[idx];
        context.has_tag = true.into();
        context.tag = self.tag;

        Ok(Response::TagTci(NewHandleResp {
            handle: context.handle,
            resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{Command, CommandHdr, InitCtxCmd},
        dpe_instance::tests::{
            TestTypes, RANDOM_HANDLE, SIMULATION_HANDLE, TEST_HANDLE, TEST_LOCALITIES,
        },
        support::Support,
    };
    use crypto::OpensslCrypto;
    use platform::default::DefaultPlatform;
    use zerocopy::AsBytes;

    const TEST_TAG_TCI_CMD: TagTciCmd = TagTciCmd {
        handle: SIMULATION_HANDLE,
        tag: 0x1234_5678,
    };

    #[test]
    fn test_deserialize_tag_tci() {
        let mut command = CommandHdr::new_for_test(Command::TAG_TCI)
            .as_bytes()
            .to_vec();
        command.extend(TEST_TAG_TCI_CMD.as_bytes());
        assert_eq!(
            Ok(Command::TagTci(TEST_TAG_TCI_CMD)),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_tag_tci() {
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::default()).unwrap();
        // Make sure it returns an error if the command is marked unsupported.
        assert_eq!(
            Err(DpeErrorCode::InvalidCommand),
            TagTciCmd {
                handle: ContextHandle::default(),
                tag: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // Make a new instance that supports tagging.
        let mut dpe = DpeInstance::new(&mut env, Support::TAGGING | Support::SIMULATION).unwrap();
        InitCtxCmd::new_use_default()
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap();
        let sim_local = TEST_LOCALITIES[1];
        // Make a simulation context to test against.
        InitCtxCmd::new_simulation()
            .execute(&mut dpe, &mut env, sim_local)
            .unwrap();

        // Invalid handle.
        assert_eq!(
            Err(DpeErrorCode::InvalidHandle),
            TagTciCmd {
                handle: TEST_HANDLE,
                tag: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // Wrong locality.
        assert_eq!(
            Err(DpeErrorCode::InvalidLocality),
            TagTciCmd {
                handle: ContextHandle::default(),
                tag: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[1])
        );

        // Tag default handle.
        assert_eq!(
            Ok(Response::TagTci(NewHandleResp {
                handle: ContextHandle::default(),
                resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
            })),
            TagTciCmd {
                handle: ContextHandle::default(),
                tag: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // Try to re-tag the default context.
        assert_eq!(
            Err(DpeErrorCode::BadTag),
            TagTciCmd {
                handle: ContextHandle::default(),
                tag: 1,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // Try same tag on simulation.
        assert_eq!(
            Err(DpeErrorCode::BadTag),
            TagTciCmd {
                handle: SIMULATION_HANDLE,
                tag: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[1])
        );

        // Give the simulation context another handle so we can prove the handle rotates when it
        // gets tagged.
        let simulation_ctx = &mut dpe.contexts[dpe
            .get_active_context_pos(&RANDOM_HANDLE, sim_local)
            .unwrap()];
        let sim_tmp_handle = ContextHandle([0xff; ContextHandle::SIZE]);
        simulation_ctx.handle = sim_tmp_handle;
        assert!(dpe
            .get_active_context_pos(&RANDOM_HANDLE, sim_local)
            .is_err());

        // Tag simulation.
        match (TagTciCmd {
            handle: sim_tmp_handle,
            tag: 1,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[1]))
        {
            Ok(Response::TagTci(NewHandleResp { handle, .. })) => {
                // Make sure it rotated back to the deterministic simulation handle.
                assert!(dpe
                    .get_active_context_pos(&sim_tmp_handle, sim_local)
                    .is_err());
                assert!(dpe.get_active_context_pos(&handle, sim_local).is_ok());
            }
            _ => panic!("Tag simulation failed"),
        }
    }
}
