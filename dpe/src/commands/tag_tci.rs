// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    dpe_instance::DpeInstance,
    response::{DpeErrorCode, NewHandleResp, Response},
    HANDLE_SIZE,
};
use core::mem::size_of;
use crypto::Crypto;

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(zerocopy::AsBytes, zerocopy::FromBytes))]
pub struct TagTciCmd {
    handle: [u8; HANDLE_SIZE],
    tag: u32,
}

impl TryFrom<&[u8]> for TagTciCmd {
    type Error = DpeErrorCode;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < size_of::<TagTciCmd>() {
            return Err(DpeErrorCode::InvalidArgument);
        }

        Ok(TagTciCmd {
            handle: raw[0..HANDLE_SIZE].try_into().unwrap(),
            tag: u32::from_le_bytes(raw[HANDLE_SIZE..HANDLE_SIZE + 4].try_into().unwrap()),
        })
    }
}

impl<C: Crypto> CommandExecution<C> for TagTciCmd {
    fn execute(&self, dpe: &mut DpeInstance<C>, locality: u32) -> Result<Response, DpeErrorCode> {
        // Make sure this command is supported.
        if !dpe.support.tagging {
            return Err(DpeErrorCode::InvalidCommand);
        }
        // Make sure the tag isn't used by any other contexts.
        if dpe.contexts.iter().any(|c| c.has_tag && c.tag == self.tag) {
            return Err(DpeErrorCode::BadTag);
        }

        let idx = dpe
            .get_active_context_pos(&self.handle, locality)
            .ok_or(DpeErrorCode::InvalidHandle)?;

        // Make sure the command is coming from the right locality.
        if dpe.contexts[idx].locality != locality {
            return Err(DpeErrorCode::InvalidHandle);
        }
        if dpe.contexts[idx].has_tag {
            return Err(DpeErrorCode::BadTag);
        }

        // Because handles are one-time use, let's rotate the handle, if it isn't the default.
        dpe.roll_onetime_use_handle(idx)?;
        let context = &mut dpe.contexts[idx];
        context.has_tag = true;
        context.tag = self.tag;

        Ok(Response::TagTci(NewHandleResp {
            handle: context.handle,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{Command, CommandHdr, InitCtxCmd},
        dpe_instance::{
            tests::{SIMULATION_HANDLE, TEST_HANDLE, TEST_LOCALITIES},
            Support,
        },
    };
    use crypto::OpensslCrypto;
    use zerocopy::{AsBytes, FromBytes};

    const TEST_TAG_TCI_CMD: TagTciCmd = TagTciCmd {
        handle: SIMULATION_HANDLE,
        tag: 0x1234_5678,
    };

    #[test]
    fn try_from_tag_tci() {
        let command_bytes = TEST_TAG_TCI_CMD.as_bytes();
        assert_eq!(
            TagTciCmd::read_from_prefix(command_bytes).unwrap(),
            TagTciCmd::try_from(command_bytes).unwrap(),
        );
    }

    #[test]
    fn test_deserialize_tag_tci() {
        let mut command = CommandHdr::new(Command::TagTci(TEST_TAG_TCI_CMD))
            .as_bytes()
            .to_vec();
        command.extend(TEST_TAG_TCI_CMD.as_bytes());
        assert_eq!(
            Ok(Command::TagTci(TEST_TAG_TCI_CMD)),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_slice_to_tag_tci() {
        // Test if too small.
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            TagTciCmd::try_from([0u8; size_of::<TagTciCmd>() - 1].as_slice())
        );

        assert_eq!(
            TEST_TAG_TCI_CMD,
            TagTciCmd::try_from(TEST_TAG_TCI_CMD.as_bytes()).unwrap()
        );
    }

    #[test]
    fn test_tag_tci() {
        let mut dpe =
            DpeInstance::<OpensslCrypto>::new_for_test(Support::default(), &TEST_LOCALITIES)
                .unwrap();
        // Make sure it returns an error if the command is marked unsupported.
        assert_eq!(
            Err(DpeErrorCode::InvalidCommand),
            TagTciCmd {
                handle: DpeInstance::<OpensslCrypto>::DEFAULT_CONTEXT_HANDLE,
                tag: 0,
            }
            .execute(&mut dpe, TEST_LOCALITIES[0])
        );

        // Make a new instance that supports tagging.
        let mut dpe = DpeInstance::<OpensslCrypto>::new_for_test(
            Support {
                tagging: true,
                simulation: true,
                ..Support::default()
            },
            &TEST_LOCALITIES,
        )
        .unwrap();
        InitCtxCmd::new_use_default()
            .execute(&mut dpe, TEST_LOCALITIES[0])
            .unwrap();
        let sim_local = TEST_LOCALITIES[1];
        // Make a simulation context to test against.
        InitCtxCmd::new_simulation()
            .execute(&mut dpe, sim_local)
            .unwrap();

        // Invalid handle.
        assert_eq!(
            Err(DpeErrorCode::InvalidHandle),
            TagTciCmd {
                handle: TEST_HANDLE,
                tag: 0,
            }
            .execute(&mut dpe, TEST_LOCALITIES[0])
        );

        // Wrong locality.
        assert_eq!(
            Err(DpeErrorCode::InvalidHandle),
            TagTciCmd {
                handle: DpeInstance::<OpensslCrypto>::DEFAULT_CONTEXT_HANDLE,
                tag: 0,
            }
            .execute(&mut dpe, TEST_LOCALITIES[1])
        );

        // Tag default handle.
        assert_eq!(
            Ok(Response::TagTci(NewHandleResp {
                handle: DpeInstance::<OpensslCrypto>::DEFAULT_CONTEXT_HANDLE,
            })),
            TagTciCmd {
                handle: DpeInstance::<OpensslCrypto>::DEFAULT_CONTEXT_HANDLE,
                tag: 0,
            }
            .execute(&mut dpe, TEST_LOCALITIES[0])
        );

        // Try to re-tag the default context.
        assert_eq!(
            Err(DpeErrorCode::BadTag),
            TagTciCmd {
                handle: DpeInstance::<OpensslCrypto>::DEFAULT_CONTEXT_HANDLE,
                tag: 1,
            }
            .execute(&mut dpe, TEST_LOCALITIES[0])
        );

        // Try same tag on simulation.
        assert_eq!(
            Err(DpeErrorCode::BadTag),
            TagTciCmd {
                handle: SIMULATION_HANDLE,
                tag: 0,
            }
            .execute(&mut dpe, TEST_LOCALITIES[1])
        );

        // Give the simulation context another handle so we can prove the handle rotates when it
        // gets tagged.
        let simulation_ctx = &mut dpe.contexts[dpe
            .get_active_context_pos(&SIMULATION_HANDLE, sim_local)
            .unwrap()];
        let sim_tmp_handle = [0xff; HANDLE_SIZE];
        simulation_ctx.handle = sim_tmp_handle;
        assert!(dpe
            .get_active_context_pos(&SIMULATION_HANDLE, sim_local)
            .is_none());

        // Tag simulation.
        assert_eq!(
            Ok(Response::TagTci(NewHandleResp {
                handle: SIMULATION_HANDLE,
            })),
            TagTciCmd {
                handle: sim_tmp_handle,
                tag: 1,
            }
            .execute(&mut dpe, TEST_LOCALITIES[1])
        );
        // Make sure it rotated back to the deterministic simulation handle.
        assert!(dpe
            .get_active_context_pos(&sim_tmp_handle, sim_local)
            .is_none());
        assert!(dpe
            .get_active_context_pos(&SIMULATION_HANDLE, sim_local)
            .is_some());
    }
}
