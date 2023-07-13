// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::ContextHandle,
    dpe_instance::{flags_iter, DpeInstance},
    response::{DpeErrorCode, Response, ResponseHdr},
    MAX_HANDLES,
};
use crypto::Crypto;
use platform::Platform;

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::FromBytes)]
#[cfg_attr(test, derive(zerocopy::AsBytes))]
pub struct DestroyCtxCmd {
    pub handle: ContextHandle,
    pub flags: u32,
}

impl DestroyCtxCmd {
    const DESTROY_CHILDREN_FLAG_MASK: u32 = 1 << 31;

    const fn flag_is_destroy_descendants(&self) -> bool {
        self.flags & Self::DESTROY_CHILDREN_FLAG_MASK != 0
    }
}

impl<C: Crypto, P: Platform> CommandExecution<C, P> for DestroyCtxCmd {
    fn execute(
        &self,
        dpe: &mut DpeInstance<C, P>,
        locality: u32,
        _crypto: &mut C,
    ) -> Result<Response, DpeErrorCode> {
        let idx = dpe.get_active_context_pos(&self.handle, locality)?;
        let context = &dpe.contexts[idx];
        // Make sure the command is coming from the right locality.
        if context.locality != locality {
            return Err(DpeErrorCode::InvalidLocality);
        }

        let to_destroy = if self.flag_is_destroy_descendants() {
            (1 << idx) | dpe.get_descendants(context)?
        } else {
            1 << idx
        };

        for idx in flags_iter(to_destroy, MAX_HANDLES) {
            dpe.contexts[idx].destroy();
        }
        Ok(Response::DestroyCtx(ResponseHdr::new(
            DpeErrorCode::NoError,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{Command, CommandHdr},
        dpe_instance::tests::SIMULATION_HANDLE,
    };
    use zerocopy::AsBytes;

    const TEST_DESTROY_CTX_CMD: DestroyCtxCmd = DestroyCtxCmd {
        handle: SIMULATION_HANDLE,
        flags: 0x1234_5678,
    };

    #[test]
    fn test_deserialize_destroy_context() {
        let mut command = CommandHdr::new_for_test(Command::DestroyCtx(TEST_DESTROY_CTX_CMD))
            .as_bytes()
            .to_vec();
        command.extend(TEST_DESTROY_CTX_CMD.as_bytes());
        assert_eq!(
            Ok(Command::DestroyCtx(TEST_DESTROY_CTX_CMD)),
            Command::deserialize(&command)
        );
    }
}
