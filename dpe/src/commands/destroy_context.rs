// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    dpe_instance::{flags_iter, ContextHandle, DpeInstance},
    response::{DpeErrorCode, Response},
    MAX_HANDLES,
};
use core::mem::size_of;
use crypto::Crypto;

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(zerocopy::AsBytes, zerocopy::FromBytes))]
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

impl TryFrom<&[u8]> for DestroyCtxCmd {
    type Error = DpeErrorCode;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < size_of::<DestroyCtxCmd>() {
            return Err(DpeErrorCode::InvalidArgument);
        }

        let handle = ContextHandle::try_from(raw)?;

        let raw = &raw[ContextHandle::SIZE..];
        Ok(DestroyCtxCmd {
            handle,
            flags: u32::from_le_bytes(raw[0..4].try_into().unwrap()),
        })
    }
}

impl<C: Crypto> CommandExecution<C> for DestroyCtxCmd {
    fn execute(&self, dpe: &mut DpeInstance<C>, locality: u32) -> Result<Response, DpeErrorCode> {
        let idx = dpe
            .get_active_context_pos(&self.handle, locality)
            .ok_or(DpeErrorCode::InvalidHandle)?;
        let context = &dpe.contexts[idx];
        // Make sure the command is coming from the right locality.
        if context.locality != locality {
            return Err(DpeErrorCode::InvalidHandle);
        }

        let to_destroy = if self.flag_is_destroy_descendants() {
            (1 << idx) | dpe.get_descendants(context)?
        } else {
            1 << idx
        };

        for idx in flags_iter(to_destroy, MAX_HANDLES) {
            dpe.contexts[idx].destroy();
        }
        Ok(Response::DestroyCtx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{Command, CommandHdr},
        dpe_instance::tests::SIMULATION_HANDLE,
    };
    use zerocopy::{AsBytes, FromBytes};

    const TEST_DESTROY_CTX_CMD: DestroyCtxCmd = DestroyCtxCmd {
        handle: SIMULATION_HANDLE,
        flags: 0x1234_5678,
    };

    #[test]
    fn try_from_destroy_ctx() {
        let command_bytes = TEST_DESTROY_CTX_CMD.as_bytes();
        assert_eq!(
            DestroyCtxCmd::read_from_prefix(command_bytes).unwrap(),
            DestroyCtxCmd::try_from(command_bytes).unwrap(),
        );
    }

    #[test]
    fn test_deserialize_destroy_context() {
        let mut command = CommandHdr::new(Command::DestroyCtx(TEST_DESTROY_CTX_CMD))
            .as_bytes()
            .to_vec();
        command.extend(TEST_DESTROY_CTX_CMD.as_bytes());
        assert_eq!(
            Ok(Command::DestroyCtx(TEST_DESTROY_CTX_CMD)),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_slice_to_destroy_ctx() {
        let invalid_argument: Result<DestroyCtxCmd, DpeErrorCode> =
            Err(DpeErrorCode::InvalidArgument);

        // Test if too small.
        assert_eq!(
            invalid_argument,
            DestroyCtxCmd::try_from([0u8; size_of::<DestroyCtxCmd>() - 1].as_slice())
        );

        assert_eq!(
            TEST_DESTROY_CTX_CMD,
            DestroyCtxCmd::try_from(TEST_DESTROY_CTX_CMD.as_bytes()).unwrap()
        );
    }
}
