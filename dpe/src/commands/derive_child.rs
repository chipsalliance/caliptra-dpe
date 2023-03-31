// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    dpe_instance::{ContextHandle, DpeInstance},
    response::{DpeErrorCode, Response},
    DPE_PROFILE,
};
use core::mem::size_of;
use crypto::Crypto;

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(zerocopy::AsBytes, zerocopy::FromBytes))]
pub struct DeriveChildCmd {
    handle: ContextHandle,
    data: [u8; DPE_PROFILE.get_hash_size()],
    flags: u32,
    tcb_type: u32,
    target_locality: u32,
}

impl DeriveChildCmd {
    const _INTERNAL_INPUT_INFO: u32 = 1 << 31;
    const _INTERNAL_INPUT_DICE: u32 = 1 << 30;
    const _RETAIN_PARENT: u32 = 1 << 29;
    const _TARGET_IS_DEFAULT: u32 = 1 << 28;

    const fn _is_internal_input_info(&self) -> bool {
        self.flags & Self::_INTERNAL_INPUT_INFO != 0
    }

    const fn _is_internal_input_dice(&self) -> bool {
        self.flags & Self::_INTERNAL_INPUT_DICE != 0
    }

    const fn _is_retain_parent(&self) -> bool {
        self.flags & Self::_RETAIN_PARENT != 0
    }

    const fn _is_target_is_default(&self) -> bool {
        self.flags & Self::_TARGET_IS_DEFAULT != 0
    }
}

impl<C: Crypto> CommandExecution<C> for DeriveChildCmd {
    fn execute(&self, _dpe: &mut DpeInstance<C>, _locality: u32) -> Result<Response, DpeErrorCode> {
        Err(DpeErrorCode::InvalidCommand)
    }
}

impl TryFrom<&[u8]> for DeriveChildCmd {
    type Error = DpeErrorCode;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < size_of::<DeriveChildCmd>() {
            return Err(DpeErrorCode::InvalidArgument);
        }

        let mut offset: usize = 0;

        let handle = ContextHandle::try_from(raw)?;
        offset += ContextHandle::SIZE;

        let mut data = [0; DPE_PROFILE.get_hash_size()];
        data.copy_from_slice(&raw[offset..offset + DPE_PROFILE.get_hash_size()]);
        offset += DPE_PROFILE.get_hash_size();

        let flags = u32::from_le_bytes(raw[offset..offset + size_of::<u32>()].try_into().unwrap());
        offset += size_of::<u32>();

        let tcb_type =
            u32::from_le_bytes(raw[offset..offset + size_of::<u32>()].try_into().unwrap());
        offset += size_of::<u32>();

        let target_locality =
            u32::from_le_bytes(raw[offset..offset + size_of::<u32>()].try_into().unwrap());

        Ok(DeriveChildCmd {
            handle,
            data,
            flags,
            tcb_type,
            target_locality,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{commands::tests::TEST_DIGEST, dpe_instance::tests::SIMULATION_HANDLE};
    use zerocopy::{AsBytes, FromBytes};

    const TEST_DERIVE_CHILD_CMD: DeriveChildCmd = DeriveChildCmd {
        handle: SIMULATION_HANDLE,
        data: TEST_DIGEST,
        flags: 0x1234_5678,
        tcb_type: 0x9876_5432,
        target_locality: 0x10CA_1171,
    };

    #[test]
    fn try_from_derive_child() {
        let command_bytes = TEST_DERIVE_CHILD_CMD.as_bytes();
        assert_eq!(
            DeriveChildCmd::read_from_prefix(command_bytes).unwrap(),
            DeriveChildCmd::try_from(command_bytes).unwrap(),
        );
    }

    #[test]
    fn test_slice_to_derive_child() {
        let invalid_argument: Result<DeriveChildCmd, DpeErrorCode> =
            Err(DpeErrorCode::InvalidArgument);

        // Test if too small.
        assert_eq!(
            invalid_argument,
            DeriveChildCmd::try_from([0u8; size_of::<DeriveChildCmd>() - 1].as_slice())
        );

        assert_eq!(
            TEST_DERIVE_CHILD_CMD,
            DeriveChildCmd::try_from(TEST_DERIVE_CHILD_CMD.as_bytes()).unwrap()
        );
    }
}
