// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::{Context, ContextHandle},
    dpe_instance::{flags_iter, DpeEnv, DpeInstance, DpeTypes},
    response::{DpeErrorCode, Response, ResponseHdr},
    MAX_HANDLES,
};
use bitflags::bitflags;

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::FromBytes)]
#[cfg_attr(test, derive(zerocopy::AsBytes))]
pub struct DestroyCtxFlags(u32);

bitflags! {
    impl DestroyCtxFlags: u32 {
        const DESTROY_CHILDREN_FLAG_MASK = 1u32 << 31;
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::FromBytes)]
#[cfg_attr(test, derive(zerocopy::AsBytes))]
pub struct DestroyCtxCmd {
    pub handle: ContextHandle,
    pub flags: DestroyCtxFlags,
}

impl DestroyCtxCmd {
    const fn flag_is_destroy_descendants(&self) -> bool {
        self.flags
            .contains(DestroyCtxFlags::DESTROY_CHILDREN_FLAG_MASK)
    }
}

impl CommandExecution for DestroyCtxCmd {
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        _env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
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
            if idx >= dpe.contexts.len() {
                return Err(DpeErrorCode::InternalError);
            }
            dpe.contexts[idx].destroy();
            let parent = dpe.contexts[idx].parent_idx;
            if parent != Context::ROOT_INDEX {
                dpe.contexts[parent as usize].remove_child(idx)?;
            }
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
        commands::{Command, CommandHdr, InitCtxCmd},
        context::ContextState,
        dpe_instance::tests::{TestTypes, SIMULATION_HANDLE, TEST_HANDLE, TEST_LOCALITIES},
        support::Support,
    };
    use crypto::OpensslCrypto;
    use platform::default::DefaultPlatform;
    use zerocopy::AsBytes;

    const TEST_DESTROY_CTX_CMD: DestroyCtxCmd = DestroyCtxCmd {
        handle: SIMULATION_HANDLE,
        flags: DestroyCtxFlags(0x1234_5678),
    };

    #[test]
    fn test_deserialize_destroy_context() {
        let mut command = CommandHdr::new_for_test(Command::DESTROY_CONTEXT)
            .as_bytes()
            .to_vec();
        command.extend(TEST_DESTROY_CTX_CMD.as_bytes());
        assert_eq!(
            Ok(Command::DestroyCtx(TEST_DESTROY_CTX_CMD)),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_destroy_context() {
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::default()).unwrap();

        InitCtxCmd::new_use_default()
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap();

        // Wrong locality.
        assert_eq!(
            Err(DpeErrorCode::InvalidLocality),
            DestroyCtxCmd {
                handle: ContextHandle::default(),
                flags: DestroyCtxFlags::empty(),
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[1])
        );

        // create two dummy contexts at indices 0 and 1, with 1 being the child of 0
        activate_dummy_context(&mut dpe, 0, Context::ROOT_INDEX, &TEST_HANDLE, &[1]);
        activate_dummy_context(&mut dpe, 1, 0, &ContextHandle::default(), &[]);
        // destroy context[1]
        assert_eq!(
            Ok(Response::DestroyCtx(ResponseHdr::new(
                DpeErrorCode::NoError,
            ))),
            DestroyCtxCmd {
                handle: ContextHandle::default(),
                flags: DestroyCtxFlags::empty(),
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
        assert_eq!(dpe.contexts[1].state, ContextState::Inactive);
        assert_eq!(dpe.contexts[0].children, 0);
        // destroy context[0]
        assert_eq!(
            Ok(Response::DestroyCtx(ResponseHdr::new(
                DpeErrorCode::NoError,
            ))),
            DestroyCtxCmd {
                handle: TEST_HANDLE,
                flags: DestroyCtxFlags::empty(),
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
        assert_eq!(dpe.contexts[0].state, ContextState::Inactive);

        activate_dummy_context(
            &mut dpe,
            0,
            Context::ROOT_INDEX,
            &ContextHandle::default(),
            &[1, 2],
        );
        activate_dummy_context(
            &mut dpe,
            1,
            0,
            &ContextHandle([1; ContextHandle::SIZE]),
            &[3, 4],
        );
        activate_dummy_context(
            &mut dpe,
            2,
            0,
            &ContextHandle([2; ContextHandle::SIZE]),
            &[5, 6],
        );
        activate_dummy_context(
            &mut dpe,
            3,
            1,
            &ContextHandle([3; ContextHandle::SIZE]),
            &[],
        );
        activate_dummy_context(
            &mut dpe,
            4,
            1,
            &ContextHandle([4; ContextHandle::SIZE]),
            &[],
        );
        activate_dummy_context(
            &mut dpe,
            5,
            2,
            &ContextHandle([5; ContextHandle::SIZE]),
            &[],
        );
        activate_dummy_context(
            &mut dpe,
            6,
            2,
            &ContextHandle([6; ContextHandle::SIZE]),
            &[],
        );

        // destroy context[0] and all descendents
        assert_eq!(
            Ok(Response::DestroyCtx(ResponseHdr::new(
                DpeErrorCode::NoError,
            ))),
            DestroyCtxCmd {
                handle: ContextHandle::default(),
                flags: DestroyCtxFlags::DESTROY_CHILDREN_FLAG_MASK,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
        assert_eq!(dpe.contexts[0].state, ContextState::Inactive);
        assert_eq!(dpe.contexts[1].state, ContextState::Inactive);
        assert_eq!(dpe.contexts[2].state, ContextState::Inactive);
        assert_eq!(dpe.contexts[3].state, ContextState::Inactive);
        assert_eq!(dpe.contexts[4].state, ContextState::Inactive);
        assert_eq!(dpe.contexts[5].state, ContextState::Inactive);
        assert_eq!(dpe.contexts[6].state, ContextState::Inactive);
        assert_eq!(dpe.contexts[0].children, 0);
        assert_eq!(dpe.contexts[1].children, 0);
        assert_eq!(dpe.contexts[2].children, 0);
        assert_eq!(dpe.contexts[3].children, 0);
    }

    fn activate_dummy_context(
        dpe: &mut DpeInstance,
        idx: usize,
        parent_idx: u8,
        handle: &ContextHandle,
        children: &[u8],
    ) -> () {
        dpe.contexts[idx].state = ContextState::Active;
        dpe.contexts[idx].handle = *handle;
        dpe.contexts[idx].parent_idx = parent_idx;
        for i in children {
            dpe.contexts[idx].add_child(*i as usize).unwrap();
        }
    }
}
