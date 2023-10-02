// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::ContextHandle,
    dpe_instance::{flags_iter, DpeEnv, DpeInstance, DpeTypes},
    response::{DpeErrorCode, Response, ResponseHdr},
    MAX_HANDLES,
};

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::FromBytes)]
#[cfg_attr(test, derive(zerocopy::AsBytes))]
pub struct DestroyCtxCmd {
    pub handle: ContextHandle,
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

        let to_destroy = (1 << idx) | dpe.get_descendants(context)?;

        // contexts_to_destroy[i] == true implies dpe.contexts[i] must be destroyed
        let mut contexts_to_destroy = [false; MAX_HANDLES];
        // updated_children[i] holds i's non-destroyed children.
        let mut updated_children = [0u32; MAX_HANDLES];
        // This loop collects updates to DPE state so that updates to DPE are atomic
        // and so that we don't need to copy every context.
        for idx in flags_iter(to_destroy, MAX_HANDLES) {
            if idx >= dpe.contexts.len() {
                return Err(DpeErrorCode::InternalError);
            }
            contexts_to_destroy[idx] = true;
            let parent = dpe.contexts[idx].parent_idx as usize;
            // If parent is the root, we cannot update it's children.
            if parent < MAX_HANDLES {
                let children_without_idx = dpe.contexts[parent].remove_child(idx)?;
                // Need to take intersection because multiple children of the same parent could be destroyed.
                updated_children[parent] &= children_without_idx;
            }
        }

        // At this point, we cannot error out anymore so it is safe to mutate DPE state
        for (idx, context_to_destroy) in contexts_to_destroy
            .iter()
            .enumerate()
            .take(contexts_to_destroy.len())
        {
            if *context_to_destroy {
                dpe.contexts[idx].destroy();
                let parent = dpe.contexts[idx].parent_idx as usize;
                if parent < MAX_HANDLES {
                    dpe.contexts[parent].children = updated_children[parent];
                }
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
        context::{Context, ContextState},
        dpe_instance::tests::{TestTypes, SIMULATION_HANDLE, TEST_HANDLE, TEST_LOCALITIES},
        support::Support,
    };
    use crypto::OpensslCrypto;
    use platform::default::DefaultPlatform;
    use zerocopy::AsBytes;

    const TEST_DESTROY_CTX_CMD: DestroyCtxCmd = DestroyCtxCmd {
        handle: SIMULATION_HANDLE,
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
            let children = dpe.contexts[idx].add_child(*i as usize).unwrap();
            dpe.contexts[idx].children = children;
        }
    }
}
