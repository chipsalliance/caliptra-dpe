// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::{Children, Context, ContextHandle, ContextState},
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{DpeErrorCode, Response},
    State,
};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::cfi_launder;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq};

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
pub struct DestroyCtxCmd {
    pub handle: ContextHandle,
}

pub(crate) fn destroy_context(
    context_handle: &ContextHandle,
    state: &mut State,
    locality: u32,
) -> Result<(), DpeErrorCode> {
    let idx = state.get_active_context_pos(context_handle, locality)?;
    let context = &state.contexts[idx];
    // Make sure the command is coming from the right locality.
    if context.locality != locality {
        return Err(DpeErrorCode::InvalidLocality);
    } else {
        #[cfg(not(feature = "no-cfi"))]
        cfi_assert_eq(context.locality, locality);
    }

    // mark consecutive retired parent contexts without active children to be destroyed
    let mut retired_contexts = Children::empty();
    let mut parent_idx = context.parent_idx as usize;
    loop {
        if parent_idx == Context::ROOT_INDEX as usize {
            break;
        } else if parent_idx >= state.contexts.len() {
            return Err(DpeErrorCode::InternalError);
        }
        let parent_context = &state.contexts[parent_idx];
        // make sure the retired context does not have other active child contexts
        let child_context_count = parent_context.children.iter().count();
        if parent_context.state == ContextState::Retired && cfi_launder(child_context_count) == 1 {
            retired_contexts.add_child(parent_idx)?;
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(parent_context.state != ContextState::Retired || child_context_count != 1);
            break;
        }

        parent_idx = parent_context.parent_idx as usize;
    }

    // create a bitmask indicating that the current context, all its descendants, and its consecutive
    // retired parent contexts should be destroyed
    let mut to_destroy = state.get_descendants(context)?;
    to_destroy.add_child(idx)?;
    to_destroy.add_children(retired_contexts);

    for (idx, c) in state.contexts.iter_mut().enumerate() {
        // Clears all the to_destroy bits in the children of every context
        c.children.remove_children(to_destroy);
        if to_destroy.has_child(idx) {
            c.destroy();
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert_eq(to_destroy.has_child(idx), false);
        }
    }
    Ok(())
}

impl CommandExecution for DestroyCtxCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        destroy_context(&self.handle, env.state, locality)?;
        Ok(Response::DestroyCtx(
            dpe.response_hdr(DpeErrorCode::NoError),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{
            tests::PROFILES, Command, CommandHdr, DeriveContextCmd, DeriveContextFlags, InitCtxCmd,
        },
        context::{Context, ContextState},
        dpe_instance::tests::{
            test_env, test_state, DPE_PROFILE, SIMULATION_HANDLE, TEST_HANDLE, TEST_LOCALITIES,
        },
    };
    use caliptra_cfi_lib_git::CfiCounter;
    use zerocopy::IntoBytes;

    const TEST_DESTROY_CTX_CMD: DestroyCtxCmd = DestroyCtxCmd {
        handle: SIMULATION_HANDLE,
    };

    #[test]
    fn test_deserialize_destroy_context() {
        CfiCounter::reset_for_test();
        for p in PROFILES {
            let mut command = CommandHdr::new(p, Command::DESTROY_CONTEXT)
                .as_bytes()
                .to_vec();
            command.extend(TEST_DESTROY_CTX_CMD.as_bytes());
            assert_eq!(
                Ok(Command::DestroyCtx(&TEST_DESTROY_CTX_CMD)),
                Command::deserialize(p, &command)
            );
        }
    }

    #[test]
    fn test_destroy_context() {
        CfiCounter::reset_for_test();
        let mut state = State::default();
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

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
        activate_dummy_context(&mut env.state, 0, Context::ROOT_INDEX, &TEST_HANDLE, &[1]);
        activate_dummy_context(&mut env.state, 1, 0, &ContextHandle::default(), &[]);
        // destroy context[1]
        assert_eq!(
            Ok(Response::DestroyCtx(
                dpe.response_hdr(DpeErrorCode::NoError)
            )),
            DestroyCtxCmd {
                handle: ContextHandle::default(),
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
        assert_eq!(env.state.contexts[1].state, ContextState::Inactive);
        assert!(env.state.contexts[0].children.is_empty());
        // destroy context[0]
        assert_eq!(
            Ok(Response::DestroyCtx(
                dpe.response_hdr(DpeErrorCode::NoError)
            )),
            DestroyCtxCmd {
                handle: TEST_HANDLE,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
        assert_eq!(env.state.contexts[0].state, ContextState::Inactive);

        activate_dummy_context(
            &mut env.state,
            0,
            Context::ROOT_INDEX,
            &ContextHandle::default(),
            &[1, 2],
        );
        activate_dummy_context(
            &mut env.state,
            1,
            0,
            &ContextHandle([1; ContextHandle::SIZE]),
            &[3, 4],
        );
        activate_dummy_context(
            &mut env.state,
            2,
            0,
            &ContextHandle([2; ContextHandle::SIZE]),
            &[5, 6],
        );
        activate_dummy_context(
            &mut env.state,
            3,
            1,
            &ContextHandle([3; ContextHandle::SIZE]),
            &[],
        );
        activate_dummy_context(
            &mut env.state,
            4,
            1,
            &ContextHandle([4; ContextHandle::SIZE]),
            &[],
        );
        activate_dummy_context(
            &mut env.state,
            5,
            2,
            &ContextHandle([5; ContextHandle::SIZE]),
            &[],
        );
        activate_dummy_context(
            &mut env.state,
            6,
            2,
            &ContextHandle([6; ContextHandle::SIZE]),
            &[],
        );

        // destroy context[0] and all descendents
        assert_eq!(
            Ok(Response::DestroyCtx(
                dpe.response_hdr(DpeErrorCode::NoError)
            )),
            DestroyCtxCmd {
                handle: ContextHandle::default(),
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
        assert_eq!(env.state.contexts[0].state, ContextState::Inactive);
        assert_eq!(env.state.contexts[1].state, ContextState::Inactive);
        assert_eq!(env.state.contexts[2].state, ContextState::Inactive);
        assert_eq!(env.state.contexts[3].state, ContextState::Inactive);
        assert_eq!(env.state.contexts[4].state, ContextState::Inactive);
        assert_eq!(env.state.contexts[5].state, ContextState::Inactive);
        assert_eq!(env.state.contexts[6].state, ContextState::Inactive);
        assert!(env.state.contexts[0].children.is_empty());
        assert!(env.state.contexts[1].children.is_empty());
        assert!(env.state.contexts[2].children.is_empty());
        assert!(env.state.contexts[3].children.is_empty());

        activate_dummy_context(
            &mut env.state,
            0,
            Context::ROOT_INDEX,
            &ContextHandle::default(),
            &[1, 2],
        );
        activate_dummy_context(
            &mut env.state,
            1,
            0,
            &ContextHandle([1; ContextHandle::SIZE]),
            &[],
        );
        activate_dummy_context(
            &mut env.state,
            2,
            0,
            &ContextHandle([2; ContextHandle::SIZE]),
            &[],
        );
        // destroy context[1]
        assert_eq!(
            Ok(Response::DestroyCtx(
                dpe.response_hdr(DpeErrorCode::NoError)
            )),
            DestroyCtxCmd {
                handle: ContextHandle([1; ContextHandle::SIZE]),
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
        assert_eq!(env.state.contexts[1].state, ContextState::Inactive);
        // check that context[2] is still a child of context[0]
        assert_eq!(env.state.contexts[0].children.bits(), 1 << 2);
    }

    #[test]
    fn test_retired_parent_contexts_destroyed() {
        CfiCounter::reset_for_test();
        let mut state = test_state();
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

        // create new context while preserving auto-initialized context
        let handle_1 = match (DeriveContextCmd {
            flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT | DeriveContextFlags::CHANGE_LOCALITY,
            target_locality: TEST_LOCALITIES[1],
            ..Default::default()
        })
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        {
            Ok(Response::DeriveContext(resp)) => resp.handle,
            Ok(_) => panic!("Invalid response type"),
            Err(e) => panic!("{:?}", e),
        };

        // retire context with handle 1 and create new context
        let handle_2 = match (DeriveContextCmd {
            handle: handle_1,
            target_locality: TEST_LOCALITIES[1],
            ..Default::default()
        })
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[1])
        {
            Ok(Response::DeriveContext(resp)) => resp.handle,
            Ok(_) => panic!("Invalid response type"),
            Err(e) => panic!("{:?}", e),
        };

        // retire context with handle 2 and create new context
        let handle_3 = match (DeriveContextCmd {
            handle: handle_2,
            target_locality: TEST_LOCALITIES[1],
            ..Default::default()
        })
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[1])
        {
            Ok(Response::DeriveContext(resp)) => resp.handle,
            Ok(_) => panic!("Invalid response type"),
            Err(e) => panic!("{:?}", e),
        };

        DestroyCtxCmd { handle: handle_3 }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[1])
            .unwrap();

        // only the auto-initialized context should remain, context[1] and context[2] should be
        // destroyed since they are in the chain of consecutive retired parents of the destroyed
        // context.
        assert_eq!(
            env.state
                .count_contexts(|ctx| ctx.state != ContextState::Inactive)
                .unwrap(),
            1
        );
        assert_eq!(env.state.contexts[2].state, ContextState::Inactive);
    }

    #[test]
    fn test_retired_parent_context_not_destroyed_if_it_has_other_active_children() {
        CfiCounter::reset_for_test();
        let mut state = test_state();
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

        // create new context while preserving auto-initialized context
        let parent_handle = match (DeriveContextCmd {
            flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT | DeriveContextFlags::CHANGE_LOCALITY,
            target_locality: TEST_LOCALITIES[1],
            ..Default::default()
        })
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        {
            Ok(Response::DeriveContext(resp)) => resp.handle,
            Ok(_) => panic!("Invalid response type"),
            Err(e) => panic!("{:?}", e),
        };

        // derive one child from the parent
        let parent_handle = match (DeriveContextCmd {
            handle: parent_handle,
            flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
            target_locality: TEST_LOCALITIES[1],
            ..Default::default()
        })
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[1])
        {
            Ok(Response::DeriveContext(resp)) => resp.parent_handle,
            Ok(_) => panic!("Invalid response type"),
            Err(e) => panic!("{:?}", e),
        };

        // derive another child while retiring the parent handle
        let handle_b = match (DeriveContextCmd {
            handle: parent_handle,
            target_locality: TEST_LOCALITIES[1],
            ..Default::default()
        })
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[1])
        {
            Ok(Response::DeriveContext(resp)) => resp.handle,
            Ok(_) => panic!("Invalid response type"),
            Err(e) => panic!("{:?}", e),
        };

        DestroyCtxCmd { handle: handle_b }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[1])
            .unwrap();

        // Since the retired handle has another active context apart from handle_b, it
        // shouldn't be destroyed.
        assert_eq!(
            env.state
                .count_contexts(|ctx| ctx.state != ContextState::Inactive)
                .unwrap(),
            3
        );
        assert_eq!(env.state.contexts[1].state, ContextState::Retired);
    }

    fn activate_dummy_context(
        state: &mut State,
        idx: usize,
        parent_idx: u8,
        handle: &ContextHandle,
        children: &[u8],
    ) {
        state.contexts[idx].state = ContextState::Active;
        state.contexts[idx].handle = *handle;
        state.contexts[idx].parent_idx = parent_idx;
        for i in children {
            let children = state.contexts[idx].add_child(*i as usize).unwrap();
            state.contexts[idx].children = children;
        }
    }
}
