// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::{Children, Context, ContextHandle, ContextState},
    dpe_instance::{DpeEnv, DpeInstance},
    error::{DpeErrorCode, InternalErrorCode},
    State,
};
#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_impl_fn;
#[cfg(feature = "cfi")]
use caliptra_cfi_lib::{cfi_assert, cfi_assert_bool, cfi_assert_eq, cfi_launder};
use caliptra_dpe_response_buffer::ResponseBuffer;
use zerocopy::IntoBytes;

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
    let (context, idx) = state.get_active_context_and_idx(context_handle, locality)?;
    // Make sure the command is coming from the right locality.
    if context.locality != locality {
        return Err(DpeErrorCode::InvalidLocality);
    } else {
        #[cfg(feature = "cfi")]
        cfi_assert_eq(context.locality, locality);
    }

    // mark consecutive retired parent contexts without active children to be destroyed
    let mut retired_contexts = Children::empty();
    let mut parent_idx = context.parent_idx as usize;
    loop {
        if parent_idx == Context::ROOT_INDEX as usize {
            break;
        }
        let parent_context = state
            .contexts
            .get(parent_idx)
            .ok_or(DpeErrorCode::from(InternalErrorCode::DestroyParentIndexOob))?;
        // make sure the retired context does not have other active child contexts
        let child_context_count = parent_context.children.iter().count();
        #[cfg(feature = "cfi")]
        let child_context_count = cfi_launder(child_context_count);
        if parent_context.state == ContextState::Retired && child_context_count == 1 {
            retired_contexts.add_child(parent_idx)?;
        } else {
            #[cfg(feature = "cfi")]
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
            #[cfg(feature = "cfi")]
            cfi_assert_eq(to_destroy.has_child(idx), false);
        }
    }
    Ok(())
}

impl CommandExecution for DestroyCtxCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    fn execute_serialized(
        &self,
        dpe: &mut DpeInstance,
        env: &mut dyn DpeEnv,
        locality: u32,
        out: &mut dyn ResponseBuffer,
    ) -> Result<usize, DpeErrorCode> {
        destroy_context(&self.handle, env.state(), locality)?;
        let resp = dpe.response_hdr(DpeErrorCode::NoError);
        let bytes = resp.as_bytes();
        out.write_at(0, bytes)
            .map_err(|_| DpeErrorCode::InvalidResponseBuf)?;
        Ok(bytes.len())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::{
        commands::{
            tests::PROFILES, Command, CommandHdr, DeriveContextCmd, DeriveContextFlags, InitCtxCmd,
        },
        context::{Context, ContextState},
        dpe_instance::tests::{
            test_state, DPE_PROFILE, SIMULATION_HANDLE, TEST_HANDLE, TEST_LOCALITIES,
        },
        response::Response,
        test_env, AlignedBuf,
    };
    use caliptra_cfi_lib::CfiCounter;
    use core::mem::size_of;
    use zerocopy::IntoBytes;

    const TEST_DESTROY_CTX_CMD: DestroyCtxCmd = DestroyCtxCmd {
        handle: SIMULATION_HANDLE,
    };

    #[test]
    fn test_deserialize_destroy_context() {
        CfiCounter::reset_for_test();
        for p in PROFILES {
            let hdr = CommandHdr::new(p, Command::DESTROY_CONTEXT);
            let mut buf =
                AlignedBuf::<{ size_of::<CommandHdr>() + size_of::<DestroyCtxCmd>() }>::new();
            let command = buf.as_mut_bytes();
            command[..size_of::<CommandHdr>()].copy_from_slice(hdr.as_bytes());
            command[size_of::<CommandHdr>()..].copy_from_slice(TEST_DESTROY_CTX_CMD.as_bytes());
            assert_eq!(
                Ok(Command::DestroyCtx(&TEST_DESTROY_CTX_CMD)),
                Command::deserialize(p, command)
            );
        }
    }

    #[test]
    fn test_destroy_context() {
        CfiCounter::reset_for_test();
        let mut state = State::default();
        test_env!(env, &mut state);
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
        activate_dummy_context(env.state, 0, Context::ROOT_INDEX, &TEST_HANDLE, &[1]);
        activate_dummy_context(env.state, 1, 0, &ContextHandle::default(), &[]);
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
            env.state,
            0,
            Context::ROOT_INDEX,
            &ContextHandle::default(),
            &[1, 2],
        );
        activate_dummy_context(
            env.state,
            1,
            0,
            &ContextHandle([1; ContextHandle::SIZE]),
            &[3, 4],
        );
        activate_dummy_context(
            env.state,
            2,
            0,
            &ContextHandle([2; ContextHandle::SIZE]),
            &[5, 6],
        );
        activate_dummy_context(
            env.state,
            3,
            1,
            &ContextHandle([3; ContextHandle::SIZE]),
            &[],
        );
        activate_dummy_context(
            env.state,
            4,
            1,
            &ContextHandle([4; ContextHandle::SIZE]),
            &[],
        );
        activate_dummy_context(
            env.state,
            5,
            2,
            &ContextHandle([5; ContextHandle::SIZE]),
            &[],
        );
        activate_dummy_context(
            env.state,
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
            env.state,
            0,
            Context::ROOT_INDEX,
            &ContextHandle::default(),
            &[1, 2],
        );
        activate_dummy_context(
            env.state,
            1,
            0,
            &ContextHandle([1; ContextHandle::SIZE]),
            &[],
        );
        activate_dummy_context(
            env.state,
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
        test_env!(env, &mut state);
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
        test_env!(env, &mut state);
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
            // Use a distinct tci_type; the parent already has one child with
            // tci_type=0 (from the previous DeriveContext), and INPUT_TYPE must
            // be unique among siblings.
            tci_type: 1,
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
