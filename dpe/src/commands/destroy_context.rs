// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::{Context, ContextHandle, ContextState},
    dpe_instance::{flags_iter, DpeEnv, DpeInstance, DpeTypes},
    response::{DpeErrorCode, Response},
    MAX_HANDLES,
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
    dpe: &mut DpeInstance,
    locality: u32,
) -> Result<(), DpeErrorCode> {
    let idx = dpe.get_active_context_pos(context_handle, locality)?;
    let context = &dpe.contexts[idx];
    // Make sure the command is coming from the right locality.
    if context.locality != locality {
        return Err(DpeErrorCode::InvalidLocality);
    } else {
        #[cfg(not(feature = "no-cfi"))]
        cfi_assert_eq(context.locality, locality);
    }

    // mark consecutive retired parent contexts without active children to be destroyed
    let mut retired_contexts = 0u32;
    let mut parent_idx = context.parent_idx as usize;
    loop {
        if parent_idx == Context::ROOT_INDEX as usize {
            break;
        } else if parent_idx >= dpe.contexts.len() {
            return Err(DpeErrorCode::InternalError);
        }
        let parent_context = &dpe.contexts[parent_idx];
        // make sure the retired context does not have other active child contexts
        let child_context_count = flags_iter(parent_context.children, MAX_HANDLES).count();
        if parent_context.state == ContextState::Retired && cfi_launder(child_context_count) == 1 {
            retired_contexts |= 1 << parent_idx;
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(parent_context.state != ContextState::Retired || child_context_count != 1);
            break;
        }

        parent_idx = parent_context.parent_idx as usize;
    }

    // create a bitmask indicating that the current context, all its descendants, and its consecutive
    // retired parent contexts should be destroyed
    let to_destroy = (1 << idx) | dpe.get_descendants(context)? | retired_contexts;

    for (idx, c) in dpe.contexts.iter_mut().enumerate() {
        // Clears all the to_destroy bits in the children of every context
        c.children &= !cfi_launder(to_destroy);
        if to_destroy & (1 << idx) != 0 {
            c.destroy();
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert_eq(to_destroy & (1 << idx), 0);
        }
    }
    Ok(())
}

impl CommandExecution for DestroyCtxCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        _env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        destroy_context(&self.handle, dpe, locality)?;
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
            tests::DEFAULT_PLATFORM, Command, CommandHdr, DeriveContextCmd, DeriveContextFlags,
            InitCtxCmd,
        },
        context::{Context, ContextState},
        dpe_instance::{
            tests::{TestTypes, SIMULATION_HANDLE, TEST_HANDLE, TEST_LOCALITIES},
            DpeInstanceFlags,
        },
        support::{test::SUPPORT, Support},
        DPE_PROFILE,
    };
    use caliptra_cfi_lib_git::CfiCounter;
    use crypto::RustCryptoImpl;
    use zerocopy::IntoBytes;

    const TEST_DESTROY_CTX_CMD: DestroyCtxCmd = DestroyCtxCmd {
        handle: SIMULATION_HANDLE,
    };

    #[test]
    fn test_deserialize_destroy_context() {
        CfiCounter::reset_for_test();
        let mut command = CommandHdr::new_for_test(Command::DESTROY_CONTEXT)
            .as_bytes()
            .to_vec();
        command.extend(TEST_DESTROY_CTX_CMD.as_bytes());
        assert_eq!(
            Ok(Command::DestroyCtx(&TEST_DESTROY_CTX_CMD)),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_destroy_context() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: RustCryptoImpl::new(),
            platform: DEFAULT_PLATFORM,
        };
        let mut dpe =
            DpeInstance::new(&mut env, Support::default(), DpeInstanceFlags::empty()).unwrap();

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
            Ok(Response::DestroyCtx(
                dpe.response_hdr(DpeErrorCode::NoError)
            )),
            DestroyCtxCmd {
                handle: ContextHandle::default(),
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
        assert_eq!(dpe.contexts[1].state, ContextState::Inactive);
        assert_eq!(dpe.contexts[0].children, 0);
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
            Ok(Response::DestroyCtx(
                dpe.response_hdr(DpeErrorCode::NoError)
            )),
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
            &[],
        );
        activate_dummy_context(
            &mut dpe,
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
        assert_eq!(dpe.contexts[1].state, ContextState::Inactive);
        // check that context[2] is still a child of context[0]
        assert_eq!(dpe.contexts[0].children, 1 << 2);
    }

    #[test]
    fn test_retired_parent_contexts_destroyed() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: RustCryptoImpl::new(),
            platform: DEFAULT_PLATFORM,
        };
        let mut dpe = DpeInstance::new(&mut env, SUPPORT, DpeInstanceFlags::empty()).unwrap();

        // create new context while preserving auto-initialized context
        let handle_1 = match (DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0u8; DPE_PROFILE.get_tci_size()],
            flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT | DeriveContextFlags::CHANGE_LOCALITY,
            tci_type: 0,
            target_locality: TEST_LOCALITIES[1],
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
            data: [0u8; DPE_PROFILE.get_tci_size()],
            flags: DeriveContextFlags::empty(),
            tci_type: 0,
            target_locality: TEST_LOCALITIES[1],
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
            data: [0u8; DPE_PROFILE.get_tci_size()],
            flags: DeriveContextFlags::empty(),
            tci_type: 0,
            target_locality: TEST_LOCALITIES[1],
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
            dpe.count_contexts(|ctx| ctx.state != ContextState::Inactive)
                .unwrap(),
            1
        );
        assert_eq!(dpe.contexts[2].state, ContextState::Inactive);
    }

    #[test]
    fn test_retired_parent_context_not_destroyed_if_it_has_other_active_children() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: RustCryptoImpl::new(),
            platform: DEFAULT_PLATFORM,
        };
        let mut dpe = DpeInstance::new(&mut env, SUPPORT, DpeInstanceFlags::empty()).unwrap();

        // create new context while preserving auto-initialized context
        let parent_handle = match (DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0u8; DPE_PROFILE.get_tci_size()],
            flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT | DeriveContextFlags::CHANGE_LOCALITY,
            tci_type: 0,
            target_locality: TEST_LOCALITIES[1],
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
            data: [0u8; DPE_PROFILE.get_tci_size()],
            flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
            tci_type: 0,
            target_locality: TEST_LOCALITIES[1],
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
            data: [0u8; DPE_PROFILE.get_tci_size()],
            flags: DeriveContextFlags::empty(),
            tci_type: 0,
            target_locality: TEST_LOCALITIES[1],
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
            dpe.count_contexts(|ctx| ctx.state != ContextState::Inactive)
                .unwrap(),
            3
        );
        assert_eq!(dpe.contexts[1].state, ContextState::Retired);
    }

    fn activate_dummy_context(
        dpe: &mut DpeInstance,
        idx: usize,
        parent_idx: u8,
        handle: &ContextHandle,
        children: &[u8],
    ) {
        dpe.contexts[idx].state = ContextState::Active;
        dpe.contexts[idx].handle = *handle;
        dpe.contexts[idx].parent_idx = parent_idx;
        for i in children {
            let children = dpe.contexts[idx].add_child(*i as usize).unwrap();
            dpe.contexts[idx].children = children;
        }
    }
}
