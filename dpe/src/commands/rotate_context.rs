// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::{ContextHandle, ContextState},
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{DpeErrorCode, NewHandleResp, Response, ResponseHdr},
};
use bitflags::bitflags;
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
pub struct RotateCtxFlags(u32);

bitflags! {
    impl RotateCtxFlags: u32 {
        const TARGET_IS_DEFAULT = 1u32 << 31;
    }
}

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
pub struct RotateCtxCmd {
    pub handle: ContextHandle,
    pub flags: RotateCtxFlags,
}

impl RotateCtxCmd {
    pub const TARGET_IS_DEFAULT: u32 = 1 << 31;

    const fn uses_target_is_default(&self) -> bool {
        self.flags.contains(RotateCtxFlags::TARGET_IS_DEFAULT)
    }

    /// Check if there are non-default context handles in
    /// `locality` other than dpe.contexts[`target_idx`].handle
    ///
    ///
    /// # Arguments
    ///
    /// * `dpe` - DPE instance
    /// * `locality` - The locality to search
    /// * `target_idx` - The index of the context that is not considered
    fn non_default_valid_handles_exist(
        &self,
        dpe: &mut DpeInstance,
        locality: u32,
        target_idx: usize,
    ) -> bool {
        dpe.contexts.iter().enumerate().any(|(idx, context)| {
            context.state == ContextState::Active
                && context.locality == locality
                && !context.handle.is_default()
                && idx != target_idx
        })
    }
}

impl CommandExecution for RotateCtxCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        if !dpe.support.rotate_context() {
            return Err(DpeErrorCode::InvalidCommand);
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(dpe.support.rotate_context());
        }
        let idx = dpe.get_active_context_pos(&self.handle, locality)?;

        // Make sure caller's locality does not already have a default context.
        if self.uses_target_is_default() {
            let default_context_idx =
                dpe.get_active_context_pos(&ContextHandle::default(), locality);
            let non_default_valid_handles_exist =
                self.non_default_valid_handles_exist(dpe, locality, idx);
            if default_context_idx.is_ok() || cfi_launder(non_default_valid_handles_exist) {
                return Err(DpeErrorCode::InvalidArgument);
            } else {
                #[cfg(not(feature = "no-cfi"))]
                cfi_assert!(default_context_idx.is_err() && !non_default_valid_handles_exist);
            }
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(!self.uses_target_is_default());
        }

        let new_handle = if self.uses_target_is_default() {
            ContextHandle::default()
        } else {
            dpe.generate_new_handle(env)?
        };
        dpe.contexts[idx].handle = new_handle;

        Ok(Response::RotateCtx(NewHandleResp {
            handle: new_handle,
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
    use caliptra_cfi_lib_git::CfiCounter;
    use crypto::OpensslCrypto;
    use platform::default::DefaultPlatform;
    use zerocopy::IntoBytes;

    const TEST_ROTATE_CTX_CMD: RotateCtxCmd = RotateCtxCmd {
        flags: RotateCtxFlags(0x1234_5678),
        handle: TEST_HANDLE,
    };

    #[test]
    fn test_deserialize_rotate_context() {
        CfiCounter::reset_for_test();
        let mut command = CommandHdr::new_for_test(Command::ROTATE_CONTEXT_HANDLE)
            .as_bytes()
            .to_vec();
        command.extend(TEST_ROTATE_CTX_CMD.as_bytes());
        assert_eq!(
            Ok(Command::RotateCtx(TEST_ROTATE_CTX_CMD)),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_rotate_context() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::default()).unwrap();
        // Make sure it returns an error if the command is marked unsupported.
        assert_eq!(
            Err(DpeErrorCode::InvalidCommand),
            RotateCtxCmd {
                handle: ContextHandle::default(),
                flags: RotateCtxFlags::empty(),
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // Make a new instance that supports RotateContext.
        let mut dpe = DpeInstance::new(&mut env, Support::ROTATE_CONTEXT).unwrap();
        InitCtxCmd::new_use_default()
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap();

        // Invalid handle.
        assert_eq!(
            Err(DpeErrorCode::InvalidHandle),
            RotateCtxCmd {
                handle: TEST_HANDLE,
                flags: RotateCtxFlags::empty(),
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // Wrong locality.
        assert_eq!(
            Err(DpeErrorCode::InvalidLocality),
            RotateCtxCmd {
                handle: ContextHandle::default(),
                flags: RotateCtxFlags::empty(),
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[1])
        );

        // Caller's locality already has default context.
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            RotateCtxCmd {
                handle: ContextHandle::default(),
                flags: RotateCtxFlags::TARGET_IS_DEFAULT,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // Rotate default handle.
        assert_eq!(
            Ok(Response::RotateCtx(NewHandleResp {
                handle: RANDOM_HANDLE,
                resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
            })),
            RotateCtxCmd {
                handle: ContextHandle::default(),
                flags: RotateCtxFlags::empty(),
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        dpe.contexts[1].state = ContextState::Active;
        dpe.contexts[1].locality = TEST_LOCALITIES[0];
        dpe.contexts[1].handle = SIMULATION_HANDLE;
        // Check that it returns an error if we try to rotate to a default context
        // when we have other non-default contexts in the same locality.
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            RotateCtxCmd {
                handle: SIMULATION_HANDLE,
                flags: RotateCtxFlags::TARGET_IS_DEFAULT,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
        dpe.contexts[1].state = ContextState::Inactive;

        // New handle is all 0s if caller requests default handle
        assert_eq!(
            Ok(Response::RotateCtx(NewHandleResp {
                handle: ContextHandle::default(),
                resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
            })),
            RotateCtxCmd {
                handle: RANDOM_HANDLE,
                flags: RotateCtxFlags::TARGET_IS_DEFAULT,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
    }
}
