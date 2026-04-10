// Licensed under the Apache-2.0 license.

//! UpdateContextMeasurement is a vendor command that allows the holder of a parent context
//! handle to update the TCI measurement of a child context. It is semantically equivalent
//! to DeriveContext with RECURSIVE set, but authorizes the update via parent ownership
//! rather than child context ownership. Unlike DeriveContext(RECURSIVE=true), this command
//! bypasses the ALLOW_RECURSIVE check on the child; authorization comes from the parent handle.
//!
//! Command ID: 0x80000000 (first vendor command slot).

use super::CommandExecution;
use crate::{
    context::{Context, ContextState},
    dpe_instance::{DpeEnv, DpeInstance},
    mutresp,
    response::{DpeErrorCode, UpdateContextMeasurementResp},
    tci::TciMeasurement,
};
#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_impl_fn;
use core::mem::size_of_val;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// ABI input structure for UpdateContextMeasurement.
///
/// Wire layout (after CommandHdr):
/// | Offset    | Type       | Name              | Description                          |
/// |-----------|------------|-------------------|--------------------------------------|
/// | 0x00      | BYTES[16]  | parent_handle     | Handle of the parent context.        |
/// | 0x10      | HASH       | data              | New TCI measurement data.            |
/// | 0x10+H    | U32        | reserved          | Reserved; must be zero.              |
/// | 0x14+H    | U32        | tci_type          | INPUT_TYPE identifying the child.    |
/// | 0x18+H    | U32        | reserved_svn      | Reserved; ignored by this command.   |
#[repr(C)]
#[derive(Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct UpdateContextMeasurementCmd {
    /// Handle of the parent context. Must not be the default handle.
    pub parent_handle: crate::context::ContextHandle,
    /// New TCI measurement to extend into the child context.
    pub data: TciMeasurement,
    /// Reserved bitfield; must be zero.
    pub reserved: u32,
    /// Identifies the direct child of parent_handle to update (matched by tci_type).
    pub tci_type: u32,
    /// Reserved for future use; ignored by this command. SVN is fixed at context creation
    /// via DeriveContext and cannot be updated here.
    pub reserved_svn: u32,
}

impl CommandExecution for UpdateContextMeasurementCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    fn execute_serialized(
        &self,
        dpe: &mut DpeInstance,
        env: &mut dyn DpeEnv,
        locality: u32,
        out: &mut [u8],
    ) -> Result<usize, DpeErrorCode> {
        // PARENT_CONTEXT_HANDLE must not be the default (null) handle.
        if self.parent_handle.is_default() {
            return Err(DpeErrorCode::InvalidArgument);
        }

        // PARENT_CONTEXT_HANDLE must exist in the caller's locality.
        // Any failure (handle not found or wrong locality) => InvalidParentLocality.
        let parent_idx = env
            .state()
            .get_active_context_pos(&self.parent_handle, locality)
            .map_err(|_| DpeErrorCode::InvalidParentLocality)?;

        // Identify the direct child of parent_handle by INPUT_TYPE (tci_type).
        // Children is a Copy type so this does not hold a borrow on env.state().
        let parent_children = env.state().contexts[parent_idx].children;
        let child_idx = parent_children
            .iter()
            .find(|&idx| {
                let ctx = &env.state().contexts[idx];
                ctx.state == ContextState::Active && ctx.tci.tci_type == self.tci_type
            })
            .ok_or(DpeErrorCode::InvalidArgument)?;

        let response = mutresp::<UpdateContextMeasurementResp>(dpe.profile, out)?;

        // Copy the child context for mutation to avoid touching internal state on error.
        let mut tmp_child = env.state().contexts[child_idx];
        // The child's locality authorizes the TCI update (parent provides the authorization).
        let child_locality = tmp_child.locality;

        // Extend the child's TCI: tci_cumulative = HASH(tci_cumulative || INPUT_DATA).
        dpe.add_tci_measurement(env, &mut tmp_child, &self.data, child_locality)?;

        // Rotate the parent handle; parent is always retained (as if RETAIN_PARENT_CONTEXT).
        dpe.roll_onetime_use_handle(env, parent_idx)?;

        // Rotate the child handle.
        dpe.roll_onetime_use_handle(env, child_idx)?;

        // Commit the updated child TCI, preserving the newly rotated handle.
        env.state().contexts[child_idx] = Context {
            handle: env.state().contexts[child_idx].handle,
            ..tmp_child
        };

        *response = UpdateContextMeasurementResp {
            resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
            new_context_handle: env.state().contexts[child_idx].handle,
            new_parent_context_handle: env.state().contexts[parent_idx].handle,
        };
        Ok(size_of_val(response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpe_instance::tests::DPE_PROFILE;
    use crate::{
        commands::{
            rotate_context::{RotateCtxCmd, RotateCtxFlags},
            DeriveContextCmd, DeriveContextFlags,
        },
        context::ContextHandle,
        dpe_instance::{tests::TEST_LOCALITIES, DpeInstance},
        response::{DpeErrorCode, Response},
        support::Support,
        test_env, DpeFlags, State, TCI_SIZE,
    };
    use caliptra_cfi_lib::CfiCounter;

    /// Helper: create a default root context and derive a non-default child with the given tci_type.
    /// Returns (parent_handle, child_handle) after rotating the parent to non-default.
    fn setup_parent_and_child(
        dpe: &mut DpeInstance,
        env: &mut impl crate::dpe_instance::DpeEnv,
        tci_type: u32,
    ) -> (ContextHandle, ContextHandle) {
        // Rotate default handle to a non-default handle so we can use RetainParentContext.
        let parent_handle = match (RotateCtxCmd {
            handle: ContextHandle::default(),
            flags: RotateCtxFlags::empty(),
        })
        .execute(dpe, env, TEST_LOCALITIES[0])
        .unwrap()
        {
            Response::RotateCtx(resp) => resp.handle,
            _ => panic!("unexpected response"),
        };
        // Derive a child, retaining the parent so both handles are live.
        // DeriveContext with RETAIN_PARENT_CONTEXT rotates the parent handle;
        // capture the new parent handle from resp.parent_handle.
        let resp = match (DeriveContextCmd {
            handle: parent_handle,
            flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT | DeriveContextFlags::INPUT_ALLOW_X509,
            tci_type,
            ..Default::default()
        })
        .execute(dpe, env, TEST_LOCALITIES[0])
        .unwrap()
        {
            Response::DeriveContext(resp) => resp,
            _ => panic!("unexpected response"),
        };
        (resp.parent_handle, resp.handle)
    }

    #[test]
    fn test_update_context_measurement_success() {
        CfiCounter::reset_for_test();
        let mut state = State::new(
            Support::AUTO_INIT
                | Support::RETAIN_PARENT_CONTEXT
                | Support::ROTATE_CONTEXT
                | Support::X509,
            DpeFlags::empty(),
        );
        test_env!(env, &mut state);
        let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

        let (parent_handle, child_handle) = setup_parent_and_child(&mut dpe, &mut env, 1);

        let child_idx = env
            .state
            .get_active_context_pos(&child_handle, TEST_LOCALITIES[0])
            .unwrap();
        let tci_before = env.state.contexts[child_idx].tci.tci_cumulative;

        let resp = match (UpdateContextMeasurementCmd {
            parent_handle,
            data: TciMeasurement([0xab; TCI_SIZE]),
            reserved: 0,
            tci_type: 1,
            reserved_svn: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap())
        {
            Response::UpdateContextMeasurement(resp) => resp,
            _ => panic!("unexpected response"),
        };

        // Handles must have been rotated.
        assert_ne!(resp.new_context_handle, child_handle);
        assert_ne!(resp.new_parent_context_handle, parent_handle);

        // TCI cumulative must have changed.
        let new_child_idx = env
            .state
            .get_active_context_pos(&resp.new_context_handle, TEST_LOCALITIES[0])
            .unwrap();
        assert_ne!(
            env.state.contexts[new_child_idx].tci.tci_cumulative,
            tci_before
        );
    }

    #[test]
    fn test_default_parent_handle_rejected() {
        CfiCounter::reset_for_test();
        let mut state = State::new(Support::AUTO_INIT, DpeFlags::empty());
        test_env!(env, &mut state);
        let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            UpdateContextMeasurementCmd {
                parent_handle: ContextHandle::default(),
                data: TciMeasurement([0; TCI_SIZE]),
                reserved: 0,
                tci_type: 0,
                reserved_svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
    }

    #[test]
    fn test_unknown_parent_handle_rejected() {
        CfiCounter::reset_for_test();
        let mut state = State::new(Support::AUTO_INIT, DpeFlags::empty());
        test_env!(env, &mut state);
        let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

        assert_eq!(
            Err(DpeErrorCode::InvalidParentLocality),
            UpdateContextMeasurementCmd {
                parent_handle: ContextHandle([0xde; ContextHandle::SIZE]),
                data: TciMeasurement([0; TCI_SIZE]),
                reserved: 0,
                tci_type: 0,
                reserved_svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
    }

    #[test]
    fn test_unknown_tci_type_rejected() {
        CfiCounter::reset_for_test();
        let mut state = State::new(
            Support::AUTO_INIT
                | Support::RETAIN_PARENT_CONTEXT
                | Support::ROTATE_CONTEXT
                | Support::X509,
            DpeFlags::empty(),
        );
        test_env!(env, &mut state);
        let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

        let (parent_handle, _child_handle) = setup_parent_and_child(&mut dpe, &mut env, 1);

        // tci_type=99 does not match any child.
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            UpdateContextMeasurementCmd {
                parent_handle,
                data: TciMeasurement([0; TCI_SIZE]),
                reserved: 0,
                tci_type: 99,
                reserved_svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
    }

    #[test]
    fn test_reserved_svn_ignored() {
        CfiCounter::reset_for_test();
        let mut state = State::new(
            Support::AUTO_INIT
                | Support::RETAIN_PARENT_CONTEXT
                | Support::ROTATE_CONTEXT
                | Support::X509,
            DpeFlags::empty(),
        );
        test_env!(env, &mut state);
        let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

        let (parent_handle, _child_handle) = setup_parent_and_child(&mut dpe, &mut env, 1);

        // A non-zero reserved_svn must be silently ignored (not rejected).
        assert!(UpdateContextMeasurementCmd {
            parent_handle,
            data: TciMeasurement([0; TCI_SIZE]),
            reserved: 0,
            tci_type: 1,
            reserved_svn: 0xff,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .is_ok());
    }
}
