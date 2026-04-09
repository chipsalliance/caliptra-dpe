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
    context::Context,
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
/// | 0x18+H    | U32        | svn               | Reserved; This field is currently ignored |
#[repr(C)]
#[derive(Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct UpdateContextMeasurementCmd {
    /// Handle of the parent context. Must not be the default (null) handle.
    pub parent_handle: crate::context::ContextHandle,
    /// New TCI measurement to extend into the child context.
    pub data: TciMeasurement,
    /// Reserved bitfield; must be zero.
    pub reserved: u32,
    /// Identifies the direct child of parent_handle to update (matched by tci_type).
    pub tci_type: u32,
    /// Must be zero. SVN is fixed at context creation via DeriveContext and cannot be
    /// updated by this command. A non-zero value is rejected with InvalidArgument.
    pub svn: u32,
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
        // SVN cannot be updated by this command; it is fixed at context creation.
        if self.svn != 0 {
            return Err(DpeErrorCode::InvalidArgument);
        }

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
            .find(|&idx| env.state().contexts[idx].tci.tci_type == self.tci_type)
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
