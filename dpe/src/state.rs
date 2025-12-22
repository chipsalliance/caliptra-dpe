// Licensed under the Apache-2.0 license.
use crate::{
    context::{ChildToRootIter, Context, ContextHandle, ContextState},
    dpe_instance::flags_iter,
    response::DpeErrorCode,
    support::Support,
    tci::TciNodeData,
    U8Bool, MAX_HANDLES,
};
use bitflags::bitflags;
use caliptra_cfi_lib_git::cfi_launder;
use core::mem::align_of;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};
use zeroize::Zeroize;

#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;

#[repr(C)]
#[derive(Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, Zeroize)]
pub struct DpeFlags(pub u16);

bitflags! {
    impl DpeFlags: u16 {
        /// Mark DICE extensions as "Critical" in certificates.
        const MARK_DICE_EXTENSIONS_CRITICAL = 1u16 << 15;
    }
}

#[repr(C, align(4))]
#[derive(IntoBytes, TryFromBytes, KnownLayout, Immutable, Zeroize)]
pub struct State {
    /// Magic marker indicating the data is a DPE state. This is just a quick sanity check.
    pub marker: u32,
    /// Layout version of this structure. If the layout of this structure changes, Self::VERSION
    /// must be updated.
    pub version: u32,
    pub contexts: [Context; MAX_HANDLES],
    pub support: Support,
    pub flags: DpeFlags,
    /// Can only successfully execute the initialize context command for non-simulation (i.e.
    /// `InitializeContext(simulation=false)`) once per reset cycle.
    pub has_initialized: U8Bool,
    // unused buffer added to be word aligned and remove padding
    pub reserved: [u8; 1],
}
const _: () = assert!(align_of::<State>() == 4);

impl Default for State {
    fn default() -> Self {
        const CONTEXT_INITIALIZER: Context = Context::new();
        State {
            marker: Self::MAGIC,
            version: Self::VERSION,
            contexts: [CONTEXT_INITIALIZER; MAX_HANDLES],
            support: Support::default(),
            flags: DpeFlags::empty(),
            has_initialized: false.into(),
            reserved: [0; 1],
        }
    }
}

impl State {
    pub const MAGIC: u32 = u32::from_be_bytes(*b"DPES");
    pub const VERSION: u32 = 1;

    pub fn new(support: Support, flags: DpeFlags) -> Self {
        let updated_support = support.preprocess_support();
        const CONTEXT_INITIALIZER: Context = Context::new();
        State {
            marker: Self::MAGIC,
            version: Self::VERSION,
            contexts: [CONTEXT_INITIALIZER; MAX_HANDLES],
            support: updated_support,
            flags,
            has_initialized: false.into(),
            reserved: [0; 1],
        }
    }

    pub fn has_initialized(&self) -> bool {
        self.has_initialized.get()
    }

    /// Finds the index of the context having `handle` in `locality`
    /// Inlined so the callsite optimizer knows that idx < self.contexts.len()
    /// and won't insert possible call to panic.
    ///
    /// # Arguments
    ///
    /// * `handle` - handle to search
    /// * `locality` - locality to search
    #[inline(always)]
    pub fn get_active_context_pos(
        &self,
        handle: &ContextHandle,
        locality: u32,
    ) -> Result<usize, DpeErrorCode> {
        let idx = self.get_active_context_pos_internal(handle, locality)?;
        if idx >= self.contexts.len() {
            return Err(DpeErrorCode::InternalError);
        }
        Ok(idx)
    }

    fn get_active_context_pos_internal(
        &self,
        handle: &ContextHandle,
        locality: u32,
    ) -> Result<usize, DpeErrorCode> {
        // find all active contexts whose localities match the locality parameter
        let mut valid_localities = self
            .contexts
            .iter()
            .enumerate()
            .filter(|(_, context)| {
                context.state == ContextState::Active && context.locality == locality
            })
            .peekable();
        if valid_localities.peek().is_none() {
            return Err(DpeErrorCode::InvalidLocality);
        }

        // filter down the contexts with valid localities based on their context handle matching the input context handle
        // the locality and handle filters are separated so that we can return InvalidHandle or InvalidLocality upon getting no valid contexts accordingly
        let mut valid_handles_and_localities = valid_localities
            .filter(|(_, context)| context.handle.equals(handle))
            .peekable();
        if valid_handles_and_localities.peek().is_none() {
            return Err(DpeErrorCode::InvalidHandle);
        }
        let (i, _) = valid_handles_and_localities
            .find(|(_, context)| {
                context.state == ContextState::Active
                    && context.handle.equals(handle)
                    && context.locality == locality
            })
            .ok_or(DpeErrorCode::InternalError)?;
        Ok(i)
    }

    pub(crate) fn get_next_inactive_context_pos(&self) -> Option<usize> {
        self.contexts
            .iter()
            .position(|context| context.state == ContextState::Inactive)
    }

    /// Recursive function that will return all of `context`'s descendants
    ///
    /// # Arguments
    ///
    /// * `context` - context to get descendants for
    ///
    /// Returns a u32 representing a bitmap of the node indices.
    pub(crate) fn get_descendants(&self, context: &Context) -> Result<u32, DpeErrorCode> {
        if context.state == ContextState::Inactive {
            return Err(DpeErrorCode::InvalidHandle);
        }

        let mut descendants = context.children;
        for idx in flags_iter(context.children, MAX_HANDLES) {
            if idx >= self.contexts.len() {
                return Err(DpeErrorCode::InternalError);
            }
            descendants |= cfi_launder(self.get_descendants(&self.contexts[idx])?);
        }
        Ok(descendants)
    }

    /// Get the TCI nodes from the context at `start_idx` to the root node following parent
    /// links. These are the nodes that should contribute to CDI and key
    /// derivation for the context at `start_idx`.
    ///
    /// # Arguments
    ///
    /// * `start_idx` - Index into context array
    /// * `nodes` - Array to write TCI nodes to
    ///
    /// Returns the number of TCIs written to `nodes`
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub(crate) fn get_tcb_nodes(
        &self,
        start_idx: usize,
        nodes: &mut [TciNodeData],
    ) -> Result<usize, DpeErrorCode> {
        let mut out_idx = 0;

        for status in ChildToRootIter::new(start_idx, &self.contexts) {
            let curr = status?;
            if out_idx >= nodes.len() {
                return Err(DpeErrorCode::InternalError);
            }

            nodes[out_idx] = curr.tci;
            out_idx += 1;
        }

        if out_idx > nodes.len() {
            return Err(DpeErrorCode::InternalError);
        }
        nodes[..out_idx].reverse();

        Ok(out_idx)
    }

    /// Count number of contexts satisfying some predicate
    ///
    /// # Arguments
    ///
    /// * `context_pred` - A predicate on a context used to determine contexts to count
    pub fn count_contexts(&self, f: impl Fn(&Context) -> bool) -> Result<usize, DpeErrorCode> {
        Ok(self.contexts.iter().filter(|context| f(context)).count())
    }
}

#[cfg(test)]
mod tests {
    use caliptra_cfi_lib_git::CfiCounter;
    use platform::default::AUTO_INIT_LOCALITY;

    use crate::dpe_instance::tests::SIMULATION_HANDLE;

    use super::*;

    #[test]
    fn test_get_active_context_index() {
        CfiCounter::reset_for_test();
        let mut state = State::default();
        let expected_index = 7;
        state.contexts[expected_index].handle = SIMULATION_HANDLE;

        let locality = AUTO_INIT_LOCALITY;
        // Has not been activated.
        assert!(state
            .get_active_context_pos(&SIMULATION_HANDLE, locality)
            .is_err());

        // Shouldn't be able to find it if it is retired either.
        state.contexts[expected_index].state = ContextState::Retired;
        assert!(state
            .get_active_context_pos(&SIMULATION_HANDLE, locality)
            .is_err());

        // Mark it active, but check the wrong locality.
        let locality = 2;
        state.contexts[expected_index].state = ContextState::Active;
        assert!(state
            .get_active_context_pos(&SIMULATION_HANDLE, locality)
            .is_err());

        // Should find it now.
        state.contexts[expected_index].locality = locality;
        let idx = state
            .get_active_context_pos(&SIMULATION_HANDLE, locality)
            .unwrap();
        assert_eq!(expected_index, idx);
    }

    #[test]
    fn test_get_descendants() {
        CfiCounter::reset_for_test();
        let mut state = State::default();
        let root = 7;
        let child_1 = 3;
        let child_1_1 = 0;
        let child_1_2 = MAX_HANDLES - 1;
        let child_1_2_1 = 1;
        let child_1_3 = MAX_HANDLES - 2;

        // Root isn't active.
        assert_eq!(
            state.get_descendants(&state.contexts[root]),
            Err(DpeErrorCode::InvalidHandle)
        );

        // No children.
        state.contexts[root].state = ContextState::Active;
        assert_eq!(state.get_descendants(&state.contexts[root]).unwrap(), 0);

        // Child not active.
        state.contexts[root].children = 1 << child_1;
        assert_eq!(
            state.get_descendants(&state.contexts[root]),
            Err(DpeErrorCode::InvalidHandle)
        );

        // One child.
        state.contexts[child_1].state = ContextState::Active;
        let mut children = state.contexts[root].children;
        assert_eq!(
            children,
            state.get_descendants(&state.contexts[root]).unwrap()
        );

        // Add grandchildren.
        state.contexts[child_1_1].state = ContextState::Active;
        state.contexts[child_1_2].state = ContextState::Active;
        state.contexts[child_1_3].state = ContextState::Active;
        state.contexts[child_1].children = (1 << child_1_1) | (1 << child_1_2) | (1 << child_1_3);
        children |= state.contexts[child_1].children;
        assert_eq!(
            children,
            state.get_descendants(&state.contexts[root]).unwrap()
        );

        // Add great-grandchildren.
        state.contexts[child_1_2_1].state = ContextState::Active;
        state.contexts[child_1_2].children = 1 << child_1_2_1;
        children |= state.contexts[child_1_2].children;
        assert_eq!(
            state.contexts[child_1_2].children,
            state.get_descendants(&state.contexts[child_1_2]).unwrap()
        );
        assert_eq!(
            children,
            state.get_descendants(&state.contexts[root]).unwrap()
        );
    }
}
