// Licensed under the Apache-2.0 license.
use crate::{
    context::{ChildToRootIter, Children, Context, ContextHandle, ContextState},
    response::DpeErrorCode,
    support::Support,
    tci::TciNodeData,
    OperationHandle, U8Bool, HASH_SIZE, MAX_HANDLES,
};
use bitflags::bitflags;
use core::mem::align_of;
use crypto::Digest;
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
#[derive(
    Debug, IntoBytes, TryFromBytes, KnownLayout, Immutable, Zeroize, Clone, Copy, PartialEq, Eq,
)]
pub struct MultipartOperationState {
    pub handle: OperationHandle,
    pub digest: [u8; HASH_SIZE],
    pub offset: u32,
}

impl Default for MultipartOperationState {
    fn default() -> Self {
        Self {
            handle: OperationHandle::default(),
            digest: [0; HASH_SIZE],
            offset: 0,
        }
    }
}

impl MultipartOperationState {
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    pub fn blank(&self) -> bool {
        self.handle.blank() && self.offset == 0 && self.digest == [0; HASH_SIZE]
    }

    pub fn active(&self) -> bool {
        !self.handle.blank() && self.offset != 0 && self.digest != [0; HASH_SIZE]
    }

    pub fn is_continued_operation(&self, handle: &OperationHandle, digest: &Digest) -> bool {
        &self.handle == handle && self.offset != 0 && self.digest == digest.as_slice()
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
    pub multipart_state: [MultipartOperationState; Self::MAX_MULTIPART_OPERATIONS],
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
            multipart_state: [MultipartOperationState::default(); Self::MAX_MULTIPART_OPERATIONS],
        }
    }
}

impl State {
    pub const MAGIC: u32 = u32::from_be_bytes(*b"DPES");
    pub const VERSION: u32 = 1;
    pub const MAX_MULTIPART_OPERATIONS: usize = 2;

    pub fn new(support: Support, flags: DpeFlags) -> Self {
        let updated_support = support.preprocess_support();
        State {
            support: updated_support,
            flags,
            ..Default::default()
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
    pub(crate) fn get_descendants(&self, context: &Context) -> Result<Children, DpeErrorCode> {
        if context.state == ContextState::Inactive {
            return Err(DpeErrorCode::InvalidHandle);
        }

        let mut descendants = context.children;
        for idx in context.children.iter() {
            if idx >= self.contexts.len() {
                return Err(DpeErrorCode::InternalError);
            }
            descendants.add_children(self.get_descendants(&self.contexts[idx])?);
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
        assert!(state
            .get_descendants(&state.contexts[root])
            .unwrap()
            .is_empty());

        // Child not active.
        state.contexts[root].children = Children::from(1 << child_1);
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
        state.contexts[child_1].children =
            Children::from((1 << child_1_1) | (1 << child_1_2) | (1 << child_1_3));
        children.add_children(state.contexts[child_1].children);
        assert_eq!(
            children,
            state.get_descendants(&state.contexts[root]).unwrap()
        );

        // Add great-grandchildren.
        state.contexts[child_1_2_1].state = ContextState::Active;
        state.contexts[child_1_2].children = Children::from(1 << child_1_2_1);
        children.add_children(state.contexts[child_1_2].children);
        assert_eq!(
            state.contexts[child_1_2].children,
            state.get_descendants(&state.contexts[child_1_2]).unwrap()
        );
        assert_eq!(
            children,
            state.get_descendants(&state.contexts[root]).unwrap()
        );
    }

    #[test]
    fn test_op_handle_wrong_handle() {
        // non-zero to make it look active
        let handle = OperationHandle([1; OperationHandle::SIZE]);
        let digest = [1; HASH_SIZE];
        let offset = 1;
        let state = MultipartOperationState {
            handle,
            digest,
            offset,
        };

        let wrong_handle = OperationHandle::default();
        assert!(!state.is_continued_operation(&wrong_handle, &digest.into()))
    }

    #[test]
    fn test_op_handle_wrong_digest() {
        let handle = OperationHandle::default();

        let digest = [1; HASH_SIZE];
        let offset = 1;
        let state = MultipartOperationState {
            handle,
            digest,
            offset,
        };

        let wrong_digest = [2; HASH_SIZE];
        assert!(!state.is_continued_operation(&handle, &wrong_digest.into()))
    }

    #[test]
    fn test_multiop_wrong_offset() {
        let handle = OperationHandle::default();
        let digest = [1; HASH_SIZE];
        let state = MultipartOperationState {
            handle,
            digest,
            offset: 0, // The offset should never be zero for a valid active state.
        };

        assert!(!state.is_continued_operation(&handle, &digest.into()))
    }

    #[test]
    fn test_multiop_valid_active() {
        let handle = OperationHandle::default();
        let digest = [1; HASH_SIZE];
        let offset = 1;

        let state = MultipartOperationState {
            handle,
            digest,
            offset,
        };

        assert!(state.is_continued_operation(&handle, &digest.into()))
    }

    #[test]
    fn test_multiop_clear() {
        let handle = OperationHandle::default();
        let digest = [1; HASH_SIZE];
        let offset = 1;

        let mut state = MultipartOperationState {
            handle,
            digest,
            offset,
        };
        assert_ne!(state, MultipartOperationState::default());

        // Clear the state and make sure it becomes the default state.
        state.clear();
        assert_eq!(state, MultipartOperationState::default())
    }

    #[test]
    fn test_new_has_correct_defaults() {
        let state = State::new(Support::default(), DpeFlags::empty());
        assert_eq!(state.marker, State::MAGIC);
        assert_eq!(state.version, State::VERSION);
        assert_eq!(state.has_initialized.get(), false);
        assert_eq!(state.flags, DpeFlags::empty());
        assert_eq!(state.reserved, [0; 1]);
        assert_eq!(
            state.multipart_state,
            [MultipartOperationState::default(); 2]
        );
        assert_eq!(state.contexts, [Context::new(); MAX_HANDLES]);
    }
}
