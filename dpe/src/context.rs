// Licensed under the Apache-2.0 license.
use crate::{response::DpeErrorCode, tci::TciNodeData, MAX_HANDLES};
use core::mem::size_of;
use crypto::Crypto;

#[repr(C, align(4))]
pub(crate) struct Context<C: Crypto> {
    pub handle: ContextHandle,
    pub tci: TciNodeData,
    /// Bitmap of the node indices that are children of this node
    pub children: u32,
    /// Index in DPE instance of the parent context. 0xFF if this node is the root
    pub parent_idx: u8,
    pub context_type: ContextType,
    pub state: ContextState,
    /// Which hardware locality owns the context.
    pub locality: u32,
    /// Whether a tag has been assigned to the context.
    pub has_tag: bool,
    /// Optional tag assigned to the context.
    pub tag: u32,
    /// Private key which is cached only in non-deterministic key derivation mode
    pub cached_priv_key: Option<C::PrivKey>,
    /// Whether we should hash internal input info consisting of major_version, minor_version, vendor_id, vendor_sku, max_tci_nodes, flags, and DPE_PROFILE when deriving the CDI
    pub uses_internal_input_info: bool,
    /// Whether we should hash internal dice info consisting of the certificate chain when deriving the CDI
    pub uses_internal_input_dice: bool,
}

impl<C: Crypto> Context<C> {
    pub const ROOT_INDEX: u8 = 0xff;

    pub const fn new() -> Context<C> {
        Context {
            handle: ContextHandle::default(),
            tci: TciNodeData::new(),
            children: 0,
            parent_idx: Self::ROOT_INDEX,
            context_type: ContextType::Normal,
            state: ContextState::Inactive,
            locality: 0,
            has_tag: false,
            tag: 0,
            cached_priv_key: None,
            uses_internal_input_info: false,
            uses_internal_input_dice: false,
        }
    }

    /// Resets all values to a freshly initialized state.
    ///
    /// # Arguments
    ///
    /// * `context_type` - Context type this will become.
    /// * `locality` - Which hardware locality owns the context.
    /// * `handle` - Value that will be used to refer to the context. Random value for simulation
    ///   contexts and 0x0 for the default context.
    pub fn activate(&mut self, args: &ActiveContextArgs) {
        self.handle = *args.handle;
        self.tci = TciNodeData::new();
        self.tci.tci_type = args.tci_type;
        self.children = 0;
        self.parent_idx = args.parent_idx;
        self.context_type = args.context_type;
        self.state = ContextState::Active;
        self.locality = args.locality;
    }

    /// Destroy this context so it can no longer be used until it is re-initialized. The default
    /// context cannot be re-initialized.
    pub fn destroy(&mut self) {
        self.tci = TciNodeData::new();
        self.has_tag = false;
        self.tag = 0;
        self.state = ContextState::Inactive;
        self.cached_priv_key = None;
        self.uses_internal_input_info = false;
        self.uses_internal_input_dice = false;
    }

    /// Add a child to list of children in the context.
    pub fn add_child(&mut self, idx: usize) -> Result<(), DpeErrorCode> {
        if idx >= MAX_HANDLES {
            return Err(DpeErrorCode::InternalError);
        }
        self.children |= 1 << idx;
        Ok(())
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, zerocopy::AsBytes, zerocopy::FromBytes)]
pub struct ContextHandle(pub [u8; ContextHandle::SIZE]);

impl ContextHandle {
    pub const SIZE: usize = 16;
    const DEFAULT: [u8; Self::SIZE] = [0; Self::SIZE];

    /// Returns the default context handle.
    pub const fn default() -> ContextHandle {
        ContextHandle(Self::DEFAULT)
    }

    /// Whether the handle is the default context handle.
    pub fn is_default(&self) -> bool {
        self.0 == Self::DEFAULT
    }

    /// Serializes a handle to the given destination and returns the length copied.
    pub fn serialize(&self, dst: &mut [u8]) -> Result<usize, DpeErrorCode> {
        if dst.len() < size_of::<Self>() {
            return Err(DpeErrorCode::InternalError);
        }

        dst[..ContextHandle::SIZE].copy_from_slice(&self.0);
        Ok(ContextHandle::SIZE)
    }
}

impl TryFrom<&[u8]> for ContextHandle {
    type Error = DpeErrorCode;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < size_of::<ContextHandle>() {
            return Err(DpeErrorCode::InvalidArgument);
        }

        Ok(ContextHandle(raw[0..Self::SIZE].try_into().unwrap()))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ContextState {
    /// Inactive or uninitialized.
    Inactive,
    /// Context is initialized and ready to be used.
    Active,
    /// A child was derived from this context, but it was not retained. This will need to be
    /// destroyed automatically if all of it's children have been destroyed. It is preserved for its
    /// TCI data, but the handle is no longer valid. Because the handle is no longer valid, a client
    /// cannot command it to be destroyed.
    Retired,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum ContextType {
    /// Typical context.
    Normal,
    /// Has limitations on what operations can be done.
    Simulation,
}

pub(crate) struct ActiveContextArgs<'a> {
    pub context_type: ContextType,
    pub locality: u32,
    pub handle: &'a ContextHandle,
    pub tci_type: u32,
    pub parent_idx: u8,
}

pub(crate) struct ChildToRootIter<'a, C: Crypto> {
    idx: usize,
    contexts: &'a [Context<C>],
    done: bool,
    count: usize,
}

impl<C: Crypto> ChildToRootIter<'_, C> {
    /// Create a new iterator that will start at the leaf and go to the root node.
    pub fn new(leaf_idx: usize, contexts: &[Context<C>]) -> ChildToRootIter<C> {
        ChildToRootIter {
            idx: leaf_idx,
            contexts,
            done: false,
            count: 0,
        }
    }
}

impl<'a, C: Crypto> Iterator for ChildToRootIter<'a, C> {
    type Item = Result<&'a Context<C>, DpeErrorCode>;

    fn next(&mut self) -> Option<Result<&'a Context<C>, DpeErrorCode>> {
        if self.done {
            return None;
        }
        if self.count >= MAX_HANDLES {
            self.done = true;
            return Some(Err(DpeErrorCode::MaxTcis));
        }

        let context = &self.contexts[self.idx];

        // Check if context is valid.
        const MAX_IDX: u8 = (MAX_HANDLES - 1) as u8;
        let valid_parent_idx = matches!(context.parent_idx, 0..=MAX_IDX | Context::<C>::ROOT_INDEX);
        if !valid_parent_idx || context.state == ContextState::Inactive {
            self.done = true;
            return Some(Err(DpeErrorCode::InternalError));
        }

        if context.parent_idx == Context::<C>::ROOT_INDEX {
            self.done = true;
        }
        self.idx = context.parent_idx as usize;
        self.count += 1;
        Some(Ok(context))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DpeInstance;
    use crypto::OpensslCrypto;
    use platform::DefaultPlatform;

    #[test]
    fn test_child_to_root_iter() {
        let mut contexts = DpeInstance::<OpensslCrypto, DefaultPlatform>::new_context_handles();
        let root_index = CHAIN_INDICES[0];
        assert_eq!(MAX_HANDLES, CHAIN_INDICES.len());

        // Lets put the context's index in the tag to make it easy to find later.
        contexts[root_index].tag = root_index as u32;
        contexts[root_index].state = ContextState::Retired;

        // Assign all of the children's parents and put their index in the tag.
        for (parent_chain_idx, child_idx) in CHAIN_INDICES.iter().skip(1).enumerate() {
            let parent_idx = CHAIN_INDICES[parent_chain_idx];
            let context = &mut contexts[*child_idx];
            context.parent_idx = parent_idx as u8;
            context.tag = *child_idx as u32;
            context.state = ContextState::Active;
        }

        let mut count = 0;
        let leaf_index = CHAIN_INDICES[CHAIN_INDICES.len() - 1];

        for (answer, status) in CHAIN_INDICES
            .iter()
            .rev()
            .zip(ChildToRootIter::new(leaf_index, &contexts))
        {
            assert_eq!(*answer, status.unwrap().tag as usize);
            count += 1;
        }

        // Check we didn't accidentally skip any.
        assert_eq!(CHAIN_INDICES.len(), count);
    }

    #[test]
    fn test_child_to_root_overflow() {
        let mut contexts = DpeInstance::<OpensslCrypto, DefaultPlatform>::new_context_handles();

        // Create circular relationship.
        contexts[0].parent_idx = 1;
        contexts[0].state = ContextState::Active;
        contexts[1].parent_idx = 0;
        contexts[1].state = ContextState::Active;

        let mut iter = ChildToRootIter::new(0, &contexts);
        for _ in 0..MAX_HANDLES {
            iter.next().unwrap().unwrap();
        }

        assert_eq!(DpeErrorCode::MaxTcis, iter.next().unwrap().err().unwrap());
    }

    #[test]
    fn test_child_to_root_check_parent_and_state() {
        let mut contexts = DpeInstance::<OpensslCrypto, DefaultPlatform>::new_context_handles();
        contexts[0].state = ContextState::Retired;
        contexts[0].parent_idx = MAX_HANDLES as u8;

        // Above upper bound of handles.
        let mut iter = ChildToRootIter::new(0, &contexts);
        assert_eq!(
            DpeErrorCode::InternalError,
            iter.next().unwrap().err().unwrap()
        );

        // Inactive.
        contexts[0].state = ContextState::Inactive;
        contexts[0].parent_idx = 0;
        let mut iter = ChildToRootIter::new(0, &contexts);
        assert_eq!(
            DpeErrorCode::InternalError,
            iter.next().unwrap().err().unwrap()
        );

        // Retired.
        contexts[0].state = ContextState::Retired;
        let mut iter = ChildToRootIter::new(0, &contexts);
        assert!(iter.next().unwrap().is_ok());

        // Active and upper bound of handles.
        contexts[0].state = ContextState::Active;
        contexts[0].parent_idx = (MAX_HANDLES - 1) as u8;
        let mut iter = ChildToRootIter::new(0, &contexts);
        assert!(iter.next().unwrap().is_ok());

        // Root index.
        contexts[0].parent_idx = Context::<OpensslCrypto>::ROOT_INDEX as u8;
        let mut iter = ChildToRootIter::new(0, &contexts);
        assert!(iter.next().unwrap().is_ok());
    }

    /// This is intended for testing a list of parent to children relationships. These are indices of contexts within a DPE instance.
    ///
    /// The context's parent context index is the previous value.
    ///
    /// So `dpe.contexts[2]` is the parent of `dpe.contexts[4]` which is the parent of
    /// `dpe.contexts[1]` etc.
    const CHAIN_INDICES: [usize; MAX_HANDLES] = [
        2,
        4,
        1,
        13,
        MAX_HANDLES - 1,
        3,
        0,
        9,
        5,
        6,
        7,
        8,
        10,
        11,
        12,
        14,
        15,
        16,
        17,
        18,
        19,
        20,
        21,
        22,
    ];
}
