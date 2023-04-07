// Licensed under the Apache-2.0 license.
use crate::{response::DpeErrorCode, tci::TciNodeData, MAX_HANDLES};
use core::mem::size_of;

#[repr(C, align(4))]
pub(crate) struct Context {
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
}

impl Context {
    pub const ROOT_INDEX: u8 = 0xff;

    pub const fn new() -> Context {
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
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(zerocopy::AsBytes, zerocopy::FromBytes))]
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

pub(crate) struct ChildToRootIter<'a> {
    idx: usize,
    contexts: &'a [Context],
    done: bool,
}

impl ChildToRootIter<'_> {
    /// Create a new iterator that will start at the leaf and go to the root node.
    pub fn new(leaf_idx: usize, contexts: &[Context]) -> Result<ChildToRootIter, DpeErrorCode> {
        Ok(ChildToRootIter {
            idx: leaf_idx,
            contexts,
            done: false,
        })
    }
}

impl<'a> Iterator for ChildToRootIter<'a> {
    type Item = &'a Context;

    fn next(&mut self) -> Option<&'a Context> {
        if self.done {
            return None;
        }

        let context = &self.contexts[self.idx];
        if context.parent_idx == Context::ROOT_INDEX {
            self.done = true;
        }
        self.idx = context.parent_idx as usize;
        Some(context)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_child_to_root_iter() {
        const INITIALIZER_CONTEXT: Context = Context::new();
        let mut contexts = [INITIALIZER_CONTEXT; MAX_HANDLES];
        let chain_indeces = [2, 4, 1, 13, MAX_HANDLES - 1, 3, 0, 9];
        let root_index = chain_indeces[0];

        // Lets put the context's index in the tag to make it easy to find later.
        contexts[root_index].tag = root_index as u32;

        // Assign all of the childrens' parents and put their index in the tag.
        for (parent_chain_idx, child_idx) in chain_indeces.iter().skip(1).enumerate() {
            let parent_idx = chain_indeces[parent_chain_idx];
            contexts[*child_idx].parent_idx = parent_idx as u8;
            contexts[*child_idx].tag = *child_idx as u32;
        }

        let mut count = 0;
        let leaf_index = chain_indeces[chain_indeces.len() - 1];

        for (answer, context) in chain_indeces
            .iter()
            .rev()
            .zip(ChildToRootIter::new(leaf_index, &contexts).unwrap())
        {
            assert_eq!(*answer, context.tag as usize);
            count += 1;
        }

        // Check we didn't accidentally skip any.
        assert_eq!(chain_indeces.len(), count);
    }
}
