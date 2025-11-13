// Licensed under the Apache-2.0 license.
use crate::{response::DpeErrorCode, tci::TciNodeData, U8Bool, MAX_HANDLES};
use constant_time_eq::constant_time_eq_16;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};
use zeroize::Zeroize;

#[cfg(test)]
use std::fmt::Debug;

#[repr(C, align(4))]
#[derive(IntoBytes, TryFromBytes, KnownLayout, Immutable, Copy, Clone, PartialEq, Eq, Zeroize)]
pub struct Context {
    pub handle: ContextHandle,
    pub tci: TciNodeData,
    /// Bitmap of the node indices that are children of this node
    pub children: u32,

    /// Which hardware locality owns the context.
    pub locality: u32,

    /// Index in DPE instance of the parent context. 0xFF if this node is the root
    pub parent_idx: u8,

    /// The type of this context
    pub context_type: ContextType,

    /// The current state of this context
    pub state: ContextState,
    /// Whether we should hash internal input info consisting of major_version, minor_version, vendor_id, vendor_sku, max_tci_nodes, flags, and profile when deriving the CDI
    pub uses_internal_input_info: U8Bool,
    /// Whether we should hash internal dice info consisting of the certificate chain when deriving the CDI
    pub uses_internal_input_dice: U8Bool,
    /// Whether this context can emit certificates in X.509 format
    pub allow_x509: U8Bool,
    /// Whether this context can use the `EXPORT_CDI` feature.
    pub allow_export_cdi: U8Bool,
    pub reserved: [u8; 1],
}

// As long as a `u32` is used for the children bit map the MAX_HANDLES upper bound is 32.
const _: () = assert!(
    MAX_HANDLES <= 32,
    "More than 32 MAX_HANDLES will cause an arithmatic overflow."
);

#[cfg(test)]
impl Debug for Context {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Context")
            .field("handle", &self.handle.0.get(0..2).unwrap())
            .field("state", &self.state)
            .field("chilren", &self.children)
            .field("locality", &self.locality)
            .field("parent_idx", &self.parent_idx)
            .finish()
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
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
            uses_internal_input_info: U8Bool::new(false),
            uses_internal_input_dice: U8Bool::new(false),
            allow_x509: U8Bool::new(false),
            // The root context needs to
            // allow_export_cdi or it is never enabled.
            allow_export_cdi: U8Bool::new(true),
            reserved: [0; 1],
        }
    }

    pub fn uses_internal_input_info(&self) -> bool {
        self.uses_internal_input_info.get()
    }
    pub fn uses_internal_input_dice(&self) -> bool {
        self.uses_internal_input_dice.get()
    }
    pub fn allow_x509(&self) -> bool {
        self.allow_x509.get()
    }
    pub fn allow_export_cdi(&self) -> bool {
        self.allow_export_cdi.get()
    }

    /// Sets all values to an initialized state according to ActiveContextArgs
    pub fn activate(&mut self, args: &ActiveContextArgs) {
        self.handle = *args.handle;
        self.tci = TciNodeData::new();
        self.tci.tci_type = args.tci_type;
        self.tci.locality = args.locality;
        self.tci.svn = args.svn;
        self.children = 0;
        self.parent_idx = args.parent_idx;
        self.context_type = args.context_type;
        self.state = ContextState::Active;
        self.locality = args.locality;
        self.allow_x509 = args.allow_x509.into();
        self.uses_internal_input_info = args.uses_internal_input_info.into();
        self.uses_internal_input_dice = args.uses_internal_input_dice.into();
        self.allow_export_cdi = args.allow_export_cdi.into();
    }

    /// Destroy this context so it can no longer be used until it is re-initialized. The default
    /// context cannot be re-initialized.
    pub fn destroy(&mut self) {
        self.tci = TciNodeData::new();
        self.state = ContextState::Inactive;
        self.uses_internal_input_info = false.into();
        self.uses_internal_input_dice = false.into();
        self.allow_x509 = false.into();
        self.parent_idx = Self::ROOT_INDEX;
        self.locality = 0;
        self.children = 0;
        self.handle = ContextHandle::new_invalid();
    }

    /// Return the list of children of the context with idx added.
    /// This function does not mutate DPE state.
    pub fn add_child(&mut self, idx: usize) -> Result<u32, DpeErrorCode> {
        if idx >= MAX_HANDLES {
            return Err(DpeErrorCode::InternalError);
        }
        let children_with_idx = self.children | (1 << idx);
        Ok(children_with_idx)
    }

    /// Check if `Self` has any children.
    pub fn has_children(&self) -> bool {
        self.children != 0
    }
}

#[repr(C)]
#[derive(
    Debug, PartialEq, Eq, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout, Zeroize,
)]
pub struct ContextHandle(pub [u8; ContextHandle::SIZE]);

impl ContextHandle {
    pub const SIZE: usize = 16;
    const DEFAULT: ContextHandle = ContextHandle([0; Self::SIZE]);
    const INVALID: ContextHandle = ContextHandle([0xFF; Self::SIZE]);

    /// Returns the default context handle.
    pub const fn default() -> ContextHandle {
        Self::DEFAULT
    }

    /// Returns an invalid context handle.
    pub const fn new_invalid() -> ContextHandle {
        Self::INVALID
    }

    /// Whether the handle is the default context handle.
    pub fn is_default(&self) -> bool {
        self.equals(&Self::DEFAULT)
    }

    #[inline(never)]
    pub fn equals(&self, other: &ContextHandle) -> bool {
        constant_time_eq_16(&self.0, &other.0)
    }
}

#[derive(Debug, PartialEq, Eq, IntoBytes, TryFromBytes, KnownLayout, Immutable, Copy, Clone, Zeroize)]
#[repr(u8, align(1))]
#[rustfmt::skip]
pub enum ContextState {
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

#[derive(Debug, PartialEq, Eq, Clone, Copy, IntoBytes, TryFromBytes, KnownLayout, Immutable, Zeroize)]
#[repr(u8, align(1))]
#[rustfmt::skip]
pub enum ContextType {
    /// Typical context.
    Normal,
    /// Has limitations on what operations can be done.
    Simulation,
}

pub struct ActiveContextArgs<'a> {
    pub context_type: ContextType,
    pub locality: u32,
    pub handle: &'a ContextHandle,
    pub tci_type: u32,
    pub parent_idx: u8,
    pub allow_x509: bool,
    pub uses_internal_input_info: bool,
    pub uses_internal_input_dice: bool,
    pub allow_export_cdi: bool,
    pub svn: u32,
}

pub(crate) struct ChildToRootIter<'a> {
    idx: usize,
    contexts: &'a [Context],
    done: bool,
    count: usize,
}

impl ChildToRootIter<'_> {
    /// Create a new iterator that will start at the leaf and go to the root node.
    pub fn new(leaf_idx: usize, contexts: &[Context]) -> ChildToRootIter {
        ChildToRootIter {
            idx: leaf_idx,
            contexts,
            done: false,
            count: 0,
        }
    }
}

impl<'a> Iterator for ChildToRootIter<'a> {
    type Item = Result<&'a Context, DpeErrorCode>;

    fn next(&mut self) -> Option<Result<&'a Context, DpeErrorCode>> {
        if self.done {
            return None;
        }
        if self.count >= MAX_HANDLES {
            self.done = true;
            return Some(Err(DpeErrorCode::MaxTcis));
        }
        if self.idx >= self.contexts.len() {
            self.done = true;
            return Some(Err(DpeErrorCode::InternalError));
        }

        let context = &self.contexts[self.idx];

        // Check if context is valid.
        const MAX_IDX: u8 = (MAX_HANDLES - 1) as u8;
        let valid_parent_idx = matches!(context.parent_idx, 0..=MAX_IDX | Context::ROOT_INDEX);
        if !valid_parent_idx || context.state == ContextState::Inactive {
            self.done = true;
            return Some(Err(DpeErrorCode::InvalidHandle));
        }

        if context.parent_idx == Context::ROOT_INDEX {
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
    use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

    const CONTEXT_INITIALIZER: Context = Context::new();

    #[test]
    fn test_child_to_root_iter() {
        let mut contexts = [CONTEXT_INITIALIZER; MAX_HANDLES];
        let chain_indices = get_chain_indices();
        let root_index = chain_indices[0];
        assert_eq!(MAX_HANDLES, chain_indices.len());

        // Put the context's index in the handle to make it easy to find later.
        contexts[root_index].handle = ContextHandle([root_index as u8; ContextHandle::SIZE]);
        contexts[root_index].state = ContextState::Retired;

        // Assign all of the children's parents and put their index in the handle.
        for (parent_chain_idx, child_idx) in chain_indices.iter().skip(1).enumerate() {
            let parent_idx = chain_indices[parent_chain_idx];
            let context = &mut contexts[*child_idx];
            context.parent_idx = parent_idx as u8;
            context.handle = ContextHandle([*child_idx as u8; ContextHandle::SIZE]);
            context.state = ContextState::Active;
        }

        let mut count = 0;
        let leaf_index = chain_indices[chain_indices.len() - 1];

        for (answer, status) in chain_indices
            .iter()
            .rev()
            .zip(ChildToRootIter::new(leaf_index, &contexts))
        {
            assert_eq!(
                [*answer as u8; ContextHandle::SIZE],
                status.unwrap().handle.0
            );
            count += 1;
        }

        // Check we didn't accidentally skip any.
        assert_eq!(chain_indices.len(), count);
    }

    #[test]
    fn test_child_to_root_overflow() {
        let mut contexts = [CONTEXT_INITIALIZER; MAX_HANDLES];

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
    fn test_add_child_overflow() {
        let mut contexts = [CONTEXT_INITIALIZER; MAX_HANDLES];
        assert_eq!(
            contexts[0].add_child(MAX_HANDLES + 1),
            Err(DpeErrorCode::InternalError)
        );
    }

    #[test]
    fn test_child_to_root_check_parent_and_state() {
        let mut contexts = [CONTEXT_INITIALIZER; MAX_HANDLES];
        contexts[0].state = ContextState::Retired;
        contexts[0].parent_idx = MAX_HANDLES as u8;

        // Above upper bound of handles.
        let mut iter = ChildToRootIter::new(0, &contexts);
        assert_eq!(
            DpeErrorCode::InvalidHandle,
            iter.next().unwrap().err().unwrap()
        );

        // Inactive.
        contexts[0].state = ContextState::Inactive;
        contexts[0].parent_idx = 0;
        let mut iter = ChildToRootIter::new(0, &contexts);
        assert_eq!(
            DpeErrorCode::InvalidHandle,
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
        contexts[0].parent_idx = Context::ROOT_INDEX;
        let mut iter = ChildToRootIter::new(0, &contexts);
        assert!(iter.next().unwrap().is_ok());
    }

    #[test]
    fn test_child_to_root_iter_infinite_loop() {
        let contexts = [CONTEXT_INITIALIZER; MAX_HANDLES];
        let mut i = 0;
        for _ in ChildToRootIter::new(30, &contexts) {
            i += 1;
            // fail test if we iterate over all nodes without terminating, meaning we are in infinite loop
            if i > MAX_HANDLES {
                panic!("child to root iterator loops without termination")
            }
        }
    }

    /// This is intended for testing a list of parent to children relationships. These are indices of contexts within a DPE instance.
    ///
    /// The context's parent context index is the previous value.
    ///
    /// So `dpe.contexts[chain_indices[0]]` is the parent of `dpe.contexts[chain_indices[1]]` which is the parent of
    /// `dpe.contexts[chain_indices[2]]` etc. The chain_indices vector is a random permutation of numbers in [0, MAX_HANDLES).
    fn get_chain_indices() -> Vec<usize> {
        let mut chain_indices: Vec<usize> = (0..MAX_HANDLES).collect();
        const SEED: [u8; 32] = [0xFF; 32];
        let mut seeded_rng = StdRng::from_seed(SEED);

        chain_indices.shuffle(&mut seeded_rng);
        println!("{:?}", chain_indices);
        chain_indices
    }
}
