// Licensed under the Apache-2.0 license.
use crate::{response::DpeErrorCode, tci::TciNodeData, U8Bool, MAX_HANDLES};
use constant_time_eq::constant_time_eq;
use zerocopy::{AsBytes, FromBytes};
use zeroize::Zeroize;

#[repr(C, align(4))]
#[derive(AsBytes, FromBytes, Copy, Clone, PartialEq, Eq, Zeroize)]
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
    /// Whether we should hash internal input info consisting of major_version, minor_version, vendor_id, vendor_sku, max_tci_nodes, flags, and DPE_PROFILE when deriving the CDI
    pub uses_internal_input_info: U8Bool,
    /// Whether we should hash internal dice info consisting of the certificate chain when deriving the CDI
    pub uses_internal_input_dice: U8Bool,
    /// Whether this context can emit certificates with IsCA = True
    pub allow_ca: U8Bool,
    /// Whether this context can emit certificates in X.509 format
    pub allow_x509: U8Bool,
    pub reserved: [u8; 1],
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
            allow_ca: U8Bool::new(false),
            allow_x509: U8Bool::new(false),
            reserved: [0; 1],
        }
    }

    pub fn uses_internal_input_info(&self) -> bool {
        self.uses_internal_input_info.get()
    }
    pub fn uses_internal_input_dice(&self) -> bool {
        self.uses_internal_input_dice.get()
    }
    pub fn allow_ca(&self) -> bool {
        self.allow_ca.get()
    }
    pub fn allow_x509(&self) -> bool {
        self.allow_x509.get()
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
        self.tci.locality = args.locality;
        self.children = 0;
        self.parent_idx = args.parent_idx;
        self.context_type = args.context_type;
        self.state = ContextState::Active;
        self.locality = args.locality;
        self.allow_ca = args.allow_ca.into();
        self.allow_x509 = args.allow_x509.into();
    }

    /// Destroy this context so it can no longer be used until it is re-initialized. The default
    /// context cannot be re-initialized.
    pub fn destroy(&mut self) {
        self.tci = TciNodeData::new();
        self.state = ContextState::Inactive;
        self.uses_internal_input_info = false.into();
        self.uses_internal_input_dice = false.into();
        self.parent_idx = 0xFF;
    }

    /// Return the list of children of the context with idx added.
    /// This function does not mutate DPE state.
    pub fn add_child(&mut self, idx: usize) -> Result<u32, DpeErrorCode> {
        if idx >= MAX_HANDLES {
            return Err(DpeErrorCode::InternalError);
        }
        let children_with_idx = self.children | 1 << idx;
        Ok(children_with_idx)
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, zerocopy::AsBytes, zerocopy::FromBytes, Zeroize)]
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
        constant_time_eq(&self.0, &Self::DEFAULT)
    }
}

#[derive(Debug, PartialEq, Eq, AsBytes, FromBytes, Copy, Clone, Zeroize)]
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
    // These are unused values to allow AsBytes and FromBytes to be able to use the enum.
    _03, _04, _05, _06, _07, _08, _09, _0a, _0b, _0c, _0d, _0e, _0f,
    _10, _11, _12, _13, _14, _15, _16, _17, _18, _19, _1a, _1b, _1c, _1d, _1e, _1f,
    _20, _21, _22, _23, _24, _25, _26, _27, _28, _29, _2a, _2b, _2c, _2d, _2e, _2f,
    _30, _31, _32, _33, _34, _35, _36, _37, _38, _39, _3a, _3b, _3c, _3d, _3e, _3f,
    _40, _41, _42, _43, _44, _45, _46, _47, _48, _49, _4a, _4b, _4c, _4d, _4e, _4f,
    _50, _51, _52, _53, _54, _55, _56, _57, _58, _59, _5a, _5b, _5c, _5d, _5e, _5f,
    _60, _61, _62, _63, _64, _65, _66, _67, _68, _69, _6a, _6b, _6c, _6d, _6e, _6f,
    _70, _71, _72, _73, _74, _75, _76, _77, _78, _79, _7a, _7b, _7c, _7d, _7e, _7f,
    _80, _81, _82, _83, _84, _85, _86, _87, _88, _89, _8a, _8b, _8c, _8d, _8e, _8f,
    _90, _91, _92, _93, _94, _95, _96, _97, _98, _99, _9a, _9b, _9c, _9d, _9e, _9f,
    _A0, _A1, _A2, _A3, _A4, _A5, _A6, _A7, _A8, _A9, _Aa, _Ab, _Ac, _Ad, _Ae, _Af,
    _B0, _B1, _B2, _B3, _B4, _B5, _B6, _B7, _B8, _B9, _Ba, _Bb, _Bc, _Bd, _Be, _Bf,
    _C0, _C1, _C2, _C3, _C4, _C5, _C6, _C7, _C8, _C9, _Ca, _Cb, _Cc, _Cd, _Ce, _Cf,
    _D0, _D1, _D2, _D3, _D4, _D5, _D6, _D7, _D8, _D9, _Da, _Db, _Dc, _Dd, _De, _Df,
    _E0, _E1, _E2, _E3, _E4, _E5, _E6, _E7, _E8, _E9, _Ea, _Eb, _Ec, _Ed, _Ee, _Ef,
    _F0, _F1, _F2, _F3, _F4, _F5, _F6, _F7, _F8, _F9, _Fa, _Fb, _Fc, _Fd, _Fe, _Ff,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, AsBytes, FromBytes, Zeroize)]
#[repr(u8, align(1))]
#[rustfmt::skip]
pub enum ContextType {
    /// Typical context.
    Normal,
    /// Has limitations on what operations can be done.
    Simulation,
    // These are unused values to allow AsBytes and FromBytes to be able to use the enum.
    _02, _03, _04, _05, _06, _07, _08, _09, _0a, _0b, _0c, _0d, _0e, _0f,
    _10, _11, _12, _13, _14, _15, _16, _17, _18, _19, _1a, _1b, _1c, _1d, _1e, _1f,
    _20, _21, _22, _23, _24, _25, _26, _27, _28, _29, _2a, _2b, _2c, _2d, _2e, _2f,
    _30, _31, _32, _33, _34, _35, _36, _37, _38, _39, _3a, _3b, _3c, _3d, _3e, _3f,
    _40, _41, _42, _43, _44, _45, _46, _47, _48, _49, _4a, _4b, _4c, _4d, _4e, _4f,
    _50, _51, _52, _53, _54, _55, _56, _57, _58, _59, _5a, _5b, _5c, _5d, _5e, _5f,
    _60, _61, _62, _63, _64, _65, _66, _67, _68, _69, _6a, _6b, _6c, _6d, _6e, _6f,
    _70, _71, _72, _73, _74, _75, _76, _77, _78, _79, _7a, _7b, _7c, _7d, _7e, _7f,
    _80, _81, _82, _83, _84, _85, _86, _87, _88, _89, _8a, _8b, _8c, _8d, _8e, _8f,
    _90, _91, _92, _93, _94, _95, _96, _97, _98, _99, _9a, _9b, _9c, _9d, _9e, _9f,
    _A0, _A1, _A2, _A3, _A4, _A5, _A6, _A7, _A8, _A9, _Aa, _Ab, _Ac, _Ad, _Ae, _Af,
    _B0, _B1, _B2, _B3, _B4, _B5, _B6, _B7, _B8, _B9, _Ba, _Bb, _Bc, _Bd, _Be, _Bf,
    _C0, _C1, _C2, _C3, _C4, _C5, _C6, _C7, _C8, _C9, _Ca, _Cb, _Cc, _Cd, _Ce, _Cf,
    _D0, _D1, _D2, _D3, _D4, _D5, _D6, _D7, _D8, _D9, _Da, _Db, _Dc, _Dd, _De, _Df,
    _E0, _E1, _E2, _E3, _E4, _E5, _E6, _E7, _E8, _E9, _Ea, _Eb, _Ec, _Ed, _Ee, _Ef,
    _F0, _F1, _F2, _F3, _F4, _F5, _F6, _F7, _F8, _F9, _Fa, _Fb, _Fc, _Fd, _Fe, _Ff,
}

pub struct ActiveContextArgs<'a> {
    pub context_type: ContextType,
    pub locality: u32,
    pub handle: &'a ContextHandle,
    pub tci_type: u32,
    pub parent_idx: u8,
    pub allow_ca: bool,
    pub allow_x509: bool,
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

    const CONTEXT_INITIALIZER: Context = Context::new();

    #[test]
    fn test_child_to_root_iter() {
        let mut contexts = [CONTEXT_INITIALIZER; MAX_HANDLES];
        let root_index = CHAIN_INDICES[0];
        assert_eq!(MAX_HANDLES, CHAIN_INDICES.len());

        // Put the context's index in the handle to make it easy to find later.
        contexts[root_index].handle = ContextHandle([root_index as u8; ContextHandle::SIZE]);
        contexts[root_index].state = ContextState::Retired;

        // Assign all of the children's parents and put their index in the handle.
        for (parent_chain_idx, child_idx) in CHAIN_INDICES.iter().skip(1).enumerate() {
            let parent_idx = CHAIN_INDICES[parent_chain_idx];
            let context = &mut contexts[*child_idx];
            context.parent_idx = parent_idx as u8;
            context.handle = ContextHandle([*child_idx as u8; ContextHandle::SIZE]);
            context.state = ContextState::Active;
        }

        let mut count = 0;
        let leaf_index = CHAIN_INDICES[CHAIN_INDICES.len() - 1];

        for (answer, status) in CHAIN_INDICES
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
        assert_eq!(CHAIN_INDICES.len(), count);
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
