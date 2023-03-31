/*++
Licensed under the Apache-2.0 license.

Abstract:
    Defines an instance of DPE and all of its contexts.
--*/
use crate::{
    _set_flag,
    commands::{Command, CommandExecution, InitCtxCmd},
    response::{DpeErrorCode, GetProfileResp, Response},
    DPE_PROFILE, HANDLE_SIZE, MAX_HANDLES,
};
use core::marker::PhantomData;
use core::mem::size_of;
use crypto::Crypto;

pub struct DpeInstance<'a, C: Crypto> {
    pub(crate) contexts: [Context; MAX_HANDLES],
    pub(crate) support: Support,
    pub(crate) localities: &'a [u32],

    /// Can only successfully execute the initialize context command for non-simulation (i.e.
    /// `InitializeContext(simulation=false)`) once per reset cycle.
    pub(crate) has_initialized: bool,

    // All functions/data in C are static and global. For this reason
    // DpeInstance doesn't actually need to hold an instance. The PhantomData
    // is just to make the Crypto trait work.
    phantom: PhantomData<C>,
}

impl<C: Crypto> DpeInstance<'_, C> {
    pub(crate) const DEFAULT_CONTEXT_HANDLE: [u8; HANDLE_SIZE] = [0; HANDLE_SIZE];
    const MAX_NEW_HANDLE_ATTEMPTS: usize = 8;
    pub const AUTO_INIT_LOCALITY: u32 = 0;

    /// Create a new DPE instance.
    ///
    /// # Arguments
    ///
    /// * `support` - optional functionality the instance supports
    /// * `localities` - all possible valid localities for the system
    pub fn new(support: Support, localities: &[u32]) -> Result<DpeInstance<C>, DpeErrorCode> {
        if localities.is_empty() {
            return Err(DpeErrorCode::InvalidLocality);
        }
        const CONTEXT_INITIALIZER: Context = Context::new();
        let mut dpe = DpeInstance {
            contexts: [CONTEXT_INITIALIZER; MAX_HANDLES],
            support,
            localities,
            has_initialized: false,
            phantom: PhantomData,
        };

        if dpe.support.auto_init {
            // Make sure the auto-initialized locality is listed.
            if !localities.iter().any(|&l| l == Self::AUTO_INIT_LOCALITY) {
                return Err(DpeErrorCode::InvalidLocality);
            }
            InitCtxCmd::new_use_default().execute(&mut dpe, Self::AUTO_INIT_LOCALITY)?;
        }
        Ok(dpe)
    }

    pub fn get_profile(&self) -> Result<GetProfileResp, DpeErrorCode> {
        Ok(GetProfileResp::new(self.support.get_flags()))
    }

    /// Deserializes the command and executes it.
    ///
    /// # Arguments
    ///
    /// * `locality` - which hardware locality is making the request
    /// * `cmd` - serialized command
    pub fn execute_serialized_command(
        &mut self,
        locality: u32,
        cmd: &[u8],
    ) -> Result<Response, DpeErrorCode> {
        // Make sure the command is coming from a valid locality.
        if !self.localities.iter().any(|&l| l == locality) {
            return Err(DpeErrorCode::InvalidLocality);
        }
        let command = Command::deserialize(cmd)?;
        match command {
            Command::GetProfile => Ok(Response::GetProfile(self.get_profile()?)),
            Command::InitCtx(cmd) => cmd.execute(self, locality),
            Command::DeriveChild(cmd) => cmd.execute(self, locality),
            Command::CertifyKey(cmd) => cmd.execute(self, locality),
            Command::RotateCtx(cmd) => cmd.execute(self, locality),
            Command::DestroyCtx(cmd) => cmd.execute(self, locality),
            Command::ExtendTci(cmd) => cmd.execute(self, locality),
            Command::TagTci(cmd) => cmd.execute(self, locality),
        }
    }

    pub(crate) fn get_active_context_pos(
        &self,
        handle: &[u8; HANDLE_SIZE],
        locality: u32,
    ) -> Option<usize> {
        self.contexts.iter().position(|context| {
            context.state == ContextState::Active
                && &context.handle == handle
                && context.locality == locality
        })
    }

    pub(crate) fn get_next_inactive_context_pos(&self) -> Option<usize> {
        self.contexts
            .iter()
            .position(|context| context.state == ContextState::Inactive)
    }

    /// Recursive function that will return all of a context's descendants. Returns a u32 that is
    /// a bitmap of the node indices.
    pub(crate) fn get_descendants(&self, context: &Context) -> Result<u32, DpeErrorCode> {
        if matches!(context.state, ContextState::Inactive) {
            return Err(DpeErrorCode::InvalidHandle);
        }

        let mut descendants = context.children;
        for idx in flags_iter(context.children, MAX_HANDLES) {
            descendants |= self.get_descendants(&self.contexts[idx])?;
        }
        Ok(descendants)
    }

    pub(crate) fn generate_new_handle(&self) -> Result<[u8; HANDLE_SIZE], DpeErrorCode> {
        for _ in 0..Self::MAX_NEW_HANDLE_ATTEMPTS {
            let mut handle = [0; HANDLE_SIZE];
            C::rand_bytes(&mut handle).map_err(|_| DpeErrorCode::InternalError)?;
            if handle != Self::DEFAULT_CONTEXT_HANDLE
                && !self.contexts.iter().any(|c| c.handle == handle)
            {
                return Ok(handle);
            }
        }
        Err(DpeErrorCode::InternalError)
    }

    /// Rolls the context handle if the context is not the default context.
    ///
    /// # Arguments
    ///
    /// * `idx` - the index of the context
    pub(crate) fn roll_onetime_use_handle(&mut self, idx: usize) -> Result<(), DpeErrorCode> {
        if idx >= MAX_HANDLES {
            return Err(DpeErrorCode::InternalError);
        }
        if self.contexts[idx].handle != Self::DEFAULT_CONTEXT_HANDLE {
            self.contexts[idx].handle = self.generate_new_handle()?
        };
        Ok(())
    }

    /// Get the TCI nodes from `context` to the root node following parent
    /// links. These are the nodes that should contribute to CDI and key
    /// derivation for `context`.
    ///
    /// Returns the number of TCIs written to `nodes`
    pub(crate) fn get_tcb_nodes(
        &self,
        context: &Context,
        nodes: &mut [TciNodeData],
    ) -> Result<usize, DpeErrorCode> {
        let mut curr = context;
        let mut out_idx = 0;

        loop {
            if out_idx >= nodes.len() || curr.state != ContextState::Active {
                return Err(DpeErrorCode::InternalError);
            }

            // TODO: The root node isn't a real node with measurements and
            // shouldn't be in the cert. But we don't support DeriveChild yet,
            // so this is the only node we can create to test cert creation.
            nodes[out_idx] = curr.tci;
            out_idx += 1;

            // Found the root
            if curr.parent_idx == 0xFF {
                break;
            }

            curr = &self.contexts[curr.parent_idx as usize];
        }

        Ok(out_idx)
    }
}

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct TciMeasurement(pub [u8; DPE_PROFILE.get_tci_size()]);

impl Default for TciMeasurement {
    fn default() -> Self {
        Self([0; DPE_PROFILE.get_tci_size()])
    }
}

#[derive(Default)]
pub struct Support {
    pub simulation: bool,
    pub extend_tci: bool,
    pub auto_init: bool,
    pub tagging: bool,
    pub rotate_context: bool,
    pub certify_key: bool,
    pub certify_csr: bool,
    pub internal_info: bool,
    pub internal_dice: bool,
}

impl Support {
    /// Returns all the flags bit-wise OR'ed together in the same configuration as the `GetProfile`
    /// command.
    pub fn get_flags(&self) -> u32 {
        self.get_simulation_flag()
            | self.get_extend_tci_flag()
            | self.get_auto_init_flag()
            | self.get_tagging_flag()
            | self.get_rotate_context_flag()
            | self.get_certify_key_flag()
            | self.get_certify_csr_flag()
            | self.get_internal_info_flag()
            | self.get_internal_dice_flag()
    }
    fn get_simulation_flag(&self) -> u32 {
        u32::from(self.simulation) << 31
    }
    fn get_extend_tci_flag(&self) -> u32 {
        u32::from(self.extend_tci) << 30
    }
    fn get_auto_init_flag(&self) -> u32 {
        u32::from(self.auto_init) << 29
    }
    fn get_tagging_flag(&self) -> u32 {
        u32::from(self.tagging) << 28
    }
    fn get_rotate_context_flag(&self) -> u32 {
        u32::from(self.rotate_context) << 27
    }
    fn get_certify_key_flag(&self) -> u32 {
        u32::from(self.certify_key) << 26
    }
    fn get_certify_csr_flag(&self) -> u32 {
        u32::from(self.certify_csr) << 25
    }
    fn get_internal_info_flag(&self) -> u32 {
        u32::from(self.internal_info) << 24
    }
    fn get_internal_dice_flag(&self) -> u32 {
        u32::from(self.internal_dice) << 23
    }
}

#[repr(C, align(4))]
#[derive(Default, Copy, Clone)]
pub(crate) struct TciNodeData {
    pub tci_type: u32,

    // Bits
    // 31: INTERNAL
    // 30-0: Reserved. Must be zero
    flags: u32,
    pub tci_cumulative: TciMeasurement,
    pub tci_current: TciMeasurement,
}

impl TciNodeData {
    const INTERNAL_FLAG_MASK: u32 = 1 << 31;

    pub const fn flag_is_internal(&self) -> bool {
        self.flags & Self::INTERNAL_FLAG_MASK != 0
    }

    fn _set_flag_is_internal(&mut self, value: bool) {
        _set_flag(&mut self.flags, Self::INTERNAL_FLAG_MASK, value);
    }

    pub const fn new() -> TciNodeData {
        TciNodeData {
            tci_type: 0,
            flags: 0,
            tci_cumulative: TciMeasurement([0; DPE_PROFILE.get_tci_size()]),
            tci_current: TciMeasurement([0; DPE_PROFILE.get_tci_size()]),
        }
    }

    pub fn serialize(&self, dst: &mut [u8]) -> Result<usize, DpeErrorCode> {
        if dst.len() < size_of::<Self>() {
            return Err(DpeErrorCode::InternalError);
        }

        let mut offset: usize = 0;
        dst[offset..offset + size_of::<u32>()].copy_from_slice(&self.tci_type.to_le_bytes());
        offset += size_of::<u32>();
        dst[offset..offset + self.tci_cumulative.0.len()].copy_from_slice(&self.tci_cumulative.0);
        offset += self.tci_cumulative.0.len();
        dst[offset..offset + self.tci_current.0.len()].copy_from_slice(&self.tci_current.0);
        offset += self.tci_current.0.len();

        Ok(offset)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ContextState {
    /// Inactive or uninitialized.
    Inactive,
    /// Context is initialized and ready to be used.
    Active,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ContextType {
    /// Typical context.
    Normal,
    /// Has limitations on what operations can be done.
    Simulation,
}

#[repr(C, align(4))]
pub(crate) struct Context {
    pub handle: [u8; HANDLE_SIZE],
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

    const fn new() -> Context {
        Context {
            handle: [0; HANDLE_SIZE],
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
    pub fn activate(
        &mut self,
        context_type: ContextType,
        locality: u32,
        handle: &[u8; HANDLE_SIZE],
    ) {
        self.handle.copy_from_slice(handle);
        self.tci = TciNodeData::new();
        self.children = 0;
        self.parent_idx = Self::ROOT_INDEX;
        self.context_type = context_type;
        self.state = ContextState::Active;
        self.locality = locality;
    }

    /// Destroy this context so it can no longer be used until it is re-initialized. The default
    /// context cannot be re-initialized.
    pub fn destroy(&mut self) {
        self.tci = TciNodeData::new();
        self.has_tag = false;
        self.tag = 0;
        self.state = ContextState::Inactive;
    }
}

/// Iterate over all of the bits set to 1 in a u32. Each iteration returns the bit index 0 being the
/// least significant.
///
/// # Arguments
///
/// * `flags` - bits to be iterated over
/// * `max` - number of bits to be considered
pub(crate) fn flags_iter(flags: u32, max: usize) -> FlagsIter {
    assert!((1..=u32::BITS).contains(&(max as u32)));
    FlagsIter {
        flags: flags & (u32::MAX >> (u32::BITS - max as u32)),
    }
}

pub(crate) struct FlagsIter {
    flags: u32,
}

impl Iterator for FlagsIter {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        if self.flags == 0 {
            return None;
        }
        let idx = self.flags.trailing_zeros() as usize;
        self.flags &= !(1 << idx);
        Some(idx)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::commands::DestroyCtxCmd;
    use crate::response::NewHandleResp;
    use crate::{commands::CommandHdr, CURRENT_PROFILE_VERSION};
    use crypto::OpensslCrypto;
    use zerocopy::AsBytes;

    const SUPPORT: Support = Support {
        simulation: true,
        extend_tci: false,
        auto_init: true,
        tagging: true,
        rotate_context: true,
        certify_key: true,
        certify_csr: false,
        internal_info: false,
        internal_dice: false,
    };
    pub const TEST_HANDLE: [u8; HANDLE_SIZE] =
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    pub const SIMULATION_HANDLE: [u8; HANDLE_SIZE] =
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    pub const TEST_LOCALITIES: [u32; 2] = [
        DpeInstance::<OpensslCrypto>::AUTO_INIT_LOCALITY,
        u32::from_be_bytes(*b"OTHR"),
    ];

    #[test]
    fn test_localities() {
        // Empty list of localities.
        assert_eq!(
            DpeErrorCode::InvalidLocality,
            DpeInstance::<OpensslCrypto>::new(SUPPORT, &[])
                .err()
                .unwrap()
        );

        // Auto-init without the auto-init locality.
        assert_eq!(
            DpeErrorCode::InvalidLocality,
            DpeInstance::<OpensslCrypto>::new(SUPPORT, &TEST_LOCALITIES[1..])
                .err()
                .unwrap()
        );

        let mut dpe = DpeInstance::<OpensslCrypto>::new(SUPPORT, &TEST_LOCALITIES).unwrap();
        assert_eq!(
            Err(DpeErrorCode::InvalidLocality),
            dpe.execute_serialized_command(
                0x1234_5678, // test value that is not part of the localities
                CommandHdr::new(Command::GetProfile).as_bytes(),
            )
        );

        // Make sure requests work for all localities.
        for l in TEST_LOCALITIES {
            assert_eq!(
                Response::GetProfile(GetProfileResp::new(SUPPORT.get_flags())),
                dpe.execute_serialized_command(l, CommandHdr::new(Command::GetProfile).as_bytes())
                    .unwrap()
            );
        }

        // Initialize a context to run some tests against.
        InitCtxCmd::new_simulation()
            .execute(&mut dpe, TEST_LOCALITIES[1])
            .unwrap();

        // Make sure the locality was recorded correctly.
        assert_eq!(
            dpe.contexts[dpe
                .get_active_context_pos(&SIMULATION_HANDLE, TEST_LOCALITIES[1])
                .unwrap()]
            .locality,
            TEST_LOCALITIES[1]
        );

        // Make sure the other locality can't destroy it.
        assert_eq!(
            Err(DpeErrorCode::InvalidHandle),
            DestroyCtxCmd {
                handle: SIMULATION_HANDLE,
                flags: 0
            }
            .execute(&mut dpe, TEST_LOCALITIES[0])
        );

        // Make sure right locality can destroy it.
        assert!(DestroyCtxCmd {
            handle: SIMULATION_HANDLE,
            flags: 0,
        }
        .execute(&mut dpe, TEST_LOCALITIES[1])
        .is_ok());
    }

    #[test]
    fn test_execute_serialized_command() {
        let mut dpe = DpeInstance::<OpensslCrypto>::new(SUPPORT, &TEST_LOCALITIES).unwrap();

        assert_eq!(
            Response::GetProfile(GetProfileResp::new(SUPPORT.get_flags())),
            dpe.execute_serialized_command(
                TEST_LOCALITIES[0],
                CommandHdr::new(Command::GetProfile).as_bytes(),
            )
            .unwrap()
        );

        // The default context was initialized while creating the instance. Now lets create a
        // simulation context.
        let mut command = CommandHdr::new(Command::InitCtx(InitCtxCmd::new_simulation()))
            .as_bytes()
            .to_vec();
        command.extend(InitCtxCmd::new_simulation().as_bytes());
        assert_eq!(
            Response::InitCtx(NewHandleResp {
                handle: SIMULATION_HANDLE
            }),
            dpe.execute_serialized_command(TEST_LOCALITIES[0], &command)
                .unwrap()
        );
    }

    #[test]
    fn test_get_profile() {
        let dpe = DpeInstance::<OpensslCrypto>::new(SUPPORT, &TEST_LOCALITIES).unwrap();
        let profile = dpe.get_profile().unwrap();
        assert_eq!(profile.version, CURRENT_PROFILE_VERSION);
        assert_eq!(profile.flags, SUPPORT.get_flags());
    }

    #[test]
    fn test_get_support_flags() {
        // Supports simulation flag.
        let flags = Support {
            simulation: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 31);
        // Supports extended TCI flag.
        let flags = Support {
            extend_tci: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 30);
        // Supports auto-init.
        let flags = Support {
            auto_init: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 29);
        // Supports tagging.
        let flags = Support {
            tagging: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 28);
        // Supports rotate context.
        let flags = Support {
            rotate_context: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 27);
        // Supports certify key.
        let flags = Support {
            certify_key: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 26);
        // Supports certify csr.
        let flags = Support {
            certify_csr: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 25);
        // Supports internal info.
        let flags = Support {
            internal_info: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 24);
        // Supports internal DICE.
        let flags = Support {
            internal_dice: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 23);
        // Supports a couple combos.
        let flags = Support {
            simulation: true,
            auto_init: true,
            rotate_context: true,
            certify_csr: true,
            internal_dice: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(
            flags,
            (1 << 31) | (1 << 29) | (1 << 27) | (1 << 25) | (1 << 23)
        );
        let flags = Support {
            extend_tci: true,
            tagging: true,
            certify_key: true,
            internal_info: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, (1 << 30) | (1 << 28) | (1 << 26) | (1 << 24));
        // Supports everything.
        let flags = Support {
            simulation: true,
            extend_tci: true,
            auto_init: true,
            tagging: true,
            rotate_context: true,
            certify_key: true,
            certify_csr: true,
            internal_info: true,
            internal_dice: true,
        }
        .get_flags();
        assert_eq!(
            flags,
            (1 << 31)
                | (1 << 30)
                | (1 << 29)
                | (1 << 28)
                | (1 << 27)
                | (1 << 26)
                | (1 << 25)
                | (1 << 24)
                | (1 << 23)
        );
    }

    #[test]
    fn test_get_active_context_index() {
        let mut dpe =
            DpeInstance::<OpensslCrypto>::new(Support::default(), &TEST_LOCALITIES).unwrap();
        let expected_index = 7;
        dpe.contexts[expected_index]
            .handle
            .copy_from_slice(&SIMULATION_HANDLE);

        let locality = DpeInstance::<OpensslCrypto>::AUTO_INIT_LOCALITY;
        // Has not been activated.
        assert!(dpe
            .get_active_context_pos(&SIMULATION_HANDLE, locality)
            .is_none());

        // Mark it active, but check the wrong locality.
        let locality = 2;
        dpe.contexts[expected_index].state = ContextState::Active;
        assert!(dpe
            .get_active_context_pos(&SIMULATION_HANDLE, locality)
            .is_none());

        // Should find it now.
        dpe.contexts[expected_index].locality = locality;
        let idx = dpe
            .get_active_context_pos(&SIMULATION_HANDLE, locality)
            .unwrap();
        assert_eq!(expected_index, idx);
    }

    #[test]
    fn test_get_descendants() {
        let mut dpe =
            DpeInstance::<OpensslCrypto>::new(Support::default(), &TEST_LOCALITIES).unwrap();
        let root = 7;
        let child_1 = 3;
        let child_1_1 = 0;
        let child_1_2 = MAX_HANDLES - 1;
        let child_1_2_1 = 1;
        let child_1_3 = MAX_HANDLES - 2;

        // Root isn't active.
        assert_eq!(
            dpe.get_descendants(&dpe.contexts[root]),
            Err(DpeErrorCode::InvalidHandle)
        );

        // No children.
        dpe.contexts[root].state = ContextState::Active;
        assert_eq!(dpe.get_descendants(&dpe.contexts[root]).unwrap(), 0);

        // Child not active.
        dpe.contexts[root].children = 1 << child_1;
        assert_eq!(
            dpe.get_descendants(&dpe.contexts[root]),
            Err(DpeErrorCode::InvalidHandle)
        );

        // One child.
        dpe.contexts[child_1].state = ContextState::Active;
        let mut children = dpe.contexts[root].children;
        assert_eq!(children, dpe.get_descendants(&dpe.contexts[root]).unwrap());

        // Add grandchildren.
        dpe.contexts[child_1_1].state = ContextState::Active;
        dpe.contexts[child_1_2].state = ContextState::Active;
        dpe.contexts[child_1_3].state = ContextState::Active;
        dpe.contexts[child_1].children = (1 << child_1_1) | (1 << child_1_2) | (1 << child_1_3);
        children |= dpe.contexts[child_1].children;
        assert_eq!(children, dpe.get_descendants(&dpe.contexts[root]).unwrap());

        // Add great-grandchildren.
        dpe.contexts[child_1_2_1].state = ContextState::Active;
        dpe.contexts[child_1_2].children = 1 << child_1_2_1;
        children |= dpe.contexts[child_1_2].children;
        assert_eq!(
            dpe.contexts[child_1_2].children,
            dpe.get_descendants(&dpe.contexts[child_1_2]).unwrap()
        );
        assert_eq!(children, dpe.get_descendants(&dpe.contexts[root]).unwrap());
    }
}
