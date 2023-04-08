/*++
Licensed under the Apache-2.0 license.

Abstract:
    Defines an instance of DPE and all of its contexts.
--*/
use crate::{
    commands::{Command, CommandExecution, InitCtxCmd},
    context::{ChildToRootIter, Context, ContextHandle, ContextState},
    response::{DpeErrorCode, GetProfileResp, Response},
    support::Support,
    tci::{TciMeasurement, TciNodeData},
    DPE_PROFILE, MAX_HANDLES,
};
use core::{marker::PhantomData, mem::size_of};
use crypto::{Crypto, Hasher};

pub struct DpeInstance<'a, C: Crypto> {
    pub(crate) contexts: [Context; MAX_HANDLES],
    pub(crate) support: Support,
    pub(crate) localities: &'a [u32],

    /// Can only successfully execute the initialize context command for non-simulation (i.e.
    /// `InitializeContext(simulation=false)`) once per reset cycle.
    pub(crate) has_initialized: bool,

    // Issuer Common Name to use in DPE leaf certs
    pub(crate) issuer_cn: &'a [u8],

    // All functions/data in C are static and global. For this reason
    // DpeInstance doesn't actually need to hold an instance. The PhantomData
    // is just to make the Crypto trait work.
    phantom: PhantomData<C>,
}

impl<C: Crypto> DpeInstance<'_, C> {
    const MAX_NEW_HANDLE_ATTEMPTS: usize = 8;
    pub const AUTO_INIT_LOCALITY: u32 = 0;

    /// Create a new DPE instance.
    ///
    /// # Arguments
    ///
    /// * `support` - optional functionality the instance supports
    /// * `localities` - all possible valid localities for the system
    pub fn new<'a>(
        support: Support,
        localities: &'a [u32],
        issuer_cn: &'a [u8],
    ) -> Result<DpeInstance<'a, C>, DpeErrorCode> {
        if localities.is_empty() {
            return Err(DpeErrorCode::InvalidLocality);
        }
        const CONTEXT_INITIALIZER: Context = Context::new();
        let mut dpe = DpeInstance {
            contexts: [CONTEXT_INITIALIZER; MAX_HANDLES],
            support,
            localities,
            has_initialized: false,
            issuer_cn,
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

    pub fn new_for_test(
        support: Support,
        localities: &[u32],
    ) -> Result<DpeInstance<C>, DpeErrorCode> {
        const TEST_ISSUER: &[u8] = b"Test Issuer";
        Self::new(support, localities, TEST_ISSUER)
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
            Command::Sign(cmd) => cmd.execute(self, locality),
            Command::RotateCtx(cmd) => cmd.execute(self, locality),
            Command::DestroyCtx(cmd) => cmd.execute(self, locality),
            Command::ExtendTci(cmd) => cmd.execute(self, locality),
            Command::TagTci(cmd) => cmd.execute(self, locality),
        }
    }

    pub(crate) fn get_active_context_pos(
        &self,
        handle: &ContextHandle,
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

    pub(crate) fn generate_new_handle(&self) -> Result<ContextHandle, DpeErrorCode> {
        for _ in 0..Self::MAX_NEW_HANDLE_ATTEMPTS {
            let mut handle = ContextHandle::default();
            C::rand_bytes(&mut handle.0).map_err(|_| DpeErrorCode::InternalError)?;
            if !handle.is_default() && !self.contexts.iter().any(|c| c.handle == handle) {
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
        if !self.contexts[idx].handle.is_default() {
            self.contexts[idx].handle = self.generate_new_handle()?
        };
        Ok(())
    }

    /// Get the TCI nodes from the context at `start_idx` to the root node following parent
    /// links. These are the nodes that should contribute to CDI and key
    /// derivation for the context at `start_idx`.
    ///
    /// Returns the number of TCIs written to `nodes`
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

            // TODO: The root node isn't a real node with measurements and
            // shouldn't be in the cert. But we don't support DeriveChild yet,
            // so this is the only node we can create to test cert creation.
            nodes[out_idx] = curr.tci;
            out_idx += 1;
        }

        Ok(out_idx)
    }

    pub(crate) fn add_tci_measurement(
        &mut self,
        idx: usize,
        measurement: &TciMeasurement,
        locality: u32,
    ) -> Result<(), DpeErrorCode> {
        if idx >= MAX_HANDLES {
            return Err(DpeErrorCode::InternalError);
        }

        let context = &mut self.contexts[idx];

        if context.state != ContextState::Active {
            return Err(DpeErrorCode::InvalidHandle);
        }
        if context.locality != locality {
            return Err(DpeErrorCode::InvalidLocality);
        }

        // Derive the new TCI as HASH(TCI_CUMULATIVE || INPUT_DATA).
        let mut hasher =
            C::hash_initialize(DPE_PROFILE.alg_len()).map_err(|_| DpeErrorCode::InternalError)?;
        hasher
            .update(&context.tci.tci_cumulative.0)
            .map_err(|_| DpeErrorCode::InternalError)?;
        hasher
            .update(&measurement.0)
            .map_err(|_| DpeErrorCode::InternalError)?;
        hasher
            .finish(&mut context.tci.tci_cumulative.0)
            .map_err(|_| DpeErrorCode::InternalError)?;

        context.tci.tci_current = *measurement;
        Ok(())
    }

    /// Derive the CDI for a child node.
    ///
    /// Goes up the TciNodeData chain hashing each along the way until it gets to the root node.
    ///
    /// # Arguments
    ///
    /// * `start_idx` - index of the leaf context
    pub(crate) fn derive_cdi(&self, start_idx: usize) -> Result<C::Cdi, DpeErrorCode> {
        let mut hasher =
            C::hash_initialize(DPE_PROFILE.alg_len()).map_err(|_| DpeErrorCode::InternalError)?;

        // Hash each node.
        for status in ChildToRootIter::new(start_idx, &self.contexts) {
            let context = status?;

            let mut tci_bytes = [0u8; size_of::<TciNodeData>()];
            let len = context.tci.serialize(&mut tci_bytes)?;
            hasher
                .update(&tci_bytes[..len])
                .map_err(|_| DpeErrorCode::InternalError)?;
        }

        let mut digest = [0; DPE_PROFILE.get_hash_size()];
        hasher
            .finish(&mut digest)
            .map_err(|_| DpeErrorCode::InternalError)?;

        C::derive_cdi(DPE_PROFILE.alg_len(), &digest, b"DPE")
            .map_err(|_| DpeErrorCode::InternalError)
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
    use crate::support::test::SUPPORT;
    use crate::{commands::CommandHdr, CURRENT_PROFILE_VERSION};
    use crypto::OpensslCrypto;
    use zerocopy::AsBytes;

    pub const TEST_HANDLE: ContextHandle =
        ContextHandle([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    pub const SIMULATION_HANDLE: ContextHandle =
        ContextHandle([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    pub const TEST_LOCALITIES: [u32; 2] = [
        DpeInstance::<OpensslCrypto>::AUTO_INIT_LOCALITY,
        u32::from_be_bytes(*b"OTHR"),
    ];

    #[test]
    fn test_localities() {
        // Empty list of localities.
        assert_eq!(
            DpeErrorCode::InvalidLocality,
            DpeInstance::<OpensslCrypto>::new_for_test(SUPPORT, &[])
                .err()
                .unwrap()
        );

        // Auto-init without the auto-init locality.
        assert_eq!(
            DpeErrorCode::InvalidLocality,
            DpeInstance::<OpensslCrypto>::new_for_test(SUPPORT, &TEST_LOCALITIES[1..])
                .err()
                .unwrap()
        );

        let mut dpe =
            DpeInstance::<OpensslCrypto>::new_for_test(SUPPORT, &TEST_LOCALITIES).unwrap();
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
        let mut dpe =
            DpeInstance::<OpensslCrypto>::new_for_test(SUPPORT, &TEST_LOCALITIES).unwrap();

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
        let dpe = DpeInstance::<OpensslCrypto>::new_for_test(SUPPORT, &TEST_LOCALITIES).unwrap();
        let profile = dpe.get_profile().unwrap();
        assert_eq!(profile.version, CURRENT_PROFILE_VERSION);
        assert_eq!(profile.flags, SUPPORT.get_flags());
    }

    #[test]
    fn test_get_active_context_index() {
        let mut dpe =
            DpeInstance::<OpensslCrypto>::new_for_test(Support::default(), &TEST_LOCALITIES)
                .unwrap();
        let expected_index = 7;
        dpe.contexts[expected_index].handle = SIMULATION_HANDLE;

        let locality = DpeInstance::<OpensslCrypto>::AUTO_INIT_LOCALITY;
        // Has not been activated.
        assert!(dpe
            .get_active_context_pos(&SIMULATION_HANDLE, locality)
            .is_none());

        // Shouldn't be able to find it if it is retired either.
        dpe.contexts[expected_index].state = ContextState::Retired;
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
    fn test_add_tci_measurement() {
        let mut dpe = DpeInstance::<OpensslCrypto>::new_for_test(
            Support {
                auto_init: true,
                ..Default::default()
            },
            &TEST_LOCALITIES,
        )
        .unwrap();

        // Verify bounds checking.
        assert_eq!(
            Err(DpeErrorCode::InternalError),
            dpe.add_tci_measurement(MAX_HANDLES, &TciMeasurement::default(), TEST_LOCALITIES[0])
        );

        let data = [1; DPE_PROFILE.get_hash_size()];
        dpe.add_tci_measurement(0, &TciMeasurement(data), TEST_LOCALITIES[0])
            .unwrap();
        let context = &dpe.contexts[0];
        assert_eq!(data, context.tci.tci_current.0);

        // Compute cumulative.
        let mut hasher = OpensslCrypto::hash_initialize(DPE_PROFILE.alg_len()).unwrap();
        hasher.update(&[0; DPE_PROFILE.get_hash_size()]).unwrap();
        hasher.update(&data).unwrap();
        let mut first_cumulative = [0; DPE_PROFILE.get_hash_size()];
        hasher.finish(&mut first_cumulative).unwrap();

        // Make sure the cumulative was computed correctly.
        assert_eq!(first_cumulative.as_ref(), context.tci.tci_cumulative.0);

        let data = [2; DPE_PROFILE.get_hash_size()];
        dpe.add_tci_measurement(0, &TciMeasurement(data), TEST_LOCALITIES[0])
            .unwrap();
        // Make sure the current TCI was updated correctly.
        let context = &dpe.contexts[0];
        assert_eq!(data, context.tci.tci_current.0);

        let mut hasher = OpensslCrypto::hash_initialize(DPE_PROFILE.alg_len()).unwrap();
        hasher.update(&first_cumulative).unwrap();
        hasher.update(&data).unwrap();
        let mut second_cumulative = [0; DPE_PROFILE.get_hash_size()];
        hasher.finish(&mut second_cumulative).unwrap();

        // Make sure the cumulative was computed correctly.
        assert_eq!(second_cumulative.as_ref(), context.tci.tci_cumulative.0);
    }

    #[test]
    fn test_get_descendants() {
        let mut dpe =
            DpeInstance::<OpensslCrypto>::new_for_test(Support::default(), &TEST_LOCALITIES)
                .unwrap();
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
