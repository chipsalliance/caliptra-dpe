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
    DPE_PROFILE, INTERNAL_INPUT_INFO_SIZE, MAX_HANDLES,
};
use core::{marker::PhantomData, mem::size_of};
use crypto::{Crypto, Hasher};
use platform::{Platform, MAX_CHUNK_SIZE};
use zerocopy::AsBytes;

pub struct DpeInstance<'a, C: Crypto, P: Platform> {
    pub(crate) contexts: [Context<C>; MAX_HANDLES],
    pub(crate) support: Support,

    /// Can only successfully execute the initialize context command for non-simulation (i.e.
    /// `InitializeContext(simulation=false)`) once per reset cycle.
    pub(crate) has_initialized: bool,

    // Issuer Common Name to use in DPE leaf certs
    pub(crate) issuer_cn: &'a [u8],

    // All functions/data in C and P are static and global. For this reason
    // DpeInstance doesn't actually need to hold an instance. The PhantomData
    // is just to make the Crypto and Platform traits work.
    phantom_crypto: PhantomData<C>,
    phantom_platform: PhantomData<P>,
}

impl<C: Crypto, P: Platform> DpeInstance<'_, C, P> {
    const MAX_NEW_HANDLE_ATTEMPTS: usize = 8;

    pub(crate) fn new_context_handles() -> [Context<C>; MAX_HANDLES] {
        core::array::from_fn(|_| Context::new())
    }

    /// Create a new DPE instance.
    ///
    /// # Arguments
    ///
    /// * `support` - optional functionality the instance supports
    /// * `issuer_cn` - issuer Common Name to use in DPE leaf certs
    pub fn new(support: Support, issuer_cn: &[u8]) -> Result<DpeInstance<'_, C, P>, DpeErrorCode> {
        let mut dpe = DpeInstance {
            contexts: Self::new_context_handles(),
            support,
            has_initialized: false,
            issuer_cn,
            phantom_crypto: PhantomData,
            phantom_platform: PhantomData,
        };

        if dpe.support.auto_init {
            InitCtxCmd::new_use_default().execute(
                &mut dpe,
                P::get_auto_init_locality().map_err(|_| DpeErrorCode::InvalidLocality)?,
            )?;
        }
        Ok(dpe)
    }

    pub fn new_for_test<'a>(support: Support) -> Result<DpeInstance<'a, C, P>, DpeErrorCode> {
        const TEST_ISSUER: &[u8] = b"Test Issuer";
        Self::new(support, TEST_ISSUER)
    }

    pub fn get_profile(&self) -> Result<GetProfileResp, DpeErrorCode> {
        Ok(GetProfileResp::new(
            self.support.get_flags(),
            P::get_vendor_id().map_err(|_| DpeErrorCode::InternalError)?,
            P::get_vendor_sku().map_err(|_| DpeErrorCode::InternalError)?,
        ))
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
            Command::GetTaggedTci(cmd) => cmd.execute(self, locality),
            Command::CertifyCsr(cmd) => cmd.execute(self, locality),
            Command::GetCertificateChain(cmd) => cmd.execute(self, locality),
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
    pub(crate) fn get_descendants(&self, context: &Context<C>) -> Result<u32, DpeErrorCode> {
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
        let digest = hasher.finish().map_err(|_| DpeErrorCode::InternalError)?;

        context.tci.tci_cumulative.0.copy_from_slice(digest.bytes());
        context.tci.tci_current = *measurement;
        Ok(())
    }

    fn serialize_internal_input_info(
        &self,
        internal_input_info: &mut [u8; INTERNAL_INPUT_INFO_SIZE],
    ) -> Result<(), DpeErrorCode> {
        // Internal DPE Info contains get profile response fields as well as the DPE_PROFILE
        let profile = self.get_profile()?;
        let profile_bytes = profile.as_bytes();
        internal_input_info
            .get_mut(..profile_bytes.len())
            .ok_or(DpeErrorCode::InternalError)?
            .copy_from_slice(profile_bytes);

        internal_input_info
            .get_mut(profile_bytes.len()..)
            .ok_or(DpeErrorCode::InternalError)?
            .copy_from_slice(&(DPE_PROFILE as u32).to_le_bytes());

        Ok(())
    }

    /// Derive the CDI for a child node.
    ///
    /// Goes up the TciNodeData chain hashing each along the way until it gets to the root node.
    ///
    /// # Arguments
    ///
    /// * `start_idx` - index of the leaf context
    pub(crate) fn derive_cdi(
        &mut self,
        start_idx: usize,
        mix_random_value: bool,
    ) -> Result<C::Cdi, DpeErrorCode> {
        let mut hasher =
            C::hash_initialize(DPE_PROFILE.alg_len()).map_err(|_| DpeErrorCode::InternalError)?;

        let mut uses_internal_input_info = false;
        let mut uses_internal_input_dice = false;

        // Hash each node.
        for status in ChildToRootIter::new(start_idx, &self.contexts) {
            let context = status?;

            let mut tci_bytes = [0u8; size_of::<TciNodeData>()];
            let len = context.tci.serialize(&mut tci_bytes)?;
            hasher
                .update(&tci_bytes[..len])
                .map_err(|_| DpeErrorCode::InternalError)?;

            // Check if any context uses internal inputs
            uses_internal_input_info = uses_internal_input_info || context.uses_internal_input_info;
            uses_internal_input_dice = uses_internal_input_dice || context.uses_internal_input_dice;
        }

        // Add internal input info to hash
        if uses_internal_input_info {
            let mut internal_input_info = [0u8; INTERNAL_INPUT_INFO_SIZE];
            self.serialize_internal_input_info(&mut internal_input_info)?;
            hasher
                .update(&internal_input_info[..INTERNAL_INPUT_INFO_SIZE])
                .map_err(|_| DpeErrorCode::InternalError)?;
        }

        // Add internal input dice to hash
        if uses_internal_input_dice {
            let mut offset = 0;
            let mut cert_chunk = [0u8; MAX_CHUNK_SIZE];
            while let Ok(len) =
                P::get_certificate_chain(offset, MAX_CHUNK_SIZE as u32, &mut cert_chunk)
            {
                hasher
                    .update(&cert_chunk[..len as usize])
                    .map_err(|_| DpeErrorCode::InternalError)?;
                offset += len;
            }
        }

        let digest = hasher.finish().map_err(|_| DpeErrorCode::InternalError)?;
        let mut seed = [0; DPE_PROFILE.alg_len().size()];
        let random_seed = if mix_random_value {
            C::rand_bytes(&mut seed).map_err(|_| DpeErrorCode::InternalError)?;
            Some(seed.as_ref())
        } else {
            None
        };

        C::derive_cdi(DPE_PROFILE.alg_len(), &digest, b"DPE", random_seed)
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
    use crate::commands::DeriveChildCmd;
    use crate::response::NewHandleResp;
    use crate::support::test::SUPPORT;
    use crate::{commands::CommandHdr, CURRENT_PROFILE_MAJOR_VERSION};
    use crypto::OpensslCrypto;
    use platform::{DefaultPlatform, AUTO_INIT_LOCALITY, MAX_CHUNK_SIZE, TEST_CERT_CHAIN};
    use zerocopy::AsBytes;

    pub const TEST_HANDLE: ContextHandle =
        ContextHandle([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    pub const SIMULATION_HANDLE: ContextHandle =
        ContextHandle([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    pub const TEST_LOCALITIES: [u32; 2] = [AUTO_INIT_LOCALITY, u32::from_be_bytes(*b"OTHR")];

    #[test]
    fn test_execute_serialized_command() {
        let mut dpe = DpeInstance::<OpensslCrypto, DefaultPlatform>::new_for_test(SUPPORT).unwrap();

        assert_eq!(
            Response::GetProfile(GetProfileResp::new(
                SUPPORT.get_flags(),
                DefaultPlatform::get_vendor_id().unwrap(),
                DefaultPlatform::get_vendor_sku().unwrap()
            )),
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
        let dpe = DpeInstance::<OpensslCrypto, DefaultPlatform>::new_for_test(SUPPORT).unwrap();
        let profile = dpe.get_profile().unwrap();
        assert_eq!(profile.major_version, CURRENT_PROFILE_MAJOR_VERSION);
        assert_eq!(profile.flags, SUPPORT.get_flags());
    }

    #[test]
    fn test_get_active_context_index() {
        let mut dpe =
            DpeInstance::<OpensslCrypto, DefaultPlatform>::new_for_test(Support::default())
                .unwrap();
        let expected_index = 7;
        dpe.contexts[expected_index].handle = SIMULATION_HANDLE;

        let locality = AUTO_INIT_LOCALITY;
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
        let mut dpe = DpeInstance::<OpensslCrypto, DefaultPlatform>::new_for_test(Support {
            auto_init: true,
            ..Default::default()
        })
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
        let first_cumulative = hasher.finish().unwrap();

        // Make sure the cumulative was computed correctly.
        assert_eq!(first_cumulative.bytes(), context.tci.tci_cumulative.0);

        let data = [2; DPE_PROFILE.get_hash_size()];
        dpe.add_tci_measurement(0, &TciMeasurement(data), TEST_LOCALITIES[0])
            .unwrap();
        // Make sure the current TCI was updated correctly.
        let context = &dpe.contexts[0];
        assert_eq!(data, context.tci.tci_current.0);

        let mut hasher = OpensslCrypto::hash_initialize(DPE_PROFILE.alg_len()).unwrap();
        hasher.update(first_cumulative.bytes()).unwrap();
        hasher.update(&data).unwrap();
        let second_cumulative = hasher.finish().unwrap();

        // Make sure the cumulative was computed correctly.
        assert_eq!(second_cumulative.bytes(), context.tci.tci_cumulative.0);
    }

    #[test]
    fn test_get_descendants() {
        let mut dpe =
            DpeInstance::<OpensslCrypto, DefaultPlatform>::new_for_test(Support::default())
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

    #[test]
    fn test_derive_cdi() {
        let mut dpe = DpeInstance::<OpensslCrypto, DefaultPlatform>::new_for_test(SUPPORT).unwrap();

        let mut last_cdi = vec![];

        for i in 0..3 {
            DeriveChildCmd {
                handle: ContextHandle::default(),
                data: [i; DPE_PROFILE.get_hash_size()],
                flags: DeriveChildCmd::MAKE_DEFAULT,
                tci_type: i as u32,
                target_locality: 0,
            }
            .execute(&mut dpe, TEST_LOCALITIES[0])
            .unwrap();

            // Check the CDI changes each time.
            let leaf_context_idx = dpe
                .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
                .unwrap();
            let curr_cdi = dpe.derive_cdi(leaf_context_idx, false).unwrap();
            assert_ne!(last_cdi, curr_cdi);

            // Ensure the CDI changes when mixing random seed
            let cdi_with_rand_seed = dpe.derive_cdi(leaf_context_idx, true).unwrap();
            assert_ne!(curr_cdi, cdi_with_rand_seed);

            last_cdi = curr_cdi;
        }

        let mut hasher = OpensslCrypto::hash_initialize(DPE_PROFILE.alg_len()).unwrap();
        let leaf_idx = dpe
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();

        for result in ChildToRootIter::new(leaf_idx, &dpe.contexts) {
            let context = result.unwrap();
            hasher.update(context.tci.as_bytes()).unwrap();
        }

        let digest = hasher.finish().unwrap();
        let answer =
            OpensslCrypto::derive_cdi(DPE_PROFILE.alg_len(), &digest, b"DPE", None).unwrap();
        assert_eq!(answer, last_cdi);
    }

    #[test]
    fn test_hash_internal_input_info() {
        let mut dpe = DpeInstance::<OpensslCrypto, DefaultPlatform>::new_for_test(Support {
            internal_info: true,
            ..SUPPORT
        })
        .unwrap();

        let parent_context_idx = dpe
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();
        DeriveChildCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.get_hash_size()],
            flags: DeriveChildCmd::MAKE_DEFAULT | DeriveChildCmd::INTERNAL_INPUT_INFO,
            tci_type: 0u32,
            target_locality: 0,
        }
        .execute(&mut dpe, TEST_LOCALITIES[0])
        .unwrap();

        let cdi_with_internal_input_info = dpe.derive_cdi(parent_context_idx, false).unwrap();
        let context = &dpe.contexts[parent_context_idx];
        assert!(context.uses_internal_input_info);

        let mut hasher = OpensslCrypto::hash_initialize(DPE_PROFILE.alg_len()).unwrap();

        hasher.update(context.tci.as_bytes()).unwrap();
        let mut internal_input_info = [0u8; INTERNAL_INPUT_INFO_SIZE];
        dpe.serialize_internal_input_info(&mut internal_input_info)
            .unwrap();

        hasher
            .update(&internal_input_info[..INTERNAL_INPUT_INFO_SIZE])
            .unwrap();

        let digest = hasher.finish().unwrap();
        let answer =
            OpensslCrypto::derive_cdi(DPE_PROFILE.alg_len(), &digest, b"DPE", None).unwrap();
        assert_eq!(answer, cdi_with_internal_input_info);
    }

    #[test]
    fn test_hash_internal_input_dice() {
        let mut dpe = DpeInstance::<OpensslCrypto, DefaultPlatform>::new_for_test(Support {
            internal_dice: true,
            ..SUPPORT
        })
        .unwrap();

        let parent_context_idx = dpe
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();
        DeriveChildCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.get_hash_size()],
            flags: DeriveChildCmd::MAKE_DEFAULT | DeriveChildCmd::INTERNAL_INPUT_DICE,
            tci_type: 0u32,
            target_locality: 0,
        }
        .execute(&mut dpe, TEST_LOCALITIES[0])
        .unwrap();

        let cdi_with_internal_input_dice = dpe.derive_cdi(parent_context_idx, false).unwrap();
        let context = &dpe.contexts[parent_context_idx];
        assert!(context.uses_internal_input_dice);

        let mut hasher = OpensslCrypto::hash_initialize(DPE_PROFILE.alg_len()).unwrap();

        hasher.update(context.tci.as_bytes()).unwrap();
        hasher.update(&TEST_CERT_CHAIN[..MAX_CHUNK_SIZE]).unwrap();

        let digest = hasher.finish().unwrap();
        let answer =
            OpensslCrypto::derive_cdi(DPE_PROFILE.alg_len(), &digest, b"DPE", None).unwrap();
        assert_eq!(answer, cdi_with_internal_input_dice)
    }
}
