/*++
Licensed under the Apache-2.0 license.

Abstract:
    Defines an instance of DPE and all of its contexts.
--*/
use crate::{
    commands::{Command, CommandExecution, InitCtxCmd},
    context::{ChildToRootIter, Context, ContextHandle, ContextState},
    response::{DpeErrorCode, GetProfileResp, Response, ResponseHdr},
    support::Support,
    tci::{TciMeasurement, TciNodeData},
    U8Bool, DPE_PROFILE, INTERNAL_INPUT_INFO_SIZE, MAX_HANDLES,
};
use crypto::{Crypto, Digest, Hasher};
use platform::{Platform, MAX_CHUNK_SIZE};
use zerocopy::{AsBytes, FromBytes};

pub trait DpeTypes {
    type Crypto<'a>: Crypto
    where
        Self: 'a;
    type Platform<'a>: Platform
    where
        Self: 'a;
}

pub struct DpeEnv<'a, T: DpeTypes + 'a> {
    pub crypto: T::Crypto<'a>,
    pub platform: T::Platform<'a>,
}

#[repr(C, align(4))]
#[derive(AsBytes, FromBytes)]
pub struct DpeInstance {
    pub(crate) contexts: [Context; MAX_HANDLES],
    pub(crate) support: Support,

    /// Can only successfully execute the initialize context command for non-simulation (i.e.
    /// `InitializeContext(simulation=false)`) once per reset cycle.
    pub(crate) has_initialized: U8Bool,

    // unused buffer added to make DpeInstance word aligned and remove padding
    reserved: [u8; 3],
}

impl DpeInstance {
    const MAX_NEW_HANDLE_ATTEMPTS: usize = 8;

    /// Create a new DPE instance.
    ///
    /// # Arguments
    ///
    /// * `support` - optional functionality the instance supports
    /// * `issuer_cn` - issuer Common Name to use in DPE leaf certs
    pub fn new(
        env: &mut DpeEnv<impl DpeTypes>,
        support: Support,
    ) -> Result<DpeInstance, DpeErrorCode> {
        const CONTEXT_INITIALIZER: Context = Context::new();
        let mut dpe = DpeInstance {
            contexts: [CONTEXT_INITIALIZER; MAX_HANDLES],
            support,
            has_initialized: false.into(),
            reserved: [0u8; 3],
        };

        if dpe.support.auto_init() {
            let locality = env
                .platform
                .get_auto_init_locality()
                .map_err(|_| DpeErrorCode::InvalidLocality)?;
            InitCtxCmd::new_use_default().execute(&mut dpe, env, locality)?;
        }
        Ok(dpe)
    }

    pub fn has_initialized(&self) -> bool {
        self.has_initialized.get()
    }

    pub fn get_profile(
        &self,
        platform: &mut impl Platform,
    ) -> Result<GetProfileResp, DpeErrorCode> {
        let vendor_id = platform
            .get_vendor_id()
            .map_err(|_| DpeErrorCode::PlatformError)?;
        let vendor_sku = platform
            .get_vendor_sku()
            .map_err(|_| DpeErrorCode::PlatformError)?;
        Ok(GetProfileResp::new(
            self.support.bits(),
            vendor_id,
            vendor_sku,
        ))
    }

    /// Deserializes the command and executes it.
    ///
    /// # Arguments
    ///
    /// * `locality` - which hardware locality is making the request
    /// * `cmd` - serialized command
    /// * `crypto` - Crypto interface
    pub fn execute_serialized_command(
        &mut self,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
        cmd: &[u8],
    ) -> Result<Response, DpeErrorCode> {
        let command = Command::deserialize(cmd)?;
        let resp = match command {
            Command::GetProfile => Ok(Response::GetProfile(self.get_profile(&mut env.platform)?)),
            Command::InitCtx(cmd) => cmd.execute(self, env, locality),
            Command::DeriveChild(cmd) => cmd.execute(self, env, locality),
            Command::CertifyKey(cmd) => cmd.execute(self, env, locality),
            Command::Sign(cmd) => cmd.execute(self, env, locality),
            Command::RotateCtx(cmd) => cmd.execute(self, env, locality),
            Command::DestroyCtx(cmd) => cmd.execute(self, env, locality),
            Command::ExtendTci(cmd) => cmd.execute(self, env, locality),
            Command::TagTci(cmd) => cmd.execute(self, env, locality),
            Command::GetTaggedTci(cmd) => cmd.execute(self, env, locality),
            Command::GetCertificateChain(cmd) => cmd.execute(self, env, locality),
        };

        match resp {
            Ok(resp) => Ok(resp),
            Err(err_code) => Ok(Response::Error(ResponseHdr::new(err_code))),
        }
    }

    // Inlined so the callsite optimizer knows that idx < self.contexts.len()
    // and won't insert possible call to panic.
    #[inline(always)]
    pub(crate) fn get_active_context_pos(
        &self,
        handle: &ContextHandle,
        locality: u32,
    ) -> Result<usize, DpeErrorCode> {
        let idx = self.get_active_context_pos_internal(handle, locality)?;
        if idx >= self.contexts.len() {
            // No idea if this is the correct error code
            return Err(DpeErrorCode::InternalError);
        }
        Ok(idx)
    }

    fn get_active_context_pos_internal(
        &self,
        handle: &ContextHandle,
        locality: u32,
    ) -> Result<usize, DpeErrorCode> {
        let mut valid_handles = self
            .contexts
            .iter()
            .enumerate()
            .filter(|(_, context)| {
                context.state == ContextState::Active && &context.handle == handle
            })
            .peekable();
        if valid_handles.peek().is_none() {
            return Err(DpeErrorCode::InvalidHandle);
        }
        let mut valid_handles_and_localities = valid_handles
            .filter(|(_, context)| context.locality == locality)
            .peekable();
        if valid_handles_and_localities.peek().is_none() {
            return Err(DpeErrorCode::InvalidLocality);
        }
        let (i, _) = valid_handles_and_localities
            .find(|(_, context)| {
                context.state == ContextState::Active
                    && &context.handle == handle
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

    /// Recursive function that will return all of a context's descendants. Returns a u32 that is
    /// a bitmap of the node indices.
    pub(crate) fn get_descendants(&self, context: &Context) -> Result<u32, DpeErrorCode> {
        if context.state == ContextState::Inactive {
            return Err(DpeErrorCode::InvalidHandle);
        }

        let mut descendants = context.children;
        for idx in flags_iter(context.children, MAX_HANDLES) {
            if idx >= self.contexts.len() {
                return Err(DpeErrorCode::InternalError);
            }
            descendants |= self.get_descendants(&self.contexts[idx])?;
        }
        Ok(descendants)
    }

    pub(crate) fn generate_new_handle(
        &self,
        env: &mut DpeEnv<impl DpeTypes>,
    ) -> Result<ContextHandle, DpeErrorCode> {
        for _ in 0..Self::MAX_NEW_HANDLE_ATTEMPTS {
            let mut handle = ContextHandle::default();
            env.crypto
                .rand_bytes(&mut handle.0)
                .map_err(|_| DpeErrorCode::RandError)?;
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
    pub(crate) fn roll_onetime_use_handle(
        &mut self,
        env: &mut DpeEnv<impl DpeTypes>,
        idx: usize,
    ) -> Result<(), DpeErrorCode> {
        if idx >= MAX_HANDLES {
            return Err(DpeErrorCode::MaxTcis);
        }
        if !self.contexts[idx].handle.is_default() {
            self.contexts[idx].handle = self.generate_new_handle(env)?
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
        env: &mut DpeEnv<impl DpeTypes>,
        idx: usize,
        measurement: &TciMeasurement,
        locality: u32,
    ) -> Result<(), DpeErrorCode> {
        if idx >= MAX_HANDLES {
            return Err(DpeErrorCode::MaxTcis);
        }

        let context = &mut self.contexts[idx];

        if context.state != ContextState::Active {
            return Err(DpeErrorCode::InvalidHandle);
        }
        if context.locality != locality {
            return Err(DpeErrorCode::InvalidLocality);
        }

        // Derive the new TCI as HASH(TCI_CUMULATIVE || INPUT_DATA).
        let mut hasher = env
            .crypto
            .hash_initialize(DPE_PROFILE.alg_len())
            .map_err(|_| DpeErrorCode::HashError)?;
        hasher
            .update(&context.tci.tci_cumulative.0)
            .map_err(|_| DpeErrorCode::HashError)?;
        hasher
            .update(&measurement.0)
            .map_err(|_| DpeErrorCode::HashError)?;
        let digest = hasher.finish().map_err(|_| DpeErrorCode::HashError)?;

        let digest_bytes = digest.bytes();

        if digest_bytes.len() != context.tci.tci_cumulative.0.len() {
            return Err(DpeErrorCode::InternalError);
        }
        context.tci.tci_cumulative.0.copy_from_slice(digest_bytes);
        context.tci.tci_current = *measurement;
        Ok(())
    }

    fn serialize_internal_input_info(
        &self,
        platform: &mut impl Platform,
        internal_input_info: &mut [u8; INTERNAL_INPUT_INFO_SIZE],
    ) -> Result<(), DpeErrorCode> {
        // Internal DPE Info contains get profile response fields as well as the DPE_PROFILE
        let profile = self.get_profile(platform)?;
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

    /// Compute measurement hash for a child node.
    ///
    /// Goes up the TciNodeData chain hashing each along the way until it gets to the root node.
    ///
    /// # Arguments
    ///
    /// * `start_idx` - index of the leaf context
    pub(crate) fn compute_measurement_hash(
        &mut self,
        env: &mut DpeEnv<impl DpeTypes>,
        start_idx: usize,
    ) -> Result<Digest, DpeErrorCode> {
        let mut hasher = env
            .crypto
            .hash_initialize(DPE_PROFILE.alg_len())
            .map_err(|_| DpeErrorCode::HashError)?;

        let mut uses_internal_input_info = false;
        let mut uses_internal_input_dice = false;

        // Hash each node.
        for status in ChildToRootIter::new(start_idx, &self.contexts) {
            let context = status?;

            hasher
                .update(context.tci.as_bytes())
                .map_err(|_| DpeErrorCode::HashError)?;

            // Check if any context uses internal inputs
            uses_internal_input_info =
                uses_internal_input_info || context.uses_internal_input_info();
            uses_internal_input_dice =
                uses_internal_input_dice || context.uses_internal_input_dice();
        }

        // Add internal input info to hash
        if uses_internal_input_info {
            let mut internal_input_info = [0u8; INTERNAL_INPUT_INFO_SIZE];
            self.serialize_internal_input_info(&mut env.platform, &mut internal_input_info)?;
            hasher
                .update(&internal_input_info[..INTERNAL_INPUT_INFO_SIZE])
                .map_err(|_| DpeErrorCode::HashError)?;
        }

        // Add internal input dice to hash
        if uses_internal_input_dice {
            let mut offset = 0;
            let mut cert_chunk = [0u8; MAX_CHUNK_SIZE];
            while let Ok(len) =
                env.platform
                    .get_certificate_chain(offset, MAX_CHUNK_SIZE as u32, &mut cert_chunk)
            {
                hasher
                    .update(&cert_chunk[..len as usize])
                    .map_err(|_| DpeErrorCode::HashError)?;
                offset += len;
            }
        }

        hasher.finish().map_err(|_| DpeErrorCode::HashError)
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
    use crate::commands::{DeriveChildCmd, DeriveChildFlags};
    use crate::response::NewHandleResp;
    use crate::support::test::SUPPORT;
    use crate::{commands::CommandHdr, CURRENT_PROFILE_MAJOR_VERSION};
    use crypto::OpensslCrypto;
    use platform::{DefaultPlatform, AUTO_INIT_LOCALITY, TEST_CERT_CHAIN};
    use zerocopy::AsBytes;

    pub struct TestTypes;
    impl DpeTypes for TestTypes {
        type Crypto<'a> = OpensslCrypto;
        type Platform<'a> = DefaultPlatform;
    }

    pub const TEST_HANDLE: ContextHandle =
        ContextHandle([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    pub const SIMULATION_HANDLE: ContextHandle =
        ContextHandle([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    pub const TEST_LOCALITIES: [u32; 2] = [AUTO_INIT_LOCALITY, u32::from_be_bytes(*b"OTHR")];

    #[test]
    fn test_execute_serialized_command() {
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, SUPPORT).unwrap();

        assert_eq!(
            Response::GetProfile(GetProfileResp::new(
                SUPPORT.bits(),
                env.platform.get_vendor_id().unwrap(),
                env.platform.get_vendor_sku().unwrap()
            )),
            dpe.execute_serialized_command(
                &mut env,
                TEST_LOCALITIES[0],
                CommandHdr::new_for_test(Command::GetProfile).as_bytes(),
            )
            .unwrap()
        );

        // The default context was initialized while creating the instance. Now lets create a
        // simulation context.
        let mut command = CommandHdr::new_for_test(Command::InitCtx(InitCtxCmd::new_simulation()))
            .as_bytes()
            .to_vec();
        command.extend(InitCtxCmd::new_simulation().as_bytes());
        assert_eq!(
            Response::InitCtx(NewHandleResp {
                handle: SIMULATION_HANDLE,
                resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
            }),
            dpe.execute_serialized_command(&mut env, TEST_LOCALITIES[0], &command)
                .unwrap()
        );
    }

    #[test]
    fn test_get_profile() {
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let dpe = DpeInstance::new(&mut env, SUPPORT).unwrap();
        let profile = dpe.get_profile(&mut env.platform).unwrap();
        assert_eq!(profile.major_version, CURRENT_PROFILE_MAJOR_VERSION);
        assert_eq!(profile.flags, SUPPORT.bits());
    }

    #[test]
    fn test_get_active_context_index() {
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::default()).unwrap();
        let expected_index = 7;
        dpe.contexts[expected_index].handle = SIMULATION_HANDLE;

        let locality = AUTO_INIT_LOCALITY;
        // Has not been activated.
        assert!(dpe
            .get_active_context_pos(&SIMULATION_HANDLE, locality)
            .is_err());

        // Shouldn't be able to find it if it is retired either.
        dpe.contexts[expected_index].state = ContextState::Retired;
        assert!(dpe
            .get_active_context_pos(&SIMULATION_HANDLE, locality)
            .is_err());

        // Mark it active, but check the wrong locality.
        let locality = 2;
        dpe.contexts[expected_index].state = ContextState::Active;
        assert!(dpe
            .get_active_context_pos(&SIMULATION_HANDLE, locality)
            .is_err());

        // Should find it now.
        dpe.contexts[expected_index].locality = locality;
        let idx = dpe
            .get_active_context_pos(&SIMULATION_HANDLE, locality)
            .unwrap();
        assert_eq!(expected_index, idx);
    }

    #[test]
    fn test_add_tci_measurement() {
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };

        let mut dpe = DpeInstance::new(&mut env, Support::AUTO_INIT).unwrap();

        // Verify bounds checking.
        assert_eq!(
            Err(DpeErrorCode::MaxTcis),
            dpe.add_tci_measurement(
                &mut env,
                MAX_HANDLES,
                &TciMeasurement::default(),
                TEST_LOCALITIES[0],
            )
        );

        let data = [1; DPE_PROFILE.get_hash_size()];
        dpe.add_tci_measurement(&mut env, 0, &TciMeasurement(data), TEST_LOCALITIES[0])
            .unwrap();
        let context = &dpe.contexts[0];
        assert_eq!(data, context.tci.tci_current.0);

        // Compute cumulative.
        let mut hasher = env.crypto.hash_initialize(DPE_PROFILE.alg_len()).unwrap();
        hasher.update(&[0; DPE_PROFILE.get_hash_size()]).unwrap();
        hasher.update(&data).unwrap();
        let first_cumulative = hasher.finish().unwrap();

        // Make sure the cumulative was computed correctly.
        assert_eq!(first_cumulative.bytes(), context.tci.tci_cumulative.0);

        let data = [2; DPE_PROFILE.get_hash_size()];
        dpe.add_tci_measurement(&mut env, 0, &TciMeasurement(data), TEST_LOCALITIES[0])
            .unwrap();
        // Make sure the current TCI was updated correctly.
        let context = &dpe.contexts[0];
        assert_eq!(data, context.tci.tci_current.0);

        let mut hasher = env.crypto.hash_initialize(DPE_PROFILE.alg_len()).unwrap();
        hasher.update(first_cumulative.bytes()).unwrap();
        hasher.update(&data).unwrap();
        let second_cumulative = hasher.finish().unwrap();

        // Make sure the cumulative was computed correctly.
        assert_eq!(second_cumulative.bytes(), context.tci.tci_cumulative.0);
    }

    #[test]
    fn test_get_descendants() {
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::default()).unwrap();
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
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, SUPPORT).unwrap();

        let mut last_cdi = vec![];

        for i in 0..3 {
            DeriveChildCmd {
                handle: ContextHandle::default(),
                data: [i; DPE_PROFILE.get_hash_size()],
                flags: DeriveChildFlags::MAKE_DEFAULT,
                tci_type: i as u32,
                target_locality: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap();

            // Check the CDI changes each time.
            let leaf_context_idx = dpe
                .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
                .unwrap();
            let digest = dpe
                .compute_measurement_hash(&mut env, leaf_context_idx)
                .unwrap();
            let curr_cdi = env
                .crypto
                .derive_cdi(DPE_PROFILE.alg_len(), &digest, b"DPE")
                .unwrap();
            assert_ne!(last_cdi, curr_cdi);

            last_cdi = curr_cdi;
        }

        let mut hasher = env.crypto.hash_initialize(DPE_PROFILE.alg_len()).unwrap();
        let leaf_idx = dpe
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();

        for result in ChildToRootIter::new(leaf_idx, &dpe.contexts) {
            let context = result.unwrap();
            hasher.update(context.tci.as_bytes()).unwrap();
        }

        let digest = hasher.finish().unwrap();
        let answer = env
            .crypto
            .derive_cdi(DPE_PROFILE.alg_len(), &digest, b"DPE")
            .unwrap();
        assert_eq!(answer, last_cdi);
    }

    #[test]
    fn test_hash_internal_input_info() {
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, SUPPORT | Support::INTERNAL_INFO).unwrap();

        let parent_context_idx = dpe
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();
        DeriveChildCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.get_hash_size()],
            flags: DeriveChildFlags::MAKE_DEFAULT | DeriveChildFlags::INTERNAL_INPUT_INFO,
            tci_type: 0u32,
            target_locality: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap();

        let digest = dpe
            .compute_measurement_hash(&mut env, parent_context_idx)
            .unwrap();
        let cdi_with_internal_input_info = env
            .crypto
            .derive_cdi(DPE_PROFILE.alg_len(), &digest, b"DPE")
            .unwrap();
        let context = &dpe.contexts[parent_context_idx];
        assert!(context.uses_internal_input_info());

        let mut hasher = env.crypto.hash_initialize(DPE_PROFILE.alg_len()).unwrap();

        hasher.update(context.tci.as_bytes()).unwrap();
        let mut internal_input_info = [0u8; INTERNAL_INPUT_INFO_SIZE];
        dpe.serialize_internal_input_info(&mut env.platform, &mut internal_input_info)
            .unwrap();

        hasher
            .update(&internal_input_info[..INTERNAL_INPUT_INFO_SIZE])
            .unwrap();

        let digest = hasher.finish().unwrap();
        let answer = env
            .crypto
            .derive_cdi(DPE_PROFILE.alg_len(), &digest, b"DPE")
            .unwrap();
        assert_eq!(answer, cdi_with_internal_input_info);
    }

    #[test]
    fn test_hash_internal_input_dice() {
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, SUPPORT | Support::INTERNAL_DICE).unwrap();

        let parent_context_idx = dpe
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();
        DeriveChildCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.get_hash_size()],
            flags: DeriveChildFlags::MAKE_DEFAULT | DeriveChildFlags::INTERNAL_INPUT_DICE,
            tci_type: 0u32,
            target_locality: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap();

        let digest = dpe
            .compute_measurement_hash(&mut env, parent_context_idx)
            .unwrap();
        let cdi_with_internal_input_dice = env
            .crypto
            .derive_cdi(DPE_PROFILE.alg_len(), &digest, b"DPE")
            .unwrap();
        let context = &dpe.contexts[parent_context_idx];
        assert!(context.uses_internal_input_dice());

        let mut hasher = env.crypto.hash_initialize(DPE_PROFILE.alg_len()).unwrap();

        hasher.update(context.tci.as_bytes()).unwrap();
        hasher
            .update(&TEST_CERT_CHAIN[..TEST_CERT_CHAIN.len()])
            .unwrap();

        let digest = hasher.finish().unwrap();
        let answer = env
            .crypto
            .derive_cdi(DPE_PROFILE.alg_len(), &digest, b"DPE")
            .unwrap();
        assert_eq!(answer, cdi_with_internal_input_dice)
    }
}
