/*++
Licensed under the Apache-2.0 license.

Abstract:
    Defines an instance of DPE and all of its contexts.
--*/
#[cfg(not(feature = "disable_internal_info"))]
use crate::INTERNAL_INPUT_INFO_SIZE;
use crate::{
    commands::{Command, CommandExecution, InitCtxCmd},
    context::{ChildToRootIter, Context, ContextHandle, ContextState},
    response::{DpeErrorCode, GetProfileResp, Response, ResponseHdr},
    support::Support,
    tci::{TciMeasurement, TciNodeData},
    U8Bool, DPE_PROFILE, MAX_HANDLES,
};
use bitflags::bitflags;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::cfi_launder;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq};
use cfg_if::cfg_if;
use core::mem::align_of;
use crypto::{Crypto, Digest, Hasher};
use platform::Platform;
#[cfg(not(feature = "disable_internal_dice"))]
use platform::MAX_CHUNK_SIZE;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};
use zeroize::Zeroize;

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

#[repr(C)]
#[derive(
    Debug,
    PartialEq,
    Eq,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    Zeroize,
)]
pub struct DpeInstanceFlags(pub u16);

bitflags! {
    impl DpeInstanceFlags: u16 {
        /// Mark DICE extensions as "Critical" in certificates created by `DpeInstance`.
        const MARK_DICE_EXTENSIONS_CRITICAL = 1u16 << 15;
    }
}

#[repr(C, align(4))]
#[derive(IntoBytes, TryFromBytes, KnownLayout, Immutable, Zeroize)]
pub struct DpeInstance {
    pub contexts: [Context; MAX_HANDLES],
    pub support: Support,
    pub flags: DpeInstanceFlags,
    /// Can only successfully execute the initialize context command for non-simulation (i.e.
    /// `InitializeContext(simulation=false)`) once per reset cycle.
    pub has_initialized: U8Bool,
    // unused buffer added to make DpeInstance word aligned and remove padding
    pub reserved: [u8; 1],
}
const _: () = assert!(align_of::<DpeInstance>() == 4);

impl DpeInstance {
    const MAX_NEW_HANDLE_ATTEMPTS: usize = 8;

    /// Create a new DPE instance.
    ///
    /// # Arguments
    ///
    /// * `env` - DPE environment containing Crypto and Platform implementations
    /// * `support` - optional functionality the instance supports
    /// * `flags` - configures `Self` behaviors.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn new(
        env: &mut DpeEnv<impl DpeTypes>,
        support: Support,
        flags: DpeInstanceFlags,
    ) -> Result<DpeInstance, DpeErrorCode> {
        let updated_support = support.preprocess_support();
        const CONTEXT_INITIALIZER: Context = Context::new();
        let mut dpe = DpeInstance {
            contexts: [CONTEXT_INITIALIZER; MAX_HANDLES],
            support: updated_support,
            flags,
            has_initialized: false.into(),
            reserved: [0; 1],
        };

        if dpe.support.auto_init() {
            let locality = env.platform.get_auto_init_locality()?;
            InitCtxCmd::new_use_default().execute(&mut dpe, env, locality)?;
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(!dpe.support.auto_init());
        }
        Ok(dpe)
    }

    /// Create a new DPE instance auto-initialized with a measurement
    ///
    /// # Arguments
    ///
    /// * `env` - DPE environment containing Crypto and Platform implementations
    /// * `support` - optional functionality the instance supports
    /// * `tci_type`- tci_type of initialized context
    /// * `auto_init_measurement` - TCI data of initialized context
    /// * `flags` - configures `Self` behaviors.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[cfg(not(feature = "disable_auto_init"))]
    pub fn new_auto_init(
        env: &mut DpeEnv<impl DpeTypes>,
        support: Support,
        tci_type: u32,
        auto_init_measurement: [u8; DPE_PROFILE.get_hash_size()],
        flags: DpeInstanceFlags,
    ) -> Result<DpeInstance, DpeErrorCode> {
        let updated_support = support.preprocess_support();
        // auto-init must be supported to add an auto init measurement
        if !updated_support.auto_init() {
            return Err(DpeErrorCode::ArgumentNotSupported);
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(updated_support.auto_init());
        }
        let mut dpe = Self::new(env, updated_support, flags)?;

        let locality = env.platform.get_auto_init_locality()?;
        let idx = dpe.get_active_context_pos(&ContextHandle::default(), locality)?;
        let mut tmp_context = dpe.contexts[idx];
        // add measurement to auto-initialized context
        dpe.add_tci_measurement(
            env,
            &mut tmp_context,
            &TciMeasurement(auto_init_measurement),
            locality,
        )?;
        dpe.contexts[idx] = tmp_context;
        dpe.contexts[idx].tci.tci_type = tci_type;
        Ok(dpe)
    }

    pub fn has_initialized(&self) -> bool {
        self.has_initialized.get()
    }

    pub fn get_profile(
        &self,
        platform: &mut impl Platform,
    ) -> Result<GetProfileResp, DpeErrorCode> {
        let vendor_id = platform.get_vendor_id()?;
        let vendor_sku = platform.get_vendor_sku()?;
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
    /// * `env` - DPE environment containing Crypto and Platform implementations
    /// * `locality` - which hardware locality is making the request
    /// * `cmd` - serialized command
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn execute_serialized_command(
        &mut self,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
        cmd: &[u8],
    ) -> Result<Response, DpeErrorCode> {
        let command = Command::deserialize(cmd)?;
        let resp = match cfi_launder(command) {
            Command::GetProfile => Ok(Response::GetProfile(self.get_profile(&mut env.platform)?)),
            Command::InitCtx(cmd) => cmd.execute(self, env, locality),
            Command::DeriveContext(cmd) => cmd.execute(self, env, locality),
            Command::CertifyKey(cmd) => cmd.execute(self, env, locality),
            Command::Sign(cmd) => cmd.execute(self, env, locality),
            #[cfg(not(feature = "disable_rotate_context"))]
            Command::RotateCtx(cmd) => cmd.execute(self, env, locality),
            Command::DestroyCtx(cmd) => cmd.execute(self, env, locality),
            Command::GetCertificateChain(cmd) => cmd.execute(self, env, locality),
        };

        match resp {
            Ok(resp) => Ok(resp),
            Err(err_code) => Ok(Response::Error(ResponseHdr::new(err_code))),
        }
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

    /// Generates a random context handle that is unique from all other context handles
    ///
    /// # Arguments
    ///
    /// * `env` - DPE environment containing Crypto and Platform implementations
    pub(crate) fn generate_new_handle(
        &self,
        env: &mut DpeEnv<impl DpeTypes>,
    ) -> Result<ContextHandle, DpeErrorCode> {
        for _ in 0..Self::MAX_NEW_HANDLE_ATTEMPTS {
            let mut handle = ContextHandle::default();
            env.crypto.rand_bytes(&mut handle.0)?;
            if !handle.is_default() && !self.contexts.iter().any(|c| c.handle.equals(&handle)) {
                return Ok(handle);
            }
        }
        Err(DpeErrorCode::InternalError)
    }

    /// Rolls the context handle if the context is not the default context.
    ///
    /// # Arguments
    ///
    /// * `env` - DPE environment containing Crypto and Platform implementations
    /// * `idx` - the index of the context
    pub fn roll_onetime_use_handle(
        &mut self,
        env: &mut DpeEnv<impl DpeTypes>,
        idx: usize,
    ) -> Result<(), DpeErrorCode> {
        if idx >= MAX_HANDLES {
            return Err(DpeErrorCode::MaxTcis);
        }
        if !self.contexts[idx].handle.is_default() {
            self.contexts[idx].handle = self.generate_new_handle(env)?;
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(self.contexts[idx].handle.is_default());
        }
        Ok(())
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

    /// Adds `measurement` to `context`. The current TCI is the measurement and
    /// the cumulative TCI is the hash of the old cumulative TCI and the measurement.
    ///
    /// # Arguments
    ///
    /// * `env` - DPE environment containing Crypto and Platform implementations
    /// * `context` - context to add `measurement`` to
    /// * `measurement` - measurement to add to `context``
    /// * `locality` - locality that `context`'s locality must match
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub(crate) fn add_tci_measurement(
        &self,
        env: &mut DpeEnv<impl DpeTypes>,
        context: &mut Context,
        measurement: &TciMeasurement,
        locality: u32,
    ) -> Result<(), DpeErrorCode> {
        if context.state != ContextState::Active {
            return Err(DpeErrorCode::InvalidHandle);
        }
        if context.locality != locality {
            return Err(DpeErrorCode::InvalidLocality);
        }
        cfg_if! {
            if #[cfg(not(feature = "no-cfi"))] {
                cfi_assert_eq(context.state, ContextState::Active);
                cfi_assert_eq(context.locality, locality);
            }
        }

        // Derive the new TCI as HASH(TCI_CUMULATIVE || INPUT_DATA).
        let mut hasher = env.crypto.hash_initialize(DPE_PROFILE.alg_len())?;
        hasher.update(&context.tci.tci_cumulative.0)?;
        hasher.update(&measurement.0)?;
        let digest = hasher.finish()?;

        let digest_bytes = digest.bytes();

        if digest_bytes.len() != context.tci.tci_cumulative.0.len() {
            return Err(DpeErrorCode::InternalError);
        }
        context.tci.tci_cumulative.0.copy_from_slice(digest_bytes);
        context.tci.tci_current = *measurement;
        Ok(())
    }

    /// Serializes the DPE profile and crypto algorithm type into the
    /// `internal_input_info` slice.
    ///
    /// # Arguments
    ///
    /// * `platform` - Platform trait implementation
    /// * `internal_input_info` - array to write serialized internal input info to
    #[cfg(not(feature = "disable_internal_info"))]
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
    /// * `env` - DPE environment containing Crypto and Platform implementations
    /// * `start_idx` - index of the leaf context
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub(crate) fn compute_measurement_hash(
        &mut self,
        env: &mut DpeEnv<impl DpeTypes>,
        start_idx: usize,
    ) -> Result<Digest, DpeErrorCode> {
        let mut hasher = env.crypto.hash_initialize(DPE_PROFILE.alg_len())?;

        let mut uses_internal_input_info = false;
        let mut uses_internal_input_dice = false;

        // Hash each node.
        for status in ChildToRootIter::new(start_idx, &self.contexts) {
            let context = status?;

            hasher.update(context.tci.as_bytes())?;

            // Check if any context uses internal inputs
            uses_internal_input_info =
                uses_internal_input_info || context.uses_internal_input_info();
            uses_internal_input_dice =
                uses_internal_input_dice || context.uses_internal_input_dice();

            // Add allow x509 to hash
            hasher.update(context.allow_x509().as_bytes())?;
        }

        // Add internal input info to hash
        #[cfg(not(feature = "disable_internal_info"))]
        if cfi_launder(uses_internal_input_info) {
            let mut internal_input_info = [0u8; INTERNAL_INPUT_INFO_SIZE];
            self.serialize_internal_input_info(&mut env.platform, &mut internal_input_info)?;
            hasher.update(&internal_input_info[..INTERNAL_INPUT_INFO_SIZE])?;
        }

        // Add internal input dice to hash
        #[cfg(not(feature = "disable_internal_dice"))]
        if cfi_launder(uses_internal_input_dice) {
            let mut offset = 0;
            let mut cert_chunk = [0u8; MAX_CHUNK_SIZE];
            while let Ok(len) =
                env.platform
                    .get_certificate_chain(offset, MAX_CHUNK_SIZE as u32, &mut cert_chunk)
            {
                hasher.update(&cert_chunk[..len as usize])?;
                offset += len;
            }
        }

        Ok(hasher.finish()?)
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
    use crate::commands::tests::DEFAULT_PLATFORM;
    use crate::commands::{DeriveContextCmd, DeriveContextFlags};
    use crate::response::NewHandleResp;
    use crate::support::test::SUPPORT;
    use crate::{commands::CommandHdr, CURRENT_PROFILE_MAJOR_VERSION};
    use caliptra_cfi_lib_git::CfiCounter;
    use crypto::OpensslCrypto;
    use platform::default::{DefaultPlatform, AUTO_INIT_LOCALITY};
    use zerocopy::IntoBytes;

    pub struct TestTypes;
    impl DpeTypes for TestTypes {
        type Crypto<'a> = OpensslCrypto;
        type Platform<'a> = DefaultPlatform;
    }

    pub const TEST_HANDLE: ContextHandle =
        ContextHandle([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    pub const SIMULATION_HANDLE: ContextHandle =
        ContextHandle([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    pub const RANDOM_HANDLE: ContextHandle = ContextHandle([
        51, 1, 232, 215, 231, 84, 219, 44, 245, 123, 10, 76, 167, 63, 37, 60,
    ]);

    pub const TEST_LOCALITIES: [u32; 2] = [AUTO_INIT_LOCALITY, u32::from_be_bytes(*b"OTHR")];

    #[test]
    fn test_execute_serialized_command() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DEFAULT_PLATFORM,
        };
        let mut dpe = DpeInstance::new(&mut env, SUPPORT, DpeInstanceFlags::empty()).unwrap();

        assert_eq!(
            Response::GetProfile(GetProfileResp::new(
                SUPPORT.bits(),
                env.platform.get_vendor_id().unwrap(),
                env.platform.get_vendor_sku().unwrap()
            )),
            dpe.execute_serialized_command(
                &mut env,
                TEST_LOCALITIES[0],
                CommandHdr::new_for_test(Command::GET_PROFILE).as_bytes(),
            )
            .unwrap()
        );

        // The default context was initialized while creating the instance. Now lets create a
        // simulation context.
        let mut command = CommandHdr::new_for_test(Command::INITIALIZE_CONTEXT)
            .as_bytes()
            .to_vec();
        command.extend(InitCtxCmd::new_simulation().as_bytes());
        assert_eq!(
            Response::InitCtx(NewHandleResp {
                handle: RANDOM_HANDLE,
                resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
            }),
            dpe.execute_serialized_command(&mut env, TEST_LOCALITIES[0], &command)
                .unwrap()
        );
    }

    #[test]
    fn test_get_profile() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DEFAULT_PLATFORM,
        };
        let dpe = DpeInstance::new(&mut env, SUPPORT, DpeInstanceFlags::empty()).unwrap();
        let profile = dpe.get_profile(&mut env.platform).unwrap();
        assert_eq!(profile.major_version, CURRENT_PROFILE_MAJOR_VERSION);
        assert_eq!(profile.flags, SUPPORT.bits());
    }

    #[test]
    fn test_get_active_context_index() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DEFAULT_PLATFORM,
        };
        let mut dpe =
            DpeInstance::new(&mut env, Support::default(), DpeInstanceFlags::empty()).unwrap();
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
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DEFAULT_PLATFORM,
        };

        let mut dpe =
            DpeInstance::new(&mut env, Support::AUTO_INIT, DpeInstanceFlags::empty()).unwrap();

        let data = [1; DPE_PROFILE.get_hash_size()];
        let mut context = dpe.contexts[0];
        dpe.add_tci_measurement(
            &mut env,
            &mut context,
            &TciMeasurement(data),
            TEST_LOCALITIES[0],
        )
        .unwrap();
        dpe.contexts[0] = context;
        assert_eq!(data, context.tci.tci_current.0);

        // Compute cumulative.
        let mut hasher = env.crypto.hash_initialize(DPE_PROFILE.alg_len()).unwrap();
        hasher.update(&[0; DPE_PROFILE.get_hash_size()]).unwrap();
        hasher.update(&data).unwrap();
        let first_cumulative = hasher.finish().unwrap();

        // Make sure the cumulative was computed correctly.
        assert_eq!(first_cumulative.bytes(), context.tci.tci_cumulative.0);

        let data = [2; DPE_PROFILE.get_hash_size()];
        dpe.add_tci_measurement(
            &mut env,
            &mut context,
            &TciMeasurement(data),
            TEST_LOCALITIES[0],
        )
        .unwrap();
        // Make sure the current TCI was updated correctly.
        dpe.contexts[0] = context;
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
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DEFAULT_PLATFORM,
        };
        let mut dpe =
            DpeInstance::new(&mut env, Support::default(), DpeInstanceFlags::empty()).unwrap();
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
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DEFAULT_PLATFORM,
        };
        let mut dpe = DpeInstance::new(&mut env, SUPPORT, DpeInstanceFlags::empty()).unwrap();

        let mut last_cdi = vec![];

        for i in 0..3 {
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [i; DPE_PROFILE.get_hash_size()],
                flags: DeriveContextFlags::MAKE_DEFAULT,
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
            hasher
                .update(/*allow_x509=*/ context.allow_x509().as_bytes())
                .unwrap();
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
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DEFAULT_PLATFORM,
        };
        let mut dpe = DpeInstance::new(
            &mut env,
            SUPPORT | Support::INTERNAL_INFO,
            DpeInstanceFlags::empty(),
        )
        .unwrap();

        let parent_context_idx = dpe
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();
        DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.get_hash_size()],
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INTERNAL_INPUT_INFO,
            tci_type: 0u32,
            target_locality: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap();

        let child_context_idx = dpe
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();
        let digest = dpe
            .compute_measurement_hash(&mut env, child_context_idx)
            .unwrap();
        let cdi_with_internal_input_info = env
            .crypto
            .derive_cdi(DPE_PROFILE.alg_len(), &digest, b"DPE")
            .unwrap();
        let parent_context = &dpe.contexts[parent_context_idx];
        let child_context = &dpe.contexts[child_context_idx];
        assert!(child_context.uses_internal_input_info());
        assert!(!parent_context.uses_internal_input_info());

        let mut hasher = env.crypto.hash_initialize(DPE_PROFILE.alg_len()).unwrap();

        hasher.update(child_context.tci.as_bytes()).unwrap();
        hasher.update(/*allow_x509=*/ false.as_bytes()).unwrap();
        hasher.update(parent_context.tci.as_bytes()).unwrap();
        hasher.update(/*allow_x509=*/ true.as_bytes()).unwrap();
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
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DEFAULT_PLATFORM,
        };
        let mut dpe = DpeInstance::new(
            &mut env,
            SUPPORT | Support::INTERNAL_DICE,
            DpeInstanceFlags::empty(),
        )
        .unwrap();

        let parent_context_idx = dpe
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();
        DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.get_hash_size()],
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INTERNAL_INPUT_DICE,
            tci_type: 0u32,
            target_locality: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap();

        let child_context_idx = dpe
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();
        let digest = dpe
            .compute_measurement_hash(&mut env, child_context_idx)
            .unwrap();
        let cdi_with_internal_input_dice = env
            .crypto
            .derive_cdi(DPE_PROFILE.alg_len(), &digest, b"DPE")
            .unwrap();
        let parent_context = &dpe.contexts[parent_context_idx];
        let child_context = &dpe.contexts[child_context_idx];
        assert!(child_context.uses_internal_input_dice());
        assert!(!parent_context.uses_internal_input_dice());

        let mut hasher = env.crypto.hash_initialize(DPE_PROFILE.alg_len()).unwrap();

        hasher.update(child_context.tci.as_bytes()).unwrap();
        hasher.update(/*allow_x509=*/ false.as_bytes()).unwrap();
        hasher.update(parent_context.tci.as_bytes()).unwrap();
        hasher.update(/*allow_x509=*/ true.as_bytes()).unwrap();
        let cert_chain = env.platform.0.cert_chain();
        hasher.update(&cert_chain).unwrap();

        let digest = hasher.finish().unwrap();
        let answer = env
            .crypto
            .derive_cdi(DPE_PROFILE.alg_len(), &digest, b"DPE")
            .unwrap();
        assert_eq!(answer, cdi_with_internal_input_dice)
    }

    #[test]
    fn test_new_auto_init() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DEFAULT_PLATFORM,
        };
        let tci_type = 0xdeadbeef_u32;
        let auto_init_measurement = [0x1; DPE_PROFILE.get_hash_size()];
        let auto_init_locality = env.platform.get_auto_init_locality().unwrap();
        let mut dpe = DpeInstance::new_auto_init(
            &mut env,
            SUPPORT,
            tci_type,
            auto_init_measurement,
            DpeInstanceFlags::empty(),
        )
        .unwrap();

        let idx = dpe
            .get_active_context_pos(&ContextHandle::default(), auto_init_locality)
            .unwrap();
        assert_eq!(dpe.contexts[idx].tci.tci_type, tci_type);
        assert_eq!(dpe.contexts[idx].tci.locality, auto_init_locality);
        assert_eq!(dpe.contexts[idx].tci.tci_current.0, auto_init_measurement);
        assert_eq!(dpe.contexts[idx].parent_idx, Context::ROOT_INDEX);
        assert_eq!(dpe.contexts[idx].children, 0);
        assert_eq!(dpe.contexts[idx].state, ContextState::Active);
        assert_eq!(dpe.contexts[idx].handle, ContextHandle::default());
        assert!(dpe.has_initialized());

        // check that initialize context fails if new_auto_init was used
        assert_eq!(
            InitCtxCmd::new_use_default().execute(&mut dpe, &mut env, auto_init_locality),
            Err(DpeErrorCode::ArgumentNotSupported)
        );
    }
}
