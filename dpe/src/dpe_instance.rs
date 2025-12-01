/*++
Licensed under the Apache-2.0 license.

Abstract:
    Defines an instance of DPE and all of its contexts.
--*/
#[cfg(not(feature = "disable_internal_info"))]
use crate::INTERNAL_INPUT_INFO_SIZE;
use crate::{
    commands::{Command, CommandExecution, CommandHdr, InitCtxCmd},
    context::{ChildToRootIter, Context, ContextHandle, ContextState},
    response::{DpeErrorCode, GetProfileResp, Response, ResponseHdr},
    support::Support,
    DpeProfile, State, MAX_HANDLES,
};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::cfi_launder;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq};
use cfg_if::cfg_if;
use crypto::{Crypto, CryptoSuite, Digest, Hasher};
use platform::Platform;
#[cfg(not(feature = "disable_internal_dice"))]
use platform::MAX_CHUNK_SIZE;
use zerocopy::IntoBytes;

pub trait DpeTypes {
    type Crypto<'a>: CryptoSuite
    where
        Self: 'a;
    type Platform<'a>: Platform
    where
        Self: 'a;
}

pub struct DpeEnv<'a, T: DpeTypes + 'a> {
    pub crypto: T::Crypto<'a>,
    pub platform: T::Platform<'a>,
    pub state: &'a mut State,
}

pub struct DpeInstance {
    pub profile: DpeProfile,
}

impl DpeInstance {
    const MAX_NEW_HANDLE_ATTEMPTS: usize = 8;

    /// Create a new DPE instance without initializing.
    pub const fn initialized(profile: DpeProfile) -> Self {
        Self { profile }
    }

    /// Create a new DPE instance.
    ///
    /// # Arguments
    ///
    /// * `env` - DPE environment containing Crypto and Platform implementations
    /// * `support` - optional functionality the instance supports
    /// * `flags` - configures `Self` behaviors.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn new(env: &mut DpeEnv<impl DpeTypes>, profile: DpeProfile) -> Result<Self, DpeErrorCode> {
        let mut dpe = Self::initialized(profile);

        if env.state.support.auto_init() {
            let locality = env.platform.get_auto_init_locality()?;
            InitCtxCmd::new_use_default().execute(&mut dpe, env, locality)?;
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(!env.state.support.auto_init());
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
        profile: DpeProfile,
        tci_type: u32,
        auto_init_measurement: &Digest,
    ) -> Result<Self, DpeErrorCode> {
        // auto-init must be supported to add an auto init measurement
        if !env.state.support.auto_init() {
            return Err(DpeErrorCode::ArgumentNotSupported);
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(env.state.support.auto_init());
        }
        let dpe = Self::new(env, profile)?;

        let locality = env.platform.get_auto_init_locality()?;
        let idx = env
            .state
            .get_active_context_pos(&ContextHandle::default(), locality)?;
        let mut tmp_context = env.state.contexts[idx];
        // add measurement to auto-initialized context
        dpe.add_tci_measurement(env, &mut tmp_context, auto_init_measurement, locality)?;
        env.state.contexts[idx] = tmp_context;
        env.state.contexts[idx].tci.tci_type = tci_type;
        Ok(dpe)
    }

    pub fn get_profile(
        &self,
        platform: &mut impl Platform,
        support: Support,
    ) -> Result<GetProfileResp, DpeErrorCode> {
        let vendor_id = platform.get_vendor_id()?;
        let vendor_sku = platform.get_vendor_sku()?;
        Ok(GetProfileResp::new(
            self.profile,
            support.bits(),
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
        let command = self.deserialize_command(cmd)?;
        let resp = match cfi_launder(command) {
            Command::GetProfile => Ok(Response::GetProfile(
                self.get_profile(&mut env.platform, env.state.support)?,
            )),
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
            Err(err_code) => Ok(Response::Error(self.response_hdr(err_code))),
        }
    }

    pub fn response_hdr(&self, err_code: DpeErrorCode) -> ResponseHdr {
        ResponseHdr::new(self.profile, err_code)
    }

    pub fn command_hdr(&self, cmd_id: u32) -> CommandHdr {
        CommandHdr::new(self.profile, cmd_id)
    }

    pub fn deserialize_command<'a>(&self, cmd: &'a [u8]) -> Result<Command<'a>, DpeErrorCode> {
        Command::deserialize(self.profile, cmd)
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
            if !handle.is_default() && !env.state.contexts.iter().any(|c| c.handle.equals(&handle))
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
        if !env.state.contexts[idx].handle.is_default() {
            env.state.contexts[idx].handle = self.generate_new_handle(env)?;
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(env.state.contexts[idx].handle.is_default());
        }
        Ok(())
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
        measurement: &Digest,
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

        let measurement = match (self.profile, measurement) {
            (DpeProfile::P256Sha256, Digest::Sha256(m)) => m.as_bytes(),
            (DpeProfile::P384Sha384, Digest::Sha384(m)) => m.as_bytes(),
            #[cfg(feature = "ml-dsa")]
            (DpeProfile::Mldsa87ExternalMu, Digest::Sha384(m)) => m.as_bytes(),
            _ => {
                return Err(DpeErrorCode::InvalidArgument);
            }
        };

        // Derive the new TCI as HASH(TCI_CUMULATIVE || INPUT_DATA).
        let mut hasher = env.crypto.hash_initialize()?;
        hasher.update(&context.tci.tci_cumulative.0)?;
        hasher.update(measurement)?;
        let digest = hasher.finish()?;

        let digest_bytes = digest.as_slice();

        if digest_bytes.len() != context.tci.tci_cumulative.0.len() {
            return Err(DpeErrorCode::InternalError);
        }
        context.tci.tci_cumulative.0.copy_from_slice(digest_bytes);
        context.tci.tci_current.0.copy_from_slice(measurement);
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
        support: Support,
        internal_input_info: &mut [u8; INTERNAL_INPUT_INFO_SIZE],
    ) -> Result<(), DpeErrorCode> {
        // Internal DPE Info contains get profile response fields as well as the profile
        let profile = self.get_profile(platform, support)?;
        let profile_bytes = profile.as_bytes();
        internal_input_info
            .get_mut(..profile_bytes.len())
            .ok_or(DpeErrorCode::InternalError)?
            .copy_from_slice(profile_bytes);

        internal_input_info
            .get_mut(profile_bytes.len()..)
            .ok_or(DpeErrorCode::InternalError)?
            .copy_from_slice(&(u32::from(self.profile)).to_le_bytes());

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
        let mut hasher = env.crypto.hash_initialize()?;

        let mut uses_internal_input_info = false;
        let mut uses_internal_input_dice = false;

        // Hash each node.
        for status in ChildToRootIter::new(start_idx, &env.state.contexts) {
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
            self.serialize_internal_input_info(
                &mut env.platform,
                env.state.support,
                &mut internal_input_info,
            )?;
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
    use crate::commands::DeriveContextFlags;
    #[cfg(feature = "ml-dsa")]
    use crate::commands::DeriveContextMldsaExternalMu87Cmd as DeriveContextCmd;
    #[cfg(feature = "p256")]
    use crate::commands::DeriveContextP256Cmd as DeriveContextCmd;
    #[cfg(feature = "p384")]
    use crate::commands::DeriveContextP384Cmd as DeriveContextCmd;
    use crate::response::NewHandleResp;
    use crate::support::test::SUPPORT;
    use crate::{DpeFlags, CURRENT_PROFILE_MAJOR_VERSION};
    use caliptra_cfi_lib_git::CfiCounter;
    use crypto::RustCryptoImpl;
    use platform::default::{DefaultPlatform, AUTO_INIT_LOCALITY};
    use zerocopy::IntoBytes;

    #[cfg(feature = "p256")]
    pub const DPE_PROFILE: DpeProfile = DpeProfile::P256Sha256;

    #[cfg(feature = "p384")]
    pub const DPE_PROFILE: DpeProfile = DpeProfile::P384Sha384;

    #[cfg(feature = "ml-dsa")]
    pub const DPE_PROFILE: DpeProfile = DpeProfile::Mldsa87ExternalMu;

    #[cfg(feature = "p256")]
    use crypto::Ecdsa256RustCrypto;

    #[cfg(feature = "p384")]
    use crypto::Ecdsa384RustCrypto;

    #[cfg(feature = "ml-dsa")]
    use crypto::MldsaRustCrypto;

    pub struct TestTypes;
    impl DpeTypes for TestTypes {
        #[cfg(feature = "p256")]
        type Crypto<'a> = Ecdsa256RustCrypto;

        #[cfg(feature = "p384")]
        type Crypto<'a> = Ecdsa384RustCrypto;

        #[cfg(feature = "ml-dsa")]
        type Crypto<'a> = MldsaRustCrypto;

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

    pub fn test_env(state: &mut State) -> DpeEnv<TestTypes> {
        DpeEnv::<TestTypes> {
            crypto: RustCryptoImpl::new(),
            platform: DEFAULT_PLATFORM,
            state,
        }
    }

    pub fn test_state() -> State {
        State::new(SUPPORT, DpeFlags::empty())
    }

    #[test]
    fn test_execute_serialized_command() {
        CfiCounter::reset_for_test();
        let mut state = test_state();
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

        assert_eq!(
            Response::GetProfile(GetProfileResp::new(
                dpe.profile,
                SUPPORT.bits(),
                env.platform.get_vendor_id().unwrap(),
                env.platform.get_vendor_sku().unwrap()
            )),
            dpe.execute_serialized_command(
                &mut env,
                TEST_LOCALITIES[0],
                dpe.command_hdr(Command::GET_PROFILE).as_bytes(),
            )
            .unwrap()
        );

        // The default context was initialized while creating the instance. Now lets create a
        // simulation context.
        let mut command = dpe
            .command_hdr(Command::INITIALIZE_CONTEXT)
            .as_bytes()
            .to_vec();
        command.extend(InitCtxCmd::new_simulation().as_bytes());
        assert_eq!(
            Response::InitCtx(NewHandleResp {
                handle: RANDOM_HANDLE,
                resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
            }),
            dpe.execute_serialized_command(&mut env, TEST_LOCALITIES[0], &command)
                .unwrap()
        );
    }

    #[test]
    fn test_get_profile() {
        CfiCounter::reset_for_test();
        let mut state = test_state();
        let mut env = test_env(&mut state);
        let dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();
        let profile = dpe
            .get_profile(&mut env.platform, env.state.support)
            .unwrap();
        assert_eq!(profile.major_version, CURRENT_PROFILE_MAJOR_VERSION);
        assert_eq!(profile.flags, SUPPORT.bits());
    }

    #[test]
    fn test_add_tci_measurement() {
        CfiCounter::reset_for_test();
        let mut state = State::new(Support::AUTO_INIT, DpeFlags::empty());
        let mut env = test_env(&mut state);
        let dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

        let data = [1; DPE_PROFILE.hash_size()];
        let mut context = env.state.contexts[0];
        dpe.add_tci_measurement(&mut env, &mut context, &data.into(), TEST_LOCALITIES[0])
            .unwrap();
        env.state.contexts[0] = context;
        assert_eq!(data, context.tci.tci_current.0);

        // Compute cumulative.
        let mut hasher = env.crypto.hash_initialize().unwrap();
        hasher.update(&[0; DPE_PROFILE.hash_size()]).unwrap();
        hasher.update(&data).unwrap();
        let first_cumulative = hasher.finish().unwrap();

        // Make sure the cumulative was computed correctly.
        assert_eq!(first_cumulative.as_slice(), context.tci.tci_cumulative.0);

        let data = [2; DPE_PROFILE.hash_size()];
        dpe.add_tci_measurement(&mut env, &mut context, &data.into(), TEST_LOCALITIES[0])
            .unwrap();
        // Make sure the current TCI was updated correctly.
        env.state.contexts[0] = context;
        assert_eq!(data, context.tci.tci_current.0);

        let mut hasher = env.crypto.hash_initialize().unwrap();
        hasher.update(first_cumulative.as_slice()).unwrap();
        hasher.update(&data).unwrap();
        let second_cumulative = hasher.finish().unwrap();

        // Make sure the cumulative was computed correctly.
        assert_eq!(second_cumulative.as_slice(), context.tci.tci_cumulative.0);
    }

    #[test]
    fn test_derive_cdi() {
        CfiCounter::reset_for_test();
        let mut state = test_state();
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

        let mut last_cdi = vec![];

        for i in 0..3 {
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [i; DPE_PROFILE.hash_size()],
                flags: DeriveContextFlags::MAKE_DEFAULT,
                tci_type: i as u32,
                target_locality: 0,
                svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap();

            // Check the CDI changes each time.
            let leaf_context_idx = env
                .state
                .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
                .unwrap();
            let digest = dpe
                .compute_measurement_hash(&mut env, leaf_context_idx)
                .unwrap();
            let curr_cdi = env.crypto.derive_cdi(&digest, b"DPE").unwrap();
            assert_ne!(last_cdi, curr_cdi);

            last_cdi = curr_cdi;
        }

        let mut hasher = env.crypto.hash_initialize().unwrap();
        let leaf_idx = env
            .state
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();

        for result in ChildToRootIter::new(leaf_idx, &env.state.contexts) {
            let context = result.unwrap();
            hasher.update(context.tci.as_bytes()).unwrap();
            hasher
                .update(/*allow_x509=*/ context.allow_x509().as_bytes())
                .unwrap();
        }

        let digest = hasher.finish().unwrap();
        let answer = env.crypto.derive_cdi(&digest, b"DPE").unwrap();
        assert_eq!(answer, last_cdi);
    }

    #[test]
    fn test_hash_internal_input_info() {
        CfiCounter::reset_for_test();
        let mut state = State::new(SUPPORT | Support::INTERNAL_INFO, DpeFlags::empty());
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

        let parent_context_idx = env
            .state
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();
        DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.hash_size()],
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INTERNAL_INPUT_INFO,
            tci_type: 0u32,
            target_locality: 0,
            svn: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap();

        let child_context_idx = env
            .state
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();
        let digest = dpe
            .compute_measurement_hash(&mut env, child_context_idx)
            .unwrap();
        let cdi_with_internal_input_info = env.crypto.derive_cdi(&digest, b"DPE").unwrap();
        let parent_context = &env.state.contexts[parent_context_idx];
        let child_context = &env.state.contexts[child_context_idx];
        assert!(child_context.uses_internal_input_info());
        assert!(!parent_context.uses_internal_input_info());

        let mut hasher = env.crypto.hash_initialize().unwrap();

        hasher.update(child_context.tci.as_bytes()).unwrap();
        hasher.update(/*allow_x509=*/ false.as_bytes()).unwrap();
        hasher.update(parent_context.tci.as_bytes()).unwrap();
        hasher.update(/*allow_x509=*/ true.as_bytes()).unwrap();
        let mut internal_input_info = [0u8; INTERNAL_INPUT_INFO_SIZE];
        dpe.serialize_internal_input_info(
            &mut env.platform,
            env.state.support,
            &mut internal_input_info,
        )
        .unwrap();

        hasher
            .update(&internal_input_info[..INTERNAL_INPUT_INFO_SIZE])
            .unwrap();

        let digest = hasher.finish().unwrap();
        let answer = env.crypto.derive_cdi(&digest, b"DPE").unwrap();
        assert_eq!(answer, cdi_with_internal_input_info);
    }

    #[test]
    fn test_hash_internal_input_dice() {
        CfiCounter::reset_for_test();
        let mut state = State::new(SUPPORT | Support::INTERNAL_DICE, DpeFlags::empty());
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

        let parent_context_idx = env
            .state
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();
        DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.hash_size()],
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INTERNAL_INPUT_DICE,
            tci_type: 0u32,
            target_locality: 0,
            svn: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap();

        let child_context_idx = env
            .state
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();
        let digest = dpe
            .compute_measurement_hash(&mut env, child_context_idx)
            .unwrap();
        let cdi_with_internal_input_dice = env.crypto.derive_cdi(&digest, b"DPE").unwrap();
        let parent_context = &env.state.contexts[parent_context_idx];
        let child_context = &env.state.contexts[child_context_idx];
        assert!(child_context.uses_internal_input_dice());
        assert!(!parent_context.uses_internal_input_dice());

        let mut hasher = env.crypto.hash_initialize().unwrap();

        hasher.update(child_context.tci.as_bytes()).unwrap();
        hasher.update(/*allow_x509=*/ false.as_bytes()).unwrap();
        hasher.update(parent_context.tci.as_bytes()).unwrap();
        hasher.update(/*allow_x509=*/ true.as_bytes()).unwrap();
        let cert_chain = env.platform.0.cert_chain();
        hasher.update(&cert_chain).unwrap();

        let digest = hasher.finish().unwrap();
        let answer = env.crypto.derive_cdi(&digest, b"DPE").unwrap();
        assert_eq!(answer, cdi_with_internal_input_dice)
    }

    #[test]
    fn test_new_auto_init() {
        CfiCounter::reset_for_test();
        let mut state = test_state();
        let mut env = test_env(&mut state);
        let tci_type = 0xdeadbeef_u32;
        let auto_init_measurement = [0x1; DPE_PROFILE.hash_size()];
        let auto_init_locality = env.platform.get_auto_init_locality().unwrap();
        let mut dpe = DpeInstance::new_auto_init(
            &mut env,
            DPE_PROFILE,
            tci_type,
            &auto_init_measurement.into(),
        )
        .unwrap();

        let idx = env
            .state
            .get_active_context_pos(&ContextHandle::default(), auto_init_locality)
            .unwrap();
        assert_eq!(env.state.contexts[idx].tci.tci_type, tci_type);
        assert_eq!(env.state.contexts[idx].tci.locality, auto_init_locality);
        assert_eq!(
            env.state.contexts[idx].tci.tci_current.0,
            auto_init_measurement
        );
        assert_eq!(env.state.contexts[idx].parent_idx, Context::ROOT_INDEX);
        assert_eq!(env.state.contexts[idx].children, 0);
        assert_eq!(env.state.contexts[idx].state, ContextState::Active);
        assert_eq!(env.state.contexts[idx].handle, ContextHandle::default());
        assert!(env.state.has_initialized());

        // check that initialize context fails if new_auto_init was used
        assert_eq!(
            InitCtxCmd::new_use_default().execute(&mut dpe, &mut env, auto_init_locality),
            Err(DpeErrorCode::ArgumentNotSupported)
        );
    }
}
