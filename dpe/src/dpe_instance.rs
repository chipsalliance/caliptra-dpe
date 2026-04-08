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
    tci::TciMeasurement,
    DpeProfile, State, MAX_HANDLES,
};
#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_lib::cfi_launder;
#[cfg(feature = "cfi")]
use caliptra_cfi_lib::{cfi_assert, cfi_assert_bool, cfi_assert_eq};
use caliptra_dpe_crypto::{CryptoSuite, Digest};
use caliptra_dpe_platform::Platform;
#[cfg(not(feature = "disable_internal_dice"))]
use caliptra_dpe_platform::MAX_CHUNK_SIZE;
use cfg_if::cfg_if;
use zerocopy::IntoBytes;

pub trait DpeEnv {
    fn crypto(&mut self) -> &mut dyn CryptoSuite;
    fn platform(&mut self) -> &mut dyn Platform;
    fn state(&mut self) -> &mut State;
    fn get(&mut self) -> (&mut dyn CryptoSuite, &mut dyn Platform, &mut State);
}

pub struct DpeEnvImpl<'a> {
    pub crypto: &'a mut dyn CryptoSuite,
    pub platform: &'a mut dyn Platform,
    pub state: &'a mut State,
}

impl DpeEnv for DpeEnvImpl<'_> {
    fn crypto(&mut self) -> &mut dyn CryptoSuite {
        self.crypto
    }
    fn platform(&mut self) -> &mut dyn Platform {
        self.platform
    }
    fn state(&mut self) -> &mut State {
        self.state
    }
    fn get(&mut self) -> (&mut dyn CryptoSuite, &mut dyn Platform, &mut State) {
        (self.crypto, self.platform, self.state)
    }
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
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    pub fn new(env: &mut dyn DpeEnv, profile: DpeProfile) -> Result<Self, DpeErrorCode> {
        let mut dpe = Self::initialized(profile);

        if env.state().support.auto_init() {
            let locality = env.platform().get_auto_init_locality()?;
            InitCtxCmd::new_use_default().execute(&mut dpe, env, locality)?;
        } else {
            #[cfg(feature = "cfi")]
            cfi_assert!(!env.state().support.auto_init());
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
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[cfg(not(feature = "disable_auto_init"))]
    pub fn new_auto_init(
        env: &mut dyn DpeEnv,
        profile: DpeProfile,
        tci_type: u32,
        auto_init_measurement: &TciMeasurement,
    ) -> Result<Self, DpeErrorCode> {
        // auto-init must be supported to add an auto init measurement
        if !env.state().support.auto_init() {
            return Err(DpeErrorCode::ArgumentNotSupported);
        } else {
            #[cfg(feature = "cfi")]
            cfi_assert!(env.state().support.auto_init());
        }
        let dpe = Self::new(env, profile)?;

        let locality = env.platform().get_auto_init_locality()?;
        let idx = env
            .state()
            .get_active_context_pos(&ContextHandle::default(), locality)?;
        let mut tmp_context = env.state().contexts[idx];
        // add measurement to auto-initialized context
        dpe.add_tci_measurement(env, &mut tmp_context, auto_init_measurement, locality)?;
        env.state().contexts[idx] = tmp_context;
        env.state().contexts[idx].tci.tci_type = tci_type;
        Ok(dpe)
    }

    pub fn get_profile(
        &self,
        platform: &mut dyn Platform,
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
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    pub fn execute_serialized_command(
        &mut self,
        env: &mut dyn DpeEnv,
        locality: u32,
        cmd: &[u8],
    ) -> Result<Response, DpeErrorCode> {
        let command = self.deserialize_command(cmd)?;
        #[cfg(feature = "cfi")]
        let command = cfi_launder(command);
        let resp = match command {
            Command::GetProfile(cmd) => cmd.execute(self, env, locality),
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
        env: &mut dyn DpeEnv,
    ) -> Result<ContextHandle, DpeErrorCode> {
        for _ in 0..Self::MAX_NEW_HANDLE_ATTEMPTS {
            let mut handle = ContextHandle::default();
            env.crypto().rand_bytes(&mut handle.0)?;
            if !handle.is_default()
                && !env
                    .state()
                    .contexts
                    .iter()
                    .any(|c| c.handle.equals(&handle))
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
        env: &mut dyn DpeEnv,
        idx: usize,
    ) -> Result<(), DpeErrorCode> {
        if idx >= MAX_HANDLES {
            return Err(DpeErrorCode::MaxTcis);
        }
        if !env.state().contexts[idx].handle.is_default() {
            env.state().contexts[idx].handle = self.generate_new_handle(env)?;
        } else {
            #[cfg(feature = "cfi")]
            cfi_assert!(env.state().contexts[idx].handle.is_default());
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
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    pub(crate) fn add_tci_measurement(
        &self,
        env: &mut dyn DpeEnv,
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
            if #[cfg(feature = "cfi")] {
                cfi_assert_eq(context.state, ContextState::Active);
                cfi_assert_eq(context.locality, locality);
            }
        }

        // Derive the new TCI as HASH(TCI_CUMULATIVE || INPUT_DATA).
        let digest = env
            .crypto()
            .hash_all(&[&context.tci.tci_cumulative.0, &measurement.0])?;

        let digest_bytes = digest.as_slice();

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
        platform: &mut dyn Platform,
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
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    pub(crate) fn compute_measurement_hash(
        &mut self,
        env: &mut dyn DpeEnv,
        start_idx: usize,
    ) -> Result<Digest, DpeErrorCode> {
        let (crypto, platform, state) = env.get();
        let hasher = crypto.hasher()?;
        hasher.initialize()?;

        let mut uses_internal_input_info = false;
        let mut uses_internal_input_dice = false;

        // Hash each node.
        for status in ChildToRootIter::new(start_idx, &state.contexts) {
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
            self.serialize_internal_input_info(platform, state.support, &mut internal_input_info)?;
            hasher.update(&internal_input_info[..INTERNAL_INPUT_INFO_SIZE])?;
        }

        // Add internal input dice to hash
        #[cfg(not(feature = "disable_internal_dice"))]
        if cfi_launder(uses_internal_input_dice) {
            let mut offset = 0;
            let mut cert_chunk = [0u8; MAX_CHUNK_SIZE];
            while let Ok(len) =
                platform.get_certificate_chain(offset, MAX_CHUNK_SIZE as u32, &mut cert_chunk)
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
pub(crate) fn flags_iter(flags: u64, max: usize) -> FlagsIter {
    assert!((1..=u64::BITS).contains(&(max as u32)));
    FlagsIter {
        flags: flags & (u64::MAX >> (u64::BITS - max as u32)),
    }
}

pub(crate) struct FlagsIter {
    flags: u64,
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
    use crate::tci::TciMeasurement;
    use crate::{DpeFlags, CURRENT_PROFILE_MAJOR_VERSION};
    use caliptra_cfi_lib::CfiCounter;
    use caliptra_dpe_crypto::RustCryptoImpl;
    use caliptra_dpe_platform::default::AUTO_INIT_LOCALITY;
    use zerocopy::IntoBytes;

    #[cfg(feature = "p256")]
    pub const DPE_PROFILE: DpeProfile = DpeProfile::P256Sha256;

    #[cfg(feature = "p384")]
    pub const DPE_PROFILE: DpeProfile = DpeProfile::P384Sha384;

    #[cfg(feature = "ml-dsa")]
    pub const DPE_PROFILE: DpeProfile = DpeProfile::Mldsa87;

    #[cfg(feature = "p256")]
    pub fn new_crypto() -> RustCryptoImpl {
        RustCryptoImpl::new_ecc256()
    }
    #[cfg(feature = "p384")]
    pub fn new_crypto() -> RustCryptoImpl {
        RustCryptoImpl::new_ecc384()
    }
    #[cfg(feature = "ml-dsa")]
    pub fn new_crypto() -> RustCryptoImpl {
        RustCryptoImpl::new_mldsa87()
    }

    pub const TEST_HANDLE: ContextHandle =
        ContextHandle([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    pub const SIMULATION_HANDLE: ContextHandle =
        ContextHandle([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    pub const RANDOM_HANDLE: ContextHandle = ContextHandle([
        51, 1, 232, 215, 231, 84, 219, 44, 245, 123, 10, 76, 167, 63, 37, 60,
    ]);

    pub const TEST_LOCALITIES: [u32; 2] = [AUTO_INIT_LOCALITY, u32::from_be_bytes(*b"OTHR")];

    #[macro_export]
    macro_rules! test_env {
        ($env_name:ident, $state:expr) => {
            let mut crypto = $crate::dpe_instance::tests::new_crypto();
            let mut platform = $crate::commands::tests::DEFAULT_PLATFORM;
            let mut $env_name = $crate::dpe_instance::DpeEnvImpl {
                crypto: &mut crypto,
                platform: &mut platform,
                state: $state,
            };
        };
    }

    pub fn test_state() -> State {
        State::new(SUPPORT, DpeFlags::empty())
    }

    #[test]
    fn test_execute_serialized_command() {
        CfiCounter::reset_for_test();
        let mut state = test_state();
        test_env!(env, &mut state);
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
        test_env!(env, &mut state);
        let dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();
        let mut default_platform = DEFAULT_PLATFORM;
        let profile = dpe.get_profile(&mut default_platform, SUPPORT).unwrap();
        assert_eq!(profile.major_version, CURRENT_PROFILE_MAJOR_VERSION);
        assert_eq!(profile.flags, SUPPORT.bits());
    }

    #[test]
    fn test_add_tci_measurement() {
        CfiCounter::reset_for_test();
        let mut state = State::new(Support::AUTO_INIT, DpeFlags::empty());
        test_env!(env, &mut state);
        let dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

        let data = [1; DPE_PROFILE.hash_size()];
        let mut context = env.state.contexts[0];
        dpe.add_tci_measurement(
            &mut env,
            &mut context,
            &TciMeasurement(data),
            TEST_LOCALITIES[0],
        )
        .unwrap();
        env.state.contexts[0] = context;
        assert_eq!(data, context.tci.tci_current.0);

        // Compute cumulative.
        let first_cumulative = env
            .crypto
            .hash_all(&[&[0; DPE_PROFILE.hash_size()], &data])
            .unwrap();

        // Make sure the cumulative was computed correctly.
        assert_eq!(first_cumulative.as_slice(), context.tci.tci_cumulative.0);

        let data = [2; DPE_PROFILE.hash_size()];
        dpe.add_tci_measurement(
            &mut env,
            &mut context,
            &TciMeasurement(data),
            TEST_LOCALITIES[0],
        )
        .unwrap();
        // Make sure the current TCI was updated correctly.
        env.state.contexts[0] = context;
        assert_eq!(data, context.tci.tci_current.0);

        let second_cumulative = env
            .crypto
            .hash_all(&[&first_cumulative.as_slice(), &data])
            .unwrap();

        // Make sure the cumulative was computed correctly.
        assert_eq!(second_cumulative.as_slice(), context.tci.tci_cumulative.0);
    }

    #[test]
    fn test_derive_cdi() {
        CfiCounter::reset_for_test();
        let mut state = test_state();
        test_env!(env, &mut state);
        let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

        let mut last_cdi = vec![];

        for i in 0..3 {
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: TciMeasurement([i; DPE_PROFILE.hash_size()]),
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
            let curr_cdi = env
                .crypto
                .derive_cdi(&digest, b"DPE")
                .unwrap()
                .as_slice()
                .to_vec();
            assert_ne!(last_cdi, curr_cdi);

            last_cdi = curr_cdi;
        }

        let leaf_idx = env
            .state
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();

        let (crypto, _platform, state) = env.get();
        let digest = crypto
            .with_hasher(&|hasher| {
                for result in ChildToRootIter::new(leaf_idx, &state.contexts) {
                    let context = result.unwrap();
                    hasher.update(context.tci.as_bytes()).unwrap();
                    hasher
                        .update(/*allow_x509=*/ context.allow_x509().as_bytes())
                        .unwrap();
                }
                Ok(())
            })
            .unwrap();

        let answer = crypto
            .derive_cdi(&digest, b"DPE")
            .unwrap()
            .as_slice()
            .to_vec();
        assert_eq!(answer, last_cdi);
    }

    #[test]
    fn test_hash_internal_input_info() {
        CfiCounter::reset_for_test();
        let mut state = State::new(SUPPORT | Support::INTERNAL_INFO, DpeFlags::empty());
        test_env!(env, &mut state);
        let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

        let parent_context_idx = env
            .state
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();
        DeriveContextCmd {
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INTERNAL_INPUT_INFO,
            ..Default::default()
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
        let cdi_with_internal_input_info = env
            .crypto
            .derive_cdi(&digest, b"DPE")
            .unwrap()
            .as_slice()
            .to_vec();
        let parent_context = &env.state.contexts[parent_context_idx];
        let child_context = &env.state.contexts[child_context_idx];
        assert!(child_context.uses_internal_input_info());
        assert!(!parent_context.uses_internal_input_info());

        let mut internal_input_info = [0u8; INTERNAL_INPUT_INFO_SIZE];
        let mut default_platform = DEFAULT_PLATFORM;
        dpe.serialize_internal_input_info(
            &mut default_platform,
            env.state.support,
            &mut internal_input_info,
        )
        .unwrap();

        let digest = env
            .crypto
            .hash_all(&[
                &child_context.tci.as_bytes(),
                /*allow_x509=*/ &false.as_bytes(),
                &parent_context.tci.as_bytes(),
                /*allow_x509=*/ &true.as_bytes(),
                &&internal_input_info[..INTERNAL_INPUT_INFO_SIZE],
            ])
            .unwrap();
        let answer = env
            .crypto
            .derive_cdi(&digest, b"DPE")
            .unwrap()
            .as_slice()
            .to_vec();
        assert_eq!(answer, cdi_with_internal_input_info);
    }

    #[test]
    fn test_hash_internal_input_dice() {
        CfiCounter::reset_for_test();
        let mut state = State::new(SUPPORT | Support::INTERNAL_DICE, DpeFlags::empty());
        test_env!(env, &mut state);
        let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

        let parent_context_idx = env
            .state
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();
        DeriveContextCmd {
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INTERNAL_INPUT_DICE,
            ..Default::default()
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
        let cdi_with_internal_input_dice = env
            .crypto
            .derive_cdi(&digest, b"DPE")
            .unwrap()
            .as_slice()
            .to_vec();
        let parent_context = &env.state.contexts[parent_context_idx];
        let child_context = &env.state.contexts[child_context_idx];
        assert!(child_context.uses_internal_input_dice());
        assert!(!parent_context.uses_internal_input_dice());

        let cert_chain = DEFAULT_PLATFORM.0.cert_chain();
        let digest = env
            .crypto
            .hash_all(&[
                &child_context.tci.as_bytes(),
                /*allow_x509=*/ &false.as_bytes(),
                &parent_context.tci.as_bytes(),
                /*allow_x509=*/ &true.as_bytes(),
                &cert_chain,
            ])
            .unwrap();
        let answer = env
            .crypto
            .derive_cdi(&digest, b"DPE")
            .unwrap()
            .as_slice()
            .to_vec();
        assert_eq!(answer, cdi_with_internal_input_dice)
    }

    #[test]
    fn test_new_auto_init() {
        CfiCounter::reset_for_test();
        let mut state = test_state();
        test_env!(env, &mut state);
        let tci_type = 0xdeadbeef_u32;
        let auto_init_measurement = [0x1; DPE_PROFILE.hash_size()];
        let auto_init_locality = env.platform.get_auto_init_locality().unwrap();
        let mut dpe = DpeInstance::new_auto_init(
            &mut env,
            DPE_PROFILE,
            tci_type,
            &TciMeasurement(auto_init_measurement),
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
        assert!(env.state.contexts[idx].children.is_empty());
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
