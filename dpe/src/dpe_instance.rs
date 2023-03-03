/*++
Licensed under the Apache-2.0 license.

Abstract:
    Defines an instance of DPE and all of its contexts.
--*/
use crate::{
    commands::{Command, InitCtxCmd},
    crypto::Crypto,
    response::{DpeErrorCode, GetProfileResp, InitCtxResp, Response},
    set_flag, DPE_PROFILE, HANDLE_SIZE, MAX_HANDLES,
};

pub struct DpeInstance {
    contexts: [Context; MAX_HANDLES],
    support: Support,
}

impl DpeInstance {
    const DEFAULT_CONTEXT_HANDLE: [u8; HANDLE_SIZE] = [0; HANDLE_SIZE];

    pub fn new<C: Crypto>(support: Support) -> DpeInstance {
        const CONTEXT_INITIALIZER: Context = Context::new();
        let mut dpe = DpeInstance {
            contexts: [CONTEXT_INITIALIZER; MAX_HANDLES],
            support,
        };

        if dpe.support.auto_init {
            dpe.initialize_context::<C>(&InitCtxCmd::new_use_default())
                .unwrap();
        }
        dpe
    }

    pub fn get_profile(&self) -> Result<GetProfileResp, DpeErrorCode> {
        Ok(GetProfileResp::new(self.support.get_flags()))
    }

    pub fn initialize_context<C: Crypto>(
        &mut self,
        cmd: &InitCtxCmd,
    ) -> Result<InitCtxResp, DpeErrorCode> {
        if (cmd.flag_is_default() && self.get_default_context().is_some())
            || (cmd.flag_is_simulation() && !self.support.simulation)
        {
            return Err(DpeErrorCode::ArgumentNotSupported);
        }

        // A flag must be set, but it can't be both flags. The base DPE CDI is locked for
        // non-simulation contexts once it is used once to prevent later software from accessing the
        // CDI.
        if !(cmd.flag_is_default() ^ cmd.flag_is_simulation()) {
            return Err(DpeErrorCode::InvalidArgument);
        }

        let context = self
            .get_next_inactive_context_mut()
            .ok_or(DpeErrorCode::MaxTcis)?;
        let handle = if cmd.flag_is_default() {
            Self::DEFAULT_CONTEXT_HANDLE
        } else {
            // Simulation.
            let mut handle = [0; HANDLE_SIZE];
            C::rand_bytes(&mut handle)?;
            handle
        };

        context.activate(&handle, cmd.flag_is_simulation());
        Ok(InitCtxResp { handle })
    }

    /// Deserializes the command and executes it.
    ///
    /// # Arguments
    ///
    /// * `cmd` - serialized command
    pub fn execute_serialized_command<C: Crypto>(
        &mut self,
        cmd: &[u8],
    ) -> Result<Response, DpeErrorCode> {
        let command = Command::deserialize(cmd)?;
        match command {
            Command::GetProfile => Ok(Response::GetProfile(self.get_profile()?)),
            Command::InitCtx(context) => {
                Ok(Response::InitCtx(self.initialize_context::<C>(&context)?))
            }
        }
    }

    fn get_next_inactive_context_mut(&mut self) -> Option<&mut Context> {
        self.contexts
            .iter_mut()
            .find(|context| context.state == ContextState::Inactive)
    }

    fn get_default_context(&mut self) -> Option<&mut Context> {
        self.contexts.iter_mut().find(|context| {
            matches!(context.state, ContextState::Active | ContextState::_Locked)
                && context.handle == Self::DEFAULT_CONTEXT_HANDLE
        })
    }
}

#[repr(transparent)]
pub struct TciMeasurement([u8; DPE_PROFILE.get_tci_size()]);

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
}

#[repr(C, align(4))]
#[derive(Default)]
struct TciNodeData {
    tci_type: u32,

    // Bits
    // 31: INTERNAL
    // 30-0: Reserved. Must be zero
    flags: u32,
    tci_cumulative: TciMeasurement,
    tci_current: TciMeasurement,
}

impl TciNodeData {
    const INTERNAL_FLAG_MASK: u32 = 1 << 31;

    const fn flag_is_internal(self) -> bool {
        self.flags & Self::INTERNAL_FLAG_MASK != 0
    }

    fn set_flag_is_internal(&mut self, value: bool) {
        set_flag(&mut self.flags, Self::INTERNAL_FLAG_MASK, value);
    }

    const fn new() -> TciNodeData {
        TciNodeData {
            tci_type: 0,
            flags: 0,
            tci_cumulative: TciMeasurement([0; DPE_PROFILE.get_tci_size()]),
            tci_current: TciMeasurement([0; DPE_PROFILE.get_tci_size()]),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ContextState {
    /// Inactive or uninitialized.
    Inactive,
    /// Context is initialized and ready to be used.
    Active,
    /// Only used for the default context. If the default context gets destroyed it cannot be
    /// re-initialized.
    _Locked,
}

#[repr(C, align(4))]
struct Context {
    handle: [u8; HANDLE_SIZE],
    tci: TciNodeData,
    // Bitmap of the node indices that are children of this node
    children: u32,
    // Index in DPE instance of the parent context. 0xFF if this node is the root
    parent_idx: u8,
    simulation: bool,
    state: ContextState,
}

impl Context {
    pub const ROOT_INDEX: u8 = 0xff;

    const fn new() -> Context {
        Context {
            handle: [0; HANDLE_SIZE],
            tci: TciNodeData::new(),
            children: 0,
            parent_idx: Self::ROOT_INDEX,
            simulation: false,
            state: ContextState::Inactive,
        }
    }
    pub fn activate(&mut self, handle: &[u8; HANDLE_SIZE], is_simulation: bool) {
        self.handle.copy_from_slice(handle);
        self.tci = TciNodeData::new();
        self.children = 0;
        self.parent_idx = Self::ROOT_INDEX;
        self.simulation = is_simulation;
        self.state = ContextState::Active;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::CommandHdr, crypto::tests::DeterministicCrypto, CURRENT_PROFILE_VERSION,
    };

    const SUPPORT: Support = Support {
        simulation: true,
        extend_tci: false,
        auto_init: true,
        tagging: false,
        rotate_context: false,
    };
    const SIMULATION_HANDLE: [u8; HANDLE_SIZE] =
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    #[test]
    fn test_execute_serialized_command() {
        let mut dpe = DpeInstance::new::<DeterministicCrypto>(SUPPORT);

        assert_eq!(
            Response::GetProfile(GetProfileResp::new(SUPPORT.get_flags())),
            dpe.execute_serialized_command::<DeterministicCrypto>(&Vec::<u8>::from(
                CommandHdr::new(Command::GetProfile)
            ))
            .unwrap()
        );

        // The default context was initialized while creating the instance. Now lets create a
        // simulation context.
        let mut command = Vec::<u8>::from(CommandHdr::new(Command::InitCtx(
            InitCtxCmd::new_simulation(),
        )));

        command.extend(Vec::<u8>::from(InitCtxCmd::new_simulation()));
        assert_eq!(
            Response::InitCtx(InitCtxResp {
                handle: SIMULATION_HANDLE
            }),
            dpe.execute_serialized_command::<DeterministicCrypto>(&command)
                .unwrap()
        );
    }

    #[test]
    fn test_get_profile() {
        let dpe = DpeInstance::new::<DeterministicCrypto>(SUPPORT);
        let profile = dpe.get_profile().unwrap();
        assert_eq!(profile.version, CURRENT_PROFILE_VERSION);
        assert_eq!(profile.flags, SUPPORT.get_flags());
    }

    #[test]
    fn test_initialize_context() {
        let mut dpe = DpeInstance::new::<DeterministicCrypto>(Support::default());

        // Make sure default context is 0x0.
        assert_eq!(
            DpeInstance::DEFAULT_CONTEXT_HANDLE,
            dpe.initialize_context::<DeterministicCrypto>(&InitCtxCmd::new_use_default())
                .unwrap()
                .handle
        );

        // Try to double initialize the default context.
        assert_eq!(
            DpeErrorCode::ArgumentNotSupported,
            dpe.initialize_context::<DeterministicCrypto>(&InitCtxCmd::new_use_default())
                .err()
                .unwrap()
        );

        // Try to initialize locked default context.
        dpe.get_default_context().unwrap().state = ContextState::_Locked;
        assert_eq!(
            DpeErrorCode::ArgumentNotSupported,
            dpe.initialize_context::<DeterministicCrypto>(&InitCtxCmd::new_use_default())
                .err()
                .unwrap()
        );

        // Try not setting any flags.
        assert_eq!(
            DpeErrorCode::InvalidArgument,
            dpe.initialize_context::<DeterministicCrypto>(&InitCtxCmd { flags: 0 })
                .err()
                .unwrap()
        );

        // Try simulation when not supported.
        assert_eq!(
            DpeErrorCode::ArgumentNotSupported,
            dpe.initialize_context::<DeterministicCrypto>(&InitCtxCmd::new_simulation())
                .err()
                .unwrap()
        );

        // Change to support simulation.
        let mut dpe = DpeInstance::new::<DeterministicCrypto>(Support {
            simulation: true,
            ..Support::default()
        });

        // Try setting both flags.
        assert_eq!(
            DpeErrorCode::InvalidArgument,
            dpe.initialize_context::<DeterministicCrypto>(&InitCtxCmd { flags: 3 << 30 })
                .err()
                .unwrap()
        );

        // Initialize all of the contexts except the default.
        for _ in 0..MAX_HANDLES {
            assert_eq!(
                SIMULATION_HANDLE,
                dpe.initialize_context::<DeterministicCrypto>(&InitCtxCmd::new_simulation())
                    .unwrap()
                    .handle
            );
        }

        // Try to initilize one more.
        assert_eq!(
            DpeErrorCode::MaxTcis,
            dpe.initialize_context::<DeterministicCrypto>(&InitCtxCmd::new_simulation())
                .err()
                .unwrap()
        );
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
        // Supports a couple combos.
        let flags = Support {
            simulation: true,
            auto_init: true,
            rotate_context: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, (1 << 31) | (1 << 29) | (1 << 27));
        let flags = Support {
            extend_tci: true,
            tagging: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, (1 << 30) | (1 << 28));
        // Supports everything.
        let flags = Support {
            simulation: true,
            extend_tci: true,
            auto_init: true,
            tagging: true,
            rotate_context: true,
        }
        .get_flags();
        assert_eq!(
            flags,
            (1 << 31) | (1 << 30) | (1 << 29) | (1 << 28) | (1 << 27)
        );
    }
}
