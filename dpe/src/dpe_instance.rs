/*++
Licensed under the Apache-2.0 license.

Abstract:
    Defines an instance of DPE and all of its contexts.
--*/
use crate::{
    commands::{Command, InitCtxCmd},
    profile,
    response::{DpeErrorCode, GetProfileResp, InitCtxResp, Response},
    MAX_HANDLES,
};

pub struct DpeInstance {
    contexts: [Context; MAX_HANDLES],
    supports_simulation: bool,
    supports_extend_tci: bool,
    supports_auto_init: bool,
    supports_tagging: bool,
    supports_rotate_context: bool,
}

impl DpeInstance {
    pub fn new(
        supports_simulation: bool,
        supports_extend_tci: bool,
        supports_auto_init: bool,
        supports_tagging: bool,
        supports_rotate_context: bool,
    ) -> DpeInstance {
        const CONTEXT_INITIALIZER: Context = Context::new();
        DpeInstance {
            contexts: [CONTEXT_INITIALIZER; MAX_HANDLES],
            supports_simulation,
            supports_extend_tci,
            supports_auto_init,
            supports_tagging,
            supports_rotate_context,
        }
    }

    pub fn get_profile(&self) -> Result<GetProfileResp, DpeErrorCode> {
        const SIMULATION_MASK: u32 = 1 << 31;
        const EXTEND_TCI_MASK: u32 = 1 << 30;
        const AUTO_INIT_MASK: u32 = 1 << 29;
        const TAGGING_MASK: u32 = 1 << 28;
        const ROTATE_CONTEXT_MASK: u32 = 1 << 27;

        let mut flags = 0;
        set_flag(&mut flags, SIMULATION_MASK, self.supports_simulation);
        set_flag(&mut flags, EXTEND_TCI_MASK, self.supports_extend_tci);
        set_flag(&mut flags, AUTO_INIT_MASK, self.supports_auto_init);
        set_flag(&mut flags, TAGGING_MASK, self.supports_tagging);
        set_flag(
            &mut flags,
            ROTATE_CONTEXT_MASK,
            self.supports_rotate_context,
        );
        Ok(GetProfileResp::new(flags))
    }

    pub fn initialize_context(&mut self, _cmd: &InitCtxCmd) -> Result<InitCtxResp, DpeErrorCode> {
        Ok(InitCtxResp { handle: [0; 20] })
    }

    /// Deserializes the command and executes it.
    ///
    /// # Arguments
    ///
    /// * `cmd` - serialized command
    pub fn execute_serialized_command(&mut self, cmd: &[u8]) -> Result<Response, DpeErrorCode> {
        let command = Command::deserialize(cmd)?;
        match command {
            Command::GetProfile => Ok(Response::GetProfile(self.get_profile()?)),
            Command::InitCtx(context) => Ok(Response::InitCtx(self.initialize_context(&context)?)),
        }
    }
}

#[repr(transparent)]
pub struct TciMeasurement([u8; profile::TCI_SIZE]);

impl Default for TciMeasurement {
    fn default() -> Self {
        Self([0; profile::TCI_SIZE])
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
            tci_cumulative: TciMeasurement([0; profile::TCI_SIZE]),
            tci_current: TciMeasurement([0; profile::TCI_SIZE]),
        }
    }
}

#[repr(C, align(4))]
struct Context {
    tci: TciNodeData,
    // Bitmap of the node indices that are children of this node
    children: u32,
    // Index in DPE instance of the parent context. 0xFF if this node is the root
    parent_idx: u8,
    simulation: bool,
    is_active: bool,
}

impl Context {
    const fn new() -> Context {
        Context {
            tci: TciNodeData::new(),
            children: 0,
            parent_idx: 0xFF,
            simulation: false,
            is_active: false,
        }
    }
}

fn set_flag(field: &mut u32, mask: u32, value: bool) {
    *field = if value { *field | mask } else { *field & !mask };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CURRENT_PROFILE_VERSION;


    #[test]
    fn test_execute_serialized_command() {
        let mut dpe = DpeInstance::new();

        assert_eq!(
            Response::GetProfile(GetProfileResp::new(0)),
            dpe.execute_serialized_command(&Vec::<u8>::from(CommandHdr::new(Command::GetProfile)))
                .unwrap()
        );

        // Using random flags to check endianness and consistency.
        const GOOD_CONTEXT: InitCtxCmd = InitCtxCmd { flags: 0x1234_5678 };
        let mut command = Vec::<u8>::from(CommandHdr::new(Command::InitCtx(GOOD_CONTEXT)));

        command.extend(Vec::<u8>::from(GOOD_CONTEXT));
        assert_eq!(
            Response::InitCtx(InitCtxResp { handle: [0; 20] }),
            dpe.execute_serialized_command(&command).unwrap()
        );
    }

    #[test]
    fn test_get_profile() {
        let dpe = DpeInstance::new(false, false, false, false, false);
        let profile = dpe.get_profile().unwrap();
        assert_eq!(profile.version, CURRENT_PROFILE_VERSION);
        assert_eq!(profile.flags, 0);

        // Supports simulation flag.
        let profile = DpeInstance::new(true, false, false, false, false)
            .get_profile()
            .unwrap();
        assert_eq!(profile.flags, 1 << 31);
        // Supports extended TCI flag.
        let profile = DpeInstance::new(false, true, false, false, false)
            .get_profile()
            .unwrap();
        assert_eq!(profile.flags, 1 << 30);
        // Supports auto-init.
        let profile = DpeInstance::new(false, false, true, false, false)
            .get_profile()
            .unwrap();
        assert_eq!(profile.flags, 1 << 29);
        // Supports tagging.
        let profile = DpeInstance::new(false, false, false, true, false)
            .get_profile()
            .unwrap();
        assert_eq!(profile.flags, 1 << 28);
        // Supports rotate context.
        let profile = DpeInstance::new(false, false, false, false, true)
            .get_profile()
            .unwrap();
        assert_eq!(profile.flags, 1 << 27);
        // Supports a couple combos.
        let profile = DpeInstance::new(true, false, true, false, true)
            .get_profile()
            .unwrap();
        assert_eq!(profile.flags, (1 << 31) | (1 << 29) | (1 << 27));
        let profile = DpeInstance::new(false, true, false, true, false)
            .get_profile()
            .unwrap();
        assert_eq!(profile.flags, (1 << 30) | (1 << 28));
        // Supports everything.
        let profile = DpeInstance::new(true, true, true, true, true)
            .get_profile()
            .unwrap();
        assert_eq!(
            profile.flags,
            (1 << 31) | (1 << 30) | (1 << 29) | (1 << 28) | (1 << 27)
        );
    }
}
