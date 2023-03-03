/*++
Licensed under the Apache-2.0 license.

Abstract:
    Defines an instance of DPE and all of its contexts.
--*/
use crate::{
    commands::{Command, InitCtxCmd},
    crypto::Crypto,
    profile,
    response::{DpeErrorCode, GetProfileResp, InitCtxResp, Response},
    HANDLE_SIZE, MAX_HANDLES,
};

pub struct DpeInstance<'a> {
    contexts: [Context; MAX_HANDLES],
    support: Support,
    crypto: &'a dyn Crypto,
}

impl DpeInstance<'_> {
    pub fn new(support: Support, crypto: &dyn Crypto) -> DpeInstance {
        const CONTEXT_INITIALIZER: Context = Context::new();
        DpeInstance {
            contexts: [CONTEXT_INITIALIZER; MAX_HANDLES],
            support,
            crypto,
        }
    }

    pub fn get_profile(&self) -> Result<GetProfileResp, DpeErrorCode> {
        Ok(GetProfileResp::new(self.support.get_flags()))
    }

    pub fn initialize_context(&mut self, _cmd: &InitCtxCmd) -> Result<InitCtxResp, DpeErrorCode> {
        let mut handle = [0u8; HANDLE_SIZE];
        // The first 4 bytes will be populated when this command is finished.
        self.crypto::rand_bytes(&mut handle[4..])?;
        Ok(InitCtxResp { handle })
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

#[derive(Default)]
pub struct Support {
    simulation: bool,
    extend_tci: bool,
    auto_init: bool,
    tagging: bool,
    rotate_context: bool,
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
    use crate::{
        commands::CommandHdr, crypto::tests::DeterministicCrypto, CURRENT_PROFILE_VERSION,
    };

    #[test]
    fn test_execute_serialized_command() {
        let mut dpe = DpeInstance::new(Support::default(), &DeterministicCrypto);

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
            Response::InitCtx(InitCtxResp {
                // The first 4 bytes will be populated when this command is finished.
                handle: [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
            }),
            dpe.execute_serialized_command(&command).unwrap()
        );
    }

    #[test]
    fn test_get_profile() {
        let dpe = DpeInstance::new(
            Support {
                simulation: true,
                ..Support::default()
            },
            &DeterministicCrypto,
        );
        let profile = dpe.get_profile().unwrap();
        assert_eq!(profile.version, CURRENT_PROFILE_VERSION);
        assert_eq!(profile.flags, 1 << 31);
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
