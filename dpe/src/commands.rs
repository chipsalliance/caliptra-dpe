/*++
Licensed under the Apache-2.0 license.

Abstract:
    DPE Commands and deserialization.
--*/
use crate::{response::DpeErrorCode, DPE_PROFILE, HANDLE_SIZE};
use core::mem::size_of;

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    GetProfile,
    InitCtx(InitCtxCmd),
    DestroyCtx(DestroyCtxCmd),
}

impl Command {
    const GET_PROFILE: u32 = 0x01;
    const INITIALIZE_CONTEXT: u32 = 0x05;
    const DERIVE_CHILD: u32 = 0x06;
    const CERTIFY_KEY: u32 = 0x07;
    const SIGN: u32 = 0x08;
    const ROTATE_CONTEXT_HANDLE: u32 = 0x0e;
    const DESTROY_CONTEXT: u32 = 0x0f;
    const GET_CERTIFICATE_CHAIN: u32 = 0x1000;
    const EXTEND_TCI: u32 = 0x1001;
    const TAG_TCI: u32 = 0x1002;
    const GET_TAGGED_TCI: u32 = 0x1003;

    /// Returns the command with its parameters given a slice of bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - serialized command
    pub fn deserialize(bytes: &[u8]) -> Result<Command, DpeErrorCode> {
        let cmd_header = CommandHdr::try_from(bytes)?;
        let bytes = &bytes[size_of::<CommandHdr>()..];

        match cmd_header.cmd_id {
            Command::GET_PROFILE => Ok(Command::GetProfile),
            Command::INITIALIZE_CONTEXT => Ok(Command::InitCtx(InitCtxCmd::try_from(bytes)?)),
            Command::DERIVE_CHILD => Err(DpeErrorCode::InvalidCommand),
            Command::CERTIFY_KEY => Err(DpeErrorCode::InvalidCommand),
            Command::SIGN => Err(DpeErrorCode::InvalidCommand),
            Command::ROTATE_CONTEXT_HANDLE => Err(DpeErrorCode::InvalidCommand),
            Command::DESTROY_CONTEXT => Ok(Command::DestroyCtx(DestroyCtxCmd::try_from(bytes)?)),
            Command::GET_CERTIFICATE_CHAIN => Err(DpeErrorCode::InvalidCommand),
            Command::EXTEND_TCI => Err(DpeErrorCode::InvalidCommand),
            Command::TAG_TCI => Err(DpeErrorCode::InvalidCommand),
            Command::GET_TAGGED_TCI => Err(DpeErrorCode::InvalidCommand),
            _ => Err(DpeErrorCode::InvalidCommand),
        }
    }
}

// ABI Command structures

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub struct CommandHdr {
    pub magic: u32,
    pub cmd_id: u32,
    pub profile: u32,
}

impl CommandHdr {
    const DPE_COMMAND_MAGIC: u32 = u32::from_be_bytes(*b"DPEC");
}

impl TryFrom<&[u8]> for CommandHdr {
    type Error = DpeErrorCode;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < size_of::<CommandHdr>() {
            return Err(DpeErrorCode::InvalidCommand);
        }

        let header = CommandHdr {
            magic: u32::from_le_bytes(raw[0..4].try_into().unwrap()),
            cmd_id: u32::from_le_bytes(raw[4..8].try_into().unwrap()),
            profile: u32::from_le_bytes(raw[8..12].try_into().unwrap()),
        };
        if header.magic != Self::DPE_COMMAND_MAGIC {
            return Err(DpeErrorCode::InvalidCommand);
        }
        // The client doesn't know what profile is implemented when calling the `GetProfile`
        // command. But, all other commands should be directed towards the correct profile.
        if header.cmd_id != Command::GET_PROFILE && header.profile != DPE_PROFILE as u32 {
            return Err(DpeErrorCode::InvalidCommand);
        }
        Ok(header)
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub struct InitCtxCmd {
    pub flags: u32,
}

impl InitCtxCmd {
    const SIMULATION_FLAG_MASK: u32 = 1 << 31;
    const DEFAULT_FLAG_MASK: u32 = 1 << 30;

    pub const fn new_use_default() -> InitCtxCmd {
        InitCtxCmd {
            flags: Self::DEFAULT_FLAG_MASK,
        }
    }

    pub const fn flag_is_simulation(&self) -> bool {
        self.flags & Self::SIMULATION_FLAG_MASK != 0
    }

    pub const fn flag_is_default(&self) -> bool {
        self.flags & Self::DEFAULT_FLAG_MASK != 0
    }

    #[cfg(test)]
    pub const fn new_simulation() -> InitCtxCmd {
        InitCtxCmd {
            flags: Self::SIMULATION_FLAG_MASK,
        }
    }
}

impl TryFrom<&[u8]> for InitCtxCmd {
    type Error = DpeErrorCode;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < size_of::<InitCtxCmd>() {
            return Err(DpeErrorCode::InvalidArgument);
        }
        Ok(InitCtxCmd {
            flags: u32::from_le_bytes(raw[0..4].try_into().unwrap()),
        })
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub struct DestroyCtxCmd {
    pub handle: [u8; HANDLE_SIZE],
    pub flags: u32,
}

impl DestroyCtxCmd {
    const DESTROY_CHILDREN_FLAG_MASK: u32 = 1 << 31;

    pub const fn flag_is_destroy_descendants(&self) -> bool {
        self.flags & Self::DESTROY_CHILDREN_FLAG_MASK != 0
    }
}

impl TryFrom<&[u8]> for DestroyCtxCmd {
    type Error = DpeErrorCode;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < size_of::<DestroyCtxCmd>() {
            return Err(DpeErrorCode::InvalidArgument);
        }

        let mut handle = [0; HANDLE_SIZE];
        handle.copy_from_slice(&raw[0..HANDLE_SIZE]);

        let raw = &raw[HANDLE_SIZE..];
        Ok(DestroyCtxCmd {
            handle,
            flags: u32::from_le_bytes(raw[0..4].try_into().unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpe_instance::tests::SIMULATION_HANDLE;
    use crate::DpeProfile;
    use std::vec;
    use std::vec::Vec;

    const DEFAULT_COMMAND: CommandHdr = CommandHdr {
        magic: CommandHdr::DPE_COMMAND_MAGIC,
        cmd_id: Command::GET_PROFILE,
        profile: DPE_PROFILE as u32,
    };
    const TEST_INIT_CTX_CMD: InitCtxCmd = InitCtxCmd { flags: 0x1234_5678 };
    const TEST_DESTROY_CTX_CMD: DestroyCtxCmd = DestroyCtxCmd {
        handle: SIMULATION_HANDLE,
        flags: 0x1234_5678,
    };

    #[test]
    fn test_deserialize() {
        // Commands that can be deserialized.
        assert_eq!(
            Ok(Command::GetProfile),
            Command::deserialize(&Vec::<u8>::from(CommandHdr::new(Command::GetProfile)))
        );

        // InitCtx
        {
            let mut command: Vec<u8> =
                Vec::<u8>::from(CommandHdr::new(Command::InitCtx(TEST_INIT_CTX_CMD)));
            command.extend(Vec::<u8>::from(TEST_INIT_CTX_CMD));
            assert_eq!(
                Ok(Command::InitCtx(TEST_INIT_CTX_CMD)),
                Command::deserialize(&command)
            );
        }

        // DestroyCtx
        {
            let mut command: Vec<u8> =
                Vec::<u8>::from(CommandHdr::new(Command::DestroyCtx(TEST_DESTROY_CTX_CMD)));
            command.extend(Vec::<u8>::from(TEST_DESTROY_CTX_CMD));
            assert_eq!(
                Ok(Command::DestroyCtx(TEST_DESTROY_CTX_CMD)),
                Command::deserialize(&command)
            );
        }

        // Commands that are not implemented.
        let invalid_command = Err(DpeErrorCode::InvalidCommand);
        assert_eq!(
            invalid_command,
            Command::deserialize(&Vec::<u8>::from(CommandHdr {
                cmd_id: Command::DERIVE_CHILD,
                ..DEFAULT_COMMAND
            }))
        );
        assert_eq!(
            invalid_command,
            Command::deserialize(&Vec::<u8>::from(CommandHdr {
                cmd_id: Command::CERTIFY_KEY,
                ..DEFAULT_COMMAND
            }))
        );
        assert_eq!(
            invalid_command,
            Command::deserialize(&Vec::<u8>::from(CommandHdr {
                cmd_id: Command::SIGN,
                ..DEFAULT_COMMAND
            }))
        );
        assert_eq!(
            invalid_command,
            Command::deserialize(&Vec::<u8>::from(CommandHdr {
                cmd_id: Command::ROTATE_CONTEXT_HANDLE,
                ..DEFAULT_COMMAND
            }))
        );
        assert_eq!(
            invalid_command,
            Command::deserialize(&Vec::<u8>::from(CommandHdr {
                cmd_id: Command::GET_CERTIFICATE_CHAIN,
                ..DEFAULT_COMMAND
            }))
        );
        assert_eq!(
            invalid_command,
            Command::deserialize(&Vec::<u8>::from(CommandHdr {
                cmd_id: Command::EXTEND_TCI,
                ..DEFAULT_COMMAND
            }))
        );
        assert_eq!(
            invalid_command,
            Command::deserialize(&Vec::<u8>::from(CommandHdr {
                cmd_id: Command::TAG_TCI,
                ..DEFAULT_COMMAND
            }))
        );
        assert_eq!(
            invalid_command,
            Command::deserialize(&Vec::<u8>::from(CommandHdr {
                cmd_id: Command::GET_TAGGED_TCI,
                ..DEFAULT_COMMAND
            }))
        );
    }

    #[test]
    fn test_slice_to_command_hdr() {
        let invalid_command: Result<CommandHdr, DpeErrorCode> = Err(DpeErrorCode::InvalidCommand);

        // Test if too small.
        assert_eq!(
            invalid_command,
            CommandHdr::try_from([0u8; size_of::<CommandHdr>() - 1].as_slice())
        );

        // Test wrong magic.
        assert_eq!(
            invalid_command,
            CommandHdr::try_from(
                Vec::<u8>::from(CommandHdr {
                    magic: 0,
                    ..DEFAULT_COMMAND
                })
                .as_slice()
            )
        );

        // Test wrong profile.
        #[cfg(feature = "dpe_profile_p256_sha256")]
        let wrong_profile = DpeProfile::P384Sha384 as u32;
        #[cfg(feature = "dpe_profile_p384_sha384")]
        let wrong_profile = DpeProfile::P256Sha256 as u32;

        // All commands should check the profile except GetProfile.
        assert_eq!(
            invalid_command,
            CommandHdr::try_from(
                Vec::<u8>::from(CommandHdr {
                    profile: wrong_profile,
                    cmd_id: Command::INITIALIZE_CONTEXT,
                    ..DEFAULT_COMMAND
                })
                .as_slice()
            )
        );

        // Make sure GetProfile doesn't care.
        assert!(CommandHdr::try_from(
            Vec::<u8>::from(CommandHdr {
                profile: wrong_profile,
                ..DEFAULT_COMMAND
            })
            .as_slice()
        )
        .is_ok());

        // Test correct command. Using random command ID to check endianness and consistency.
        const GOOD_HEADER: CommandHdr = CommandHdr {
            cmd_id: 0x8765_4321,
            ..DEFAULT_COMMAND
        };
        assert_eq!(
            GOOD_HEADER,
            CommandHdr::try_from(Vec::<u8>::from(GOOD_HEADER).as_slice()).unwrap()
        );
    }

    #[test]
    fn test_slice_to_init_ctx() {
        let invalid_argument: Result<InitCtxCmd, DpeErrorCode> = Err(DpeErrorCode::InvalidArgument);

        // Test if too small.
        assert_eq!(
            invalid_argument,
            InitCtxCmd::try_from([0u8; size_of::<InitCtxCmd>() - 1].as_slice())
        );

        assert_eq!(
            TEST_INIT_CTX_CMD,
            InitCtxCmd::try_from(Vec::<u8>::from(TEST_INIT_CTX_CMD).as_slice()).unwrap()
        );
    }

    #[test]
    fn test_slice_to_destroy_ctx() {
        let invalid_argument: Result<DestroyCtxCmd, DpeErrorCode> =
            Err(DpeErrorCode::InvalidArgument);

        // Test if too small.
        assert_eq!(
            invalid_argument,
            DestroyCtxCmd::try_from([0u8; size_of::<DestroyCtxCmd>() - 1].as_slice())
        );

        assert_eq!(
            TEST_DESTROY_CTX_CMD,
            DestroyCtxCmd::try_from(Vec::<u8>::from(TEST_DESTROY_CTX_CMD).as_slice()).unwrap()
        );
    }

    impl From<CommandHdr> for Vec<u8> {
        fn from(value: CommandHdr) -> Self {
            let mut raw = vec![];
            raw.extend_from_slice(&value.magic.to_le_bytes());
            raw.extend_from_slice(&value.cmd_id.to_le_bytes());
            raw.extend_from_slice(&value.profile.to_le_bytes());
            raw
        }
    }

    impl From<InitCtxCmd> for Vec<u8> {
        fn from(value: InitCtxCmd) -> Self {
            let mut raw = vec![];
            raw.extend_from_slice(&value.flags.to_le_bytes());
            raw
        }
    }

    impl From<DestroyCtxCmd> for Vec<u8> {
        fn from(value: DestroyCtxCmd) -> Self {
            let mut raw = vec![];
            raw.extend(value.handle);
            raw.extend_from_slice(&value.flags.to_le_bytes());
            raw
        }
    }

    impl CommandHdr {
        pub fn new(command: Command) -> CommandHdr {
            let cmd_id = match command {
                Command::GetProfile => Command::GET_PROFILE,
                Command::InitCtx(_) => Command::INITIALIZE_CONTEXT,
                Command::DestroyCtx(_) => Command::DESTROY_CONTEXT,
            };
            CommandHdr {
                magic: Self::DPE_COMMAND_MAGIC,
                cmd_id,
                profile: DPE_PROFILE as u32,
            }
        }
    }
}
