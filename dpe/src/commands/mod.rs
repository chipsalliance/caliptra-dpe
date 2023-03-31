/*++
Licensed under the Apache-2.0 license.

Abstract:
    DPE Commands and deserialization.
--*/
pub(crate) use self::destroy_context::DestroyCtxCmd;
pub(crate) use self::initialize_context::InitCtxCmd;

use self::certify_key::CertifyKeyCmd;
use self::derive_child::DeriveChildCmd;
use self::extend_tci::ExtendTciCmd;
use self::rotate_context::RotateCtxCmd;
use self::tag_tci::TagTciCmd;

use crate::{
    dpe_instance::DpeInstance,
    response::{DpeErrorCode, Response},
    DPE_PROFILE,
};
use core::mem::size_of;
use crypto::Crypto;

mod certify_key;
mod derive_child;
mod destroy_context;
mod extend_tci;
mod initialize_context;
mod rotate_context;
mod tag_tci;

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    GetProfile,
    InitCtx(InitCtxCmd),
    DeriveChild(DeriveChildCmd),
    CertifyKey(CertifyKeyCmd),
    RotateCtx(RotateCtxCmd),
    DestroyCtx(DestroyCtxCmd),
    ExtendTci(ExtendTciCmd),
    TagTci(TagTciCmd),
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
            Command::CERTIFY_KEY => Ok(Command::CertifyKey(CertifyKeyCmd::try_from(bytes)?)),
            Command::SIGN => Err(DpeErrorCode::InvalidCommand),
            Command::ROTATE_CONTEXT_HANDLE => {
                Ok(Command::RotateCtx(RotateCtxCmd::try_from(bytes)?))
            }
            Command::DESTROY_CONTEXT => Ok(Command::DestroyCtx(DestroyCtxCmd::try_from(bytes)?)),
            Command::GET_CERTIFICATE_CHAIN => Err(DpeErrorCode::InvalidCommand),
            Command::EXTEND_TCI => Ok(Command::ExtendTci(ExtendTciCmd::try_from(bytes)?)),
            Command::TAG_TCI => Ok(Command::TagTci(TagTciCmd::try_from(bytes)?)),
            Command::GET_TAGGED_TCI => Err(DpeErrorCode::InvalidCommand),
            _ => Err(DpeErrorCode::InvalidCommand),
        }
    }
}

pub trait CommandExecution<C: Crypto> {
    fn execute(&self, dpe: &mut DpeInstance<C>, locality: u32) -> Result<Response, DpeErrorCode>;
}

// ABI Command structures

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(zerocopy::AsBytes, zerocopy::FromBytes))]
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{DpeProfile, DPE_PROFILE};
    use zerocopy::{AsBytes, FromBytes};

    #[cfg(feature = "dpe_profile_p256_sha256")]
    pub const TEST_DIGEST: [u8; DPE_PROFILE.get_hash_size()] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    #[cfg(feature = "dpe_profile_p384_sha384")]
    pub const TEST_DIGEST: [u8; DPE_PROFILE.get_hash_size()] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
    ];

    const DEFAULT_COMMAND: CommandHdr = CommandHdr {
        magic: CommandHdr::DPE_COMMAND_MAGIC,
        cmd_id: Command::GET_PROFILE,
        profile: DPE_PROFILE as u32,
    };

    #[test]
    fn try_from_cmd_hdr() {
        let command_bytes = DEFAULT_COMMAND.as_bytes();
        assert_eq!(
            CommandHdr::read_from_prefix(command_bytes).unwrap(),
            CommandHdr::try_from(command_bytes).unwrap(),
        );
    }

    #[test]
    fn test_deserialize_get_profile() {
        // Commands that can be deserialized.
        assert_eq!(
            Ok(Command::GetProfile),
            Command::deserialize(CommandHdr::new(Command::GetProfile).as_bytes())
        );
    }

    #[test]
    fn test_deserialize_unsupported_commands() {
        // Commands that are not implemented.
        let invalid_command = Err(DpeErrorCode::InvalidCommand);
        assert_eq!(
            invalid_command,
            Command::deserialize(
                CommandHdr {
                    cmd_id: Command::DERIVE_CHILD,
                    ..DEFAULT_COMMAND
                }
                .as_bytes()
            )
        );
        assert_eq!(
            invalid_command,
            Command::deserialize(
                CommandHdr {
                    cmd_id: Command::SIGN,
                    ..DEFAULT_COMMAND
                }
                .as_bytes()
            )
        );
        assert_eq!(
            invalid_command,
            Command::deserialize(
                CommandHdr {
                    cmd_id: Command::GET_CERTIFICATE_CHAIN,
                    ..DEFAULT_COMMAND
                }
                .as_bytes()
            )
        );
        assert_eq!(
            invalid_command,
            Command::deserialize(
                CommandHdr {
                    cmd_id: Command::GET_TAGGED_TCI,
                    ..DEFAULT_COMMAND
                }
                .as_bytes()
            )
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
                CommandHdr {
                    magic: 0,
                    ..DEFAULT_COMMAND
                }
                .as_bytes()
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
                CommandHdr {
                    profile: wrong_profile,
                    cmd_id: Command::INITIALIZE_CONTEXT,
                    ..DEFAULT_COMMAND
                }
                .as_bytes()
            )
        );

        // Make sure GetProfile doesn't care.
        assert!(CommandHdr::try_from(
            CommandHdr {
                profile: wrong_profile,
                ..DEFAULT_COMMAND
            }
            .as_bytes()
        )
        .is_ok());

        // Test correct command. Using random command ID to check endianness and consistency.
        const GOOD_HEADER: CommandHdr = CommandHdr {
            cmd_id: 0x8765_4321,
            ..DEFAULT_COMMAND
        };
        assert_eq!(
            GOOD_HEADER,
            CommandHdr::try_from(GOOD_HEADER.as_bytes()).unwrap()
        );
    }

    impl CommandHdr {
        pub fn new(command: Command) -> CommandHdr {
            let cmd_id = match command {
                Command::GetProfile => Command::GET_PROFILE,
                Command::InitCtx(_) => Command::INITIALIZE_CONTEXT,
                Command::DeriveChild(_) => Command::DERIVE_CHILD,
                Command::CertifyKey(_) => Command::CERTIFY_KEY,
                Command::RotateCtx(_) => Command::ROTATE_CONTEXT_HANDLE,
                Command::DestroyCtx(_) => Command::DESTROY_CONTEXT,
                Command::ExtendTci(_) => Command::EXTEND_TCI,
                Command::TagTci(_) => Command::TAG_TCI,
            };
            CommandHdr {
                magic: Self::DPE_COMMAND_MAGIC,
                cmd_id,
                profile: DPE_PROFILE as u32,
            }
        }
    }
}
