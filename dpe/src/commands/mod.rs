/*++
Licensed under the Apache-2.0 license.

Abstract:
    DPE Commands and deserialization.
--*/
pub use self::derive_child::{DeriveChildCmd, DeriveChildFlags};
pub(crate) use self::destroy_context::DestroyCtxCmd;
pub use self::get_certificate_chain::GetCertificateChainCmd;
pub use self::initialize_context::InitCtxCmd;

pub use self::certify_key::{CertifyKeyCmd, CertifyKeyFlags};

use self::extend_tci::ExtendTciCmd;
use self::get_tagged_tci::GetTaggedTciCmd;
use self::rotate_context::RotateCtxCmd;
pub use self::sign::{SignCmd, SignFlags};
use self::tag_tci::TagTciCmd;

use crate::{
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{DpeErrorCode, Response},
    DPE_PROFILE,
};
use core::mem::size_of;
use zerocopy::FromBytes;

mod certify_key;
mod derive_child;
mod destroy_context;
mod extend_tci;
mod get_certificate_chain;
mod get_tagged_tci;
mod initialize_context;
mod rotate_context;
mod sign;
mod tag_tci;

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    GetProfile,
    InitCtx(InitCtxCmd),
    DeriveChild(DeriveChildCmd),
    CertifyKey(CertifyKeyCmd),
    Sign(SignCmd),
    RotateCtx(RotateCtxCmd),
    DestroyCtx(DestroyCtxCmd),
    ExtendTci(ExtendTciCmd),
    TagTci(TagTciCmd),
    GetTaggedTci(GetTaggedTciCmd),
    GetCertificateChain(GetCertificateChainCmd),
}

impl Command {
    const GET_PROFILE: u32 = 0x01;
    const INITIALIZE_CONTEXT: u32 = 0x07;
    const DERIVE_CHILD: u32 = 0x08;
    const CERTIFY_KEY: u32 = 0x09;
    const SIGN: u32 = 0x0A;
    const ROTATE_CONTEXT_HANDLE: u32 = 0x0e;
    const DESTROY_CONTEXT: u32 = 0x0f;
    const GET_CERTIFICATE_CHAIN: u32 = 0x80;
    const EXTEND_TCI: u32 = 0x81;
    const TAG_TCI: u32 = 0x82;
    const GET_TAGGED_TCI: u32 = 0x83;

    /// Returns the command with its parameters given a slice of bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - serialized command
    pub fn deserialize(bytes: &[u8]) -> Result<Command, DpeErrorCode> {
        let header = CommandHdr::try_from(bytes)?;
        let bytes = &bytes[size_of::<CommandHdr>()..];

        match header.cmd_id {
            Command::GET_PROFILE => Ok(Command::GetProfile),
            Command::INITIALIZE_CONTEXT => Self::parse_command(Command::InitCtx, bytes),
            Command::DERIVE_CHILD => Self::parse_command(Command::DeriveChild, bytes),
            Command::CERTIFY_KEY => Self::parse_command(Command::CertifyKey, bytes),
            Command::SIGN => Self::parse_command(Command::Sign, bytes),
            Command::ROTATE_CONTEXT_HANDLE => Self::parse_command(Command::RotateCtx, bytes),
            Command::DESTROY_CONTEXT => Self::parse_command(Command::DestroyCtx, bytes),
            Command::GET_CERTIFICATE_CHAIN => {
                Self::parse_command(Command::GetCertificateChain, bytes)
            }
            Command::EXTEND_TCI => Self::parse_command(Command::ExtendTci, bytes),
            Command::TAG_TCI => Self::parse_command(Command::TagTci, bytes),
            Command::GET_TAGGED_TCI => Self::parse_command(Command::GetTaggedTci, bytes),
            _ => Err(DpeErrorCode::InvalidCommand),
        }
    }

    fn parse_command<T: FromBytes>(
        build: impl FnOnce(T) -> Command,
        bytes: &[u8],
    ) -> Result<Command, DpeErrorCode> {
        Ok(build(
            T::read_from_prefix(bytes).ok_or(DpeErrorCode::InvalidArgument)?,
        ))
    }
}

impl From<Command> for u32 {
    fn from(cmd: Command) -> u32 {
        match cmd {
            Command::GetProfile => Command::GET_PROFILE,
            Command::InitCtx(_) => Command::INITIALIZE_CONTEXT,
            Command::DeriveChild(_) => Command::DERIVE_CHILD,
            Command::CertifyKey(_) => Command::CERTIFY_KEY,
            Command::Sign(_) => Command::SIGN,
            Command::RotateCtx(_) => Command::ROTATE_CONTEXT_HANDLE,
            Command::DestroyCtx(_) => Command::DESTROY_CONTEXT,
            Command::ExtendTci(_) => Command::EXTEND_TCI,
            Command::TagTci(_) => Command::TAG_TCI,
            Command::GetTaggedTci(_) => Command::GET_TAGGED_TCI,
            Command::GetCertificateChain(_) => Command::GET_CERTIFICATE_CHAIN,
        }
    }
}

pub trait CommandExecution {
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
    ) -> Result<Response, DpeErrorCode>;
}

// ABI Command structures

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::FromBytes, zerocopy::AsBytes)]
pub struct CommandHdr {
    pub magic: u32,
    pub cmd_id: u32,
    pub profile: u32,
}

impl CommandHdr {
    const DPE_COMMAND_MAGIC: u32 = u32::from_be_bytes(*b"DPEC");

    pub fn new_for_test(command: Command) -> CommandHdr {
        CommandHdr {
            magic: Self::DPE_COMMAND_MAGIC,
            cmd_id: command.into(),
            profile: DPE_PROFILE as u32,
        }
    }
}

impl TryFrom<&[u8]> for CommandHdr {
    type Error = DpeErrorCode;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        let header = CommandHdr::read_from_prefix(raw).ok_or(DpeErrorCode::InvalidCommand)?;
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
    use zerocopy::AsBytes;

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
    fn test_deserialize_get_profile() {
        // Commands that can be deserialized.
        assert_eq!(
            Ok(Command::GetProfile),
            Command::deserialize(CommandHdr::new_for_test(Command::GetProfile).as_bytes())
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
}
