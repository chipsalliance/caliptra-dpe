/*++
Licensed under the Apache-2.0 license.

Abstract:
    DPE Commands and deserialization.
--*/
pub use self::certify_key::{
    CertifyKeyCommand, CertifyKeyFlags, CertifyKeyP256Cmd, CertifyKeyP384Cmd,
};
pub use self::derive_context::{DeriveContextCmd, DeriveContextFlags};
pub use self::destroy_context::DestroyCtxCmd;
pub use self::get_certificate_chain::GetCertificateChainCmd;
pub use self::initialize_context::InitCtxCmd;
pub use self::sign::{SignCommand, SignFlags, SignP256Cmd, SignP384Cmd};

#[cfg(feature = "ml-dsa")]
pub use {self::certify_key::CertifyKeyMldsaExternalMu87Cmd, sign::SignMldsaExternalMu87Cmd};

#[cfg(not(feature = "disable_rotate_context"))]
pub use self::rotate_context::{RotateCtxCmd, RotateCtxFlags};

use crate::{
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{DpeErrorCode, Response},
    DpeProfile,
};
use core::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

mod certify_key;
mod derive_context;
mod destroy_context;
mod get_certificate_chain;
mod initialize_context;
#[cfg(not(feature = "disable_rotate_context"))]
mod rotate_context;
mod sign;

#[derive(Debug, PartialEq, Eq)]
pub enum Command<'a> {
    GetProfile,
    InitCtx(&'a InitCtxCmd),
    DeriveContext(&'a DeriveContextCmd),
    CertifyKey(CertifyKeyCommand<'a>),
    Sign(SignCommand<'a>),
    #[cfg(not(feature = "disable_rotate_context"))]
    RotateCtx(&'a RotateCtxCmd),
    DestroyCtx(&'a DestroyCtxCmd),
    GetCertificateChain(&'a GetCertificateChainCmd),
}

impl Command<'_> {
    pub const GET_PROFILE: u32 = 0x01;
    pub const INITIALIZE_CONTEXT: u32 = 0x07;
    pub const DERIVE_CONTEXT: u32 = 0x08;
    pub const CERTIFY_KEY: u32 = 0x09;
    pub const SIGN: u32 = 0x0A;
    #[cfg(not(feature = "disable_rotate_context"))]
    pub const ROTATE_CONTEXT_HANDLE: u32 = 0x0e;
    pub const DESTROY_CONTEXT: u32 = 0x0f;
    pub const GET_CERTIFICATE_CHAIN: u32 = 0x10;

    /// Returns the command with its parameters given a slice of bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - serialized command
    pub fn deserialize(profile: DpeProfile, bytes: &[u8]) -> Result<Command, DpeErrorCode> {
        let header = CommandHdr::try_from_with_profile(profile, bytes)?;
        let bytes = &bytes[size_of::<CommandHdr>()..];

        match header.cmd_id {
            Command::GET_PROFILE => Ok(Command::GetProfile),
            Command::INITIALIZE_CONTEXT => Self::parse_command(Command::InitCtx, bytes),
            Command::DERIVE_CONTEXT => Self::parse_command(Command::DeriveContext, bytes),
            Command::CERTIFY_KEY => Ok(CertifyKeyCommand::deserialize(profile, bytes)?.into()),
            Command::SIGN => Ok(Command::Sign(SignCommand::deserialize(profile, bytes)?)),
            #[cfg(not(feature = "disable_rotate_context"))]
            Command::ROTATE_CONTEXT_HANDLE => Self::parse_command(Command::RotateCtx, bytes),
            Command::DESTROY_CONTEXT => Self::parse_command(Command::DestroyCtx, bytes),
            Command::GET_CERTIFICATE_CHAIN => {
                Self::parse_command(Command::GetCertificateChain, bytes)
            }
            _ => Err(DpeErrorCode::InvalidCommand),
        }
    }

    fn parse_command<'a, T: FromBytes + KnownLayout + Immutable + 'a>(
        build: impl FnOnce(&'a T) -> Command<'a>,
        bytes: &'a [u8],
    ) -> Result<Command<'a>, DpeErrorCode> {
        let (prefix, _remaining_bytes) =
            T::ref_from_prefix(bytes).map_err(|_| DpeErrorCode::InvalidArgument)?;
        Ok(build(prefix))
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Command::CertifyKey(cmd) => cmd.as_bytes(),
            Command::DeriveContext(cmd) => cmd.as_bytes(),
            Command::GetCertificateChain(cmd) => cmd.as_bytes(),
            Command::DestroyCtx(cmd) => cmd.as_bytes(),
            Command::GetProfile => &[],
            Command::InitCtx(cmd) => cmd.as_bytes(),
            Command::RotateCtx(cmd) => cmd.as_bytes(),
            Command::Sign(cmd) => cmd.as_bytes(),
        }
    }
}

impl From<Command<'_>> for u32 {
    fn from(cmd: Command) -> u32 {
        match cmd {
            Command::GetProfile => Command::GET_PROFILE,
            Command::InitCtx(_) => Command::INITIALIZE_CONTEXT,
            Command::DeriveContext(_) => Command::DERIVE_CONTEXT,
            Command::CertifyKey(_) => Command::CERTIFY_KEY,
            Command::Sign(_) => Command::SIGN,
            #[cfg(not(feature = "disable_rotate_context"))]
            Command::RotateCtx(_) => Command::ROTATE_CONTEXT_HANDLE,
            Command::DestroyCtx(_) => Command::DESTROY_CONTEXT,
            Command::GetCertificateChain(_) => Command::GET_CERTIFICATE_CHAIN,
        }
    }
}

impl<'a> From<&'a InitCtxCmd> for Command<'a> {
    fn from(cmd: &'a InitCtxCmd) -> Command<'a> {
        Command::InitCtx(cmd)
    }
}

impl<'a> From<&'a DeriveContextCmd> for Command<'a> {
    fn from(cmd: &'a DeriveContextCmd) -> Command<'a> {
        Command::DeriveContext(cmd)
    }
}

impl<'a> From<CertifyKeyCommand<'a>> for Command<'a> {
    fn from(cmd: CertifyKeyCommand<'a>) -> Command<'a> {
        Command::CertifyKey(cmd)
    }
}

#[cfg(feature = "p256")]
impl<'a> From<&'a CertifyKeyP256Cmd> for Command<'a> {
    fn from(cmd: &'a CertifyKeyP256Cmd) -> Command<'a> {
        Command::CertifyKey(CertifyKeyCommand::P256(cmd))
    }
}

#[cfg(feature = "p384")]
impl<'a> From<&'a CertifyKeyP384Cmd> for Command<'a> {
    fn from(cmd: &'a CertifyKeyP384Cmd) -> Command<'a> {
        Command::CertifyKey(CertifyKeyCommand::P384(cmd))
    }
}

#[cfg(feature = "ml-dsa")]
impl<'a> From<&'a CertifyKeyMldsaExternalMu87Cmd> for Command<'a> {
    fn from(cmd: &'a CertifyKeyMldsaExternalMu87Cmd) -> Command<'a> {
        Command::CertifyKey(CertifyKeyCommand::ExternalMu87(cmd))
    }
}

impl<'a> From<SignCommand<'a>> for Command<'a> {
    fn from(cmd: SignCommand<'a>) -> Command<'a> {
        Command::Sign(cmd)
    }
}

#[cfg(feature = "p256")]
impl<'a> From<&'a SignP256Cmd> for Command<'a> {
    fn from(cmd: &'a SignP256Cmd) -> Command<'a> {
        Command::Sign(SignCommand::P256(cmd))
    }
}

#[cfg(feature = "p384")]
impl<'a> From<&'a SignP384Cmd> for Command<'a> {
    fn from(cmd: &'a SignP384Cmd) -> Command<'a> {
        Command::Sign(SignCommand::P384(cmd))
    }
}

#[cfg(feature = "ml-dsa")]
impl<'a> From<&'a SignMldsaExternalMu87Cmd> for Command<'a> {
    fn from(cmd: &'a SignMldsaExternalMu87Cmd) -> Command<'a> {
        Command::Sign(SignCommand::ExternalMu87(cmd))
    }
}

#[cfg(not(feature = "disable_rotate_context"))]
impl<'a> From<&'a RotateCtxCmd> for Command<'a> {
    fn from(cmd: &'a RotateCtxCmd) -> Command<'a> {
        Command::RotateCtx(cmd)
    }
}

impl<'a> From<&'a DestroyCtxCmd> for Command<'a> {
    fn from(cmd: &'a DestroyCtxCmd) -> Command<'a> {
        Command::DestroyCtx(cmd)
    }
}

impl<'a> From<&'a GetCertificateChainCmd> for Command<'a> {
    fn from(cmd: &'a GetCertificateChainCmd) -> Command<'a> {
        Command::GetCertificateChain(cmd)
    }
}

pub trait CommandExecution {
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
    ) -> Result<Response, DpeErrorCode>;

    /// CFI wrapper around execute
    ///
    /// To implement this function, you need to add the
    /// cfi_impl_fn proc_macro to execute.
    #[cfg(not(feature = "no-cfi"))]
    fn __cfi_execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
    ) -> Result<Response, DpeErrorCode>;
}

// ABI Command structures

#[repr(C)]
#[derive(
    Debug,
    PartialEq,
    Eq,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
pub struct CommandHdr {
    pub magic: u32,
    pub cmd_id: u32,
    pub profile: u32,
}

impl CommandHdr {
    const DPE_COMMAND_MAGIC: u32 = u32::from_be_bytes(*b"DPEC");

    pub fn new(profile: DpeProfile, cmd_id: u32) -> CommandHdr {
        CommandHdr {
            magic: Self::DPE_COMMAND_MAGIC,
            cmd_id,
            profile: profile as u32,
        }
    }

    fn try_from_with_profile(profile: DpeProfile, raw: &[u8]) -> Result<Self, DpeErrorCode> {
        let header = CommandHdr::try_from(raw)?;
        // The client doesn't know what profile is implemented when calling the `GetProfile`
        // command. But, all other commands should be directed towards the correct profile.
        if header.cmd_id != Command::GET_PROFILE && header.profile != profile as u32 {
            return Err(DpeErrorCode::InvalidCommand);
        }
        Ok(header)
    }
}

impl TryFrom<&[u8]> for CommandHdr {
    type Error = DpeErrorCode;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        let (header, _remaining_bytes) =
            CommandHdr::read_from_prefix(raw).map_err(|_| DpeErrorCode::InvalidCommand)?;
        if header.magic != Self::DPE_COMMAND_MAGIC {
            return Err(DpeErrorCode::InvalidCommand);
        }
        Ok(header)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::dpe_instance::tests::DPE_PROFILE;
    use crate::DpeProfile;
    use caliptra_cfi_lib_git::CfiCounter;
    use platform::default::{DefaultPlatform, DefaultPlatformProfile};
    use zerocopy::IntoBytes;

    #[cfg(feature = "p256")]
    pub const TEST_DIGEST: [u8; DPE_PROFILE.hash_size()] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    #[cfg(any(feature = "p384", feature = "ml-dsa"))]
    pub const TEST_DIGEST: [u8; DPE_PROFILE.hash_size()] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
    ];

    #[cfg(feature = "p256")]
    pub const TEST_LABEL: [u8; DPE_PROFILE.hash_size()] = [
        32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
        9, 8, 7, 6, 5, 4, 3, 2, 1,
    ];
    #[cfg(any(feature = "p384", feature = "ml-dsa"))]
    pub const TEST_LABEL: [u8; DPE_PROFILE.hash_size()] = [
        48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26,
        25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
    ];

    #[cfg(feature = "p256")]
    pub const DEFAULT_PLATFORM: DefaultPlatform = DefaultPlatform(DefaultPlatformProfile::P256);
    #[cfg(feature = "p384")]
    pub const DEFAULT_PLATFORM: DefaultPlatform = DefaultPlatform(DefaultPlatformProfile::P384);
    #[cfg(feature = "ml-dsa")]
    pub const DEFAULT_PLATFORM: DefaultPlatform =
        DefaultPlatform(DefaultPlatformProfile::Mldsa87ExternalMu);

    pub const PROFILES: [DpeProfile; 2] = [DpeProfile::P256Sha256, DpeProfile::P384Sha384];

    const DEFAULT_COMMAND: CommandHdr = CommandHdr {
        magic: CommandHdr::DPE_COMMAND_MAGIC,
        cmd_id: Command::GET_PROFILE,
        profile: DPE_PROFILE as u32,
    };

    #[test]
    fn test_deserialize_get_profile() {
        CfiCounter::reset_for_test();
        for p in [DpeProfile::P256Sha256, DpeProfile::P384Sha384] {
            assert_eq!(
                Ok(Command::GetProfile),
                Command::deserialize(p, CommandHdr::new(p, Command::GET_PROFILE).as_bytes())
            );
        }
    }

    #[test]
    fn test_slice_to_command_hdr() {
        CfiCounter::reset_for_test();
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
        let profile = DPE_PROFILE;
        #[cfg(feature = "p256")]
        let wrong_profile = DpeProfile::P384Sha384 as u32;
        #[cfg(feature = "p384")]
        let wrong_profile = DpeProfile::P256Sha256 as u32;
        #[cfg(feature = "ml-dsa")]
        let wrong_profile = DpeProfile::P256Sha256 as u32;

        // All commands should check the profile except GetProfile.
        assert_eq!(
            Err(DpeErrorCode::InvalidCommand),
            Command::deserialize(
                profile,
                CommandHdr {
                    profile: wrong_profile,
                    cmd_id: Command::INITIALIZE_CONTEXT,
                    ..DEFAULT_COMMAND
                }
                .as_bytes()
            )
        );

        // Make sure GetProfile doesn't care.
        assert!(Command::deserialize(
            profile,
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
