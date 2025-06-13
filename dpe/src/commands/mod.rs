/*++
Licensed under the Apache-2.0 license.

Abstract:
    DPE Commands and deserialization.
--*/
pub use self::derive_context::{DeriveContextCmd, DeriveContextFlags};
pub use self::destroy_context::DestroyCtxCmd;
pub use self::get_certificate_chain::GetCertificateChainCmd;
pub use self::initialize_context::InitCtxCmd;

pub use self::certify_key::{CertifyKeyCmd, CertifyKeyFlags};
#[cfg(not(feature = "disable_rotate_context"))]
pub use self::rotate_context::{RotateCtxCmd, RotateCtxFlags};
pub use self::sign::{SignCmd, SignFlags};

use crate::{
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{DpeErrorCode, Response},
    DpeProfile,
};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::cfi_launder;
use core::mem::size_of;
use zerocopy::{FromBytes, Immutable, KnownLayout};

mod certify_key;
mod derive_context;
mod destroy_context;
mod get_certificate_chain;
mod initialize_context;
#[cfg(not(feature = "disable_rotate_context"))]
mod rotate_context;
mod sign;

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
pub fn deserialize<T: DpeTypes>(
    profile: DpeProfile,
    bytes: &[u8],
) -> Result<&dyn CommandExecution<T>, DpeErrorCode> {
    let header = CommandHdr::try_from_with_profile(profile, bytes)?;
    let bytes = &bytes[size_of::<CommandHdr>()..];

    match cfi_launder(header.cmd_id) {
        GET_PROFILE => parse_command::<T, GetProfileCmd>(bytes),
        INITIALIZE_CONTEXT => parse_command::<T, InitCtxCmd>(bytes),
        DERIVE_CONTEXT => parse_command::<T, DeriveContextCmd>(bytes),
        CERTIFY_KEY => parse_command::<T, CertifyKeyCmd>(bytes),
        SIGN => parse_command::<T, SignCmd>(bytes),
        #[cfg(not(feature = "disable_rotate_context"))]
        ROTATE_CONTEXT_HANDLE => parse_command::<T, RotateCtxCmd>(bytes),
        DESTROY_CONTEXT => parse_command::<T, DestroyCtxCmd>(bytes),
        GET_CERTIFICATE_CHAIN => parse_command::<T, GetCertificateChainCmd>(bytes),
        _ => Err(DpeErrorCode::InvalidCommand),
    }
}

fn parse_command<
    'a,
    T: DpeTypes,
    C: FromBytes + KnownLayout + Immutable + CommandExecution<T> + 'a,
>(
    bytes: &'a [u8],
) -> Result<&'a dyn CommandExecution<T>, DpeErrorCode> {
    let (prefix, _remaining_bytes) =
        C::ref_from_prefix(bytes).map_err(|_| DpeErrorCode::InvalidArgument)?;
    Ok(prefix)
}

pub trait CommandExecution<T: DpeTypes>: core::fmt::Debug {
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<T>,
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
        env: &mut DpeEnv<T>,
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
        if header.cmd_id != GET_PROFILE && header.profile != profile as u32 {
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

#[repr(C)]
#[derive(Debug, PartialEq, Eq, FromBytes, KnownLayout, Immutable)]
struct GetProfileCmd;

impl<T: DpeTypes> CommandExecution<T> for GetProfileCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<T>,
        _locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        Ok(Response::GetProfile(
            dpe.get_profile(&mut env.platform, env.state.support)?,
        ))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{dpe_instance::tests::TestTypes, DpeProfile, DPE_PROFILE};
    use caliptra_cfi_lib_git::CfiCounter;
    use platform::default::{DefaultPlatform, DefaultPlatformProfile};
    use zerocopy::IntoBytes;

    #[cfg(feature = "dpe_profile_p256_sha256")]
    pub const TEST_DIGEST: [u8; DPE_PROFILE.hash_size()] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    #[cfg(feature = "dpe_profile_p384_sha384")]
    pub const TEST_DIGEST: [u8; DPE_PROFILE.hash_size()] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
    ];

    #[cfg(feature = "dpe_profile_p256_sha256")]
    pub const TEST_LABEL: [u8; DPE_PROFILE.hash_size()] = [
        32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
        9, 8, 7, 6, 5, 4, 3, 2, 1,
    ];
    #[cfg(feature = "dpe_profile_p384_sha384")]
    pub const TEST_LABEL: [u8; DPE_PROFILE.hash_size()] = [
        48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26,
        25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
    ];

    #[cfg(feature = "dpe_profile_p256_sha256")]
    pub const DEFAULT_PLATFORM: DefaultPlatform = DefaultPlatform(DefaultPlatformProfile::P256);
    #[cfg(feature = "dpe_profile_p384_sha384")]
    pub const DEFAULT_PLATFORM: DefaultPlatform = DefaultPlatform(DefaultPlatformProfile::P384);

    pub const PROFILES: [DpeProfile; 2] = [DpeProfile::P256Sha256, DpeProfile::P384Sha384];

    const DEFAULT_COMMAND: CommandHdr = CommandHdr {
        magic: CommandHdr::DPE_COMMAND_MAGIC,
        cmd_id: GET_PROFILE,
        profile: DPE_PROFILE as u32,
    };

    #[test]
    fn test_deserialize_get_profile() {
        CfiCounter::reset_for_test();
        for p in [DpeProfile::P256Sha256, DpeProfile::P384Sha384] {
            assert!(
                deserialize::<TestTypes>(p, CommandHdr::new(p, GET_PROFILE).as_bytes()).is_ok()
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
        #[cfg(feature = "dpe_profile_p256_sha256")]
        let wrong_profile = DpeProfile::P384Sha384 as u32;
        #[cfg(feature = "dpe_profile_p384_sha384")]
        let wrong_profile = DpeProfile::P256Sha256 as u32;

        // All commands should check the profile except GetProfile.
        assert!(deserialize::<TestTypes>(
            profile,
            CommandHdr {
                profile: wrong_profile,
                cmd_id: INITIALIZE_CONTEXT,
                ..DEFAULT_COMMAND
            }
            .as_bytes()
        )
        .is_err());

        // Make sure GetProfile doesn't care.
        assert!(deserialize::<TestTypes>(
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
