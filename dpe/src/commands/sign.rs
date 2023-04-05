// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    dpe_instance::{ContextHandle, DpeInstance},
    response::{DpeErrorCode, Response},
    DPE_PROFILE,
};
use core::mem::size_of;
use crypto::Crypto;

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(zerocopy::AsBytes, zerocopy::FromBytes))]
pub struct SignCmd {
    handle: ContextHandle,
    label: [u8; DPE_PROFILE.get_hash_size()],
    flags: u32,
    digest: [u8; DPE_PROFILE.get_hash_size()],
}

impl TryFrom<&[u8]> for SignCmd {
    type Error = DpeErrorCode;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < size_of::<SignCmd>() {
            return Err(DpeErrorCode::InvalidArgument);
        }

        let mut offset = 0;

        let handle = ContextHandle::try_from(raw)?;
        offset += ContextHandle::SIZE;

        let label = raw[offset..offset + DPE_PROFILE.get_hash_size()]
            .try_into()
            .unwrap();
        offset += DPE_PROFILE.get_hash_size();
        let flags = u32::from_le_bytes(raw[offset..offset + 4].try_into().unwrap());
        offset += size_of::<u32>();
        let digest = raw[offset..offset + DPE_PROFILE.get_hash_size()]
            .try_into()
            .unwrap();

        Ok(SignCmd {
            handle,
            label,
            flags,
            digest,
        })
    }
}

impl<C: Crypto> CommandExecution<C> for SignCmd {
    fn execute(&self, _dpe: &mut DpeInstance<C>, _locality: u32) -> Result<Response, DpeErrorCode> {
        Err(DpeErrorCode::InvalidCommand)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{tests::TEST_DIGEST, Command, CommandHdr},
        dpe_instance::tests::SIMULATION_HANDLE,
    };
    use zerocopy::{AsBytes, FromBytes};

    #[cfg(feature = "dpe_profile_p256_sha256")]
    const TEST_LABEL: [u8; DPE_PROFILE.get_hash_size()] = [
        32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
        9, 8, 7, 6, 5, 4, 3, 2, 1,
    ];
    #[cfg(feature = "dpe_profile_p384_sha384")]
    const TEST_LABEL: [u8; DPE_PROFILE.get_hash_size()] = [
        48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26,
        25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
    ];

    const TEST_SIGN_CMD: SignCmd = SignCmd {
        handle: SIMULATION_HANDLE,
        label: TEST_LABEL,
        flags: 0x1234_5678,
        digest: TEST_DIGEST,
    };

    #[test]
    fn try_from_sign() {
        let command_bytes = TEST_SIGN_CMD.as_bytes();
        assert_eq!(
            SignCmd::read_from_prefix(command_bytes).unwrap(),
            SignCmd::try_from(command_bytes).unwrap(),
        );
    }

    #[test]
    fn test_deserialize_sign() {
        let mut command = CommandHdr::new(Command::Sign(TEST_SIGN_CMD))
            .as_bytes()
            .to_vec();
        command.extend(TEST_SIGN_CMD.as_bytes());
        assert_eq!(
            Ok(Command::Sign(TEST_SIGN_CMD)),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_slice_to_sign() {
        // Test if too small.
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            SignCmd::try_from([0u8; size_of::<SignCmd>() - 1].as_slice())
        );

        assert_eq!(
            TEST_SIGN_CMD,
            SignCmd::try_from(TEST_SIGN_CMD.as_bytes()).unwrap()
        );
    }
}
