// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::ContextHandle,
    dpe_instance::DpeInstance,
    response::{DpeErrorCode, Response},
    DPE_PROFILE,
};
use crypto::Crypto;

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::FromBytes)]
#[cfg_attr(test, derive(zerocopy::AsBytes))]
pub struct CertifyCsrCmd {
    pub handle: ContextHandle,
    pub flags: u32,
    pub label: [u8; DPE_PROFILE.get_hash_size()],
}

impl CertifyCsrCmd {
    pub const ND_DERIVATION: u32 = 1 << 31;

    // Uses non-deterministic derivation.
    const fn uses_nd_derivation(&self) -> bool {
        self.flags & Self::ND_DERIVATION != 0
    }
}

impl<C: Crypto> CommandExecution<C> for CertifyCsrCmd {
    fn execute(&self, dpe: &mut DpeInstance<C>, locality: u32) -> Result<Response, DpeErrorCode> {
        // Make sure the operation is supported.
        if !dpe.support.nd_derivation && self.uses_nd_derivation() {
            return Err(DpeErrorCode::InvalidArgument);
        }

        let idx = dpe
            .get_active_context_pos(&self.handle, locality)
            .ok_or(DpeErrorCode::InvalidHandle)?;
        let context = &dpe.contexts[idx];

        // Make sure the command is coming from the right locality.
        if context.locality != locality {
            return Err(DpeErrorCode::InvalidHandle);
        }

        Err(DpeErrorCode::InvalidCommand)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{Command, CommandHdr},
        dpe_instance::tests::{SIMULATION_HANDLE, TEST_LOCALITIES},
        support::test::SUPPORT,
    };
    use crypto::OpensslCrypto;
    use zerocopy::AsBytes;

    const TEST_CERTIFY_CSR_CMD: CertifyCsrCmd = CertifyCsrCmd {
        handle: SIMULATION_HANDLE,
        flags: 0x1234_5678,
        label: [0xaa; DPE_PROFILE.get_hash_size()],
    };

    #[test]
    fn test_deserialize_certify_csr() {
        let mut command = CommandHdr::new(Command::CertifyCsr(TEST_CERTIFY_CSR_CMD))
            .as_bytes()
            .to_vec();
        command.extend(TEST_CERTIFY_CSR_CMD.as_bytes());
        assert_eq!(
            Ok(Command::CertifyCsr(TEST_CERTIFY_CSR_CMD)),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_uses_nd_derivation() {
        // Non-deterministic flag not set
        assert!(!CertifyCsrCmd {
            flags: 0,
            ..TEST_CERTIFY_CSR_CMD
        }
        .uses_nd_derivation());

        // Non-deterministic flag set.
        assert!(CertifyCsrCmd {
            flags: CertifyCsrCmd::ND_DERIVATION,
            ..TEST_CERTIFY_CSR_CMD
        }
        .uses_nd_derivation());
    }

    #[test]
    fn test_bad_command_inputs() {
        let mut dpe =
            DpeInstance::<OpensslCrypto>::new_for_test(SUPPORT, &TEST_LOCALITIES).unwrap();

        // Bad argument
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            CertifyCsrCmd {
                handle: ContextHandle([0xff; ContextHandle::SIZE]),
                flags: CertifyCsrCmd::ND_DERIVATION,
                ..TEST_CERTIFY_CSR_CMD
            }
            .execute(&mut dpe, TEST_LOCALITIES[0])
        );

        // Bad handle.
        assert_eq!(
            Err(DpeErrorCode::InvalidHandle),
            CertifyCsrCmd {
                handle: ContextHandle([0xff; ContextHandle::SIZE]),
                ..TEST_CERTIFY_CSR_CMD
            }
            .execute(&mut dpe, TEST_LOCALITIES[0])
        );

        // Wrong locality.
        assert!(dpe
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .is_some());
        assert_eq!(
            Err(DpeErrorCode::InvalidHandle),
            CertifyCsrCmd {
                handle: ContextHandle::default(),
                ..TEST_CERTIFY_CSR_CMD
            }
            .execute(&mut dpe, TEST_LOCALITIES[1])
        );
    }
}
