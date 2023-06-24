// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::ContextHandle,
    dpe_instance::DpeInstance,
    response::{NewHandleResp, Response, ResponseHdr},
    common::error_code::DpeErrorCode,
};
use crypto::Crypto;
use platform::Platform;

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::FromBytes)]
#[cfg_attr(test, derive(zerocopy::AsBytes))]
pub struct RotateCtxCmd {
    handle: ContextHandle,
    flags: u32,
    target_locality: u32,
}

impl RotateCtxCmd {
    pub const TARGET_IS_DEFAULT: u32 = 1 << 31;

    const fn uses_target_is_default(&self) -> bool {
        self.flags & Self::TARGET_IS_DEFAULT != 0
    }
}

impl<C: Crypto, P: Platform> CommandExecution<C, P> for RotateCtxCmd {
    fn execute(
        &self,
        dpe: &mut DpeInstance<C, P>,
        locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        if !dpe.support.rotate_context {
            return Err(DpeErrorCode::InvalidCommand);
        }
        let idx = dpe.get_active_context_pos(&self.handle, locality)?;

        // Make sure caller's locality does not already have a default context.
        if self.uses_target_is_default() {
            let default_context_idx =
                dpe.get_active_context_pos(&ContextHandle::default(), locality);
            if default_context_idx.is_ok() {
                return Err(DpeErrorCode::InvalidArgument);
            }
        }

        let new_handle = if self.uses_target_is_default() {
            ContextHandle::default()
        } else {
            dpe.generate_new_handle()?
        };
        dpe.contexts[idx].handle = new_handle;
        Ok(Response::RotateCtx(NewHandleResp {
            handle: new_handle,
            resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{Command, CommandHdr, InitCtxCmd},
        dpe_instance::tests::{SIMULATION_HANDLE, TEST_HANDLE, TEST_LOCALITIES},
        support::Support,
    };
    use crypto::OpensslCrypto;
    use platform::DefaultPlatform;
    use zerocopy::AsBytes;

    const TEST_ROTATE_CTX_CMD: RotateCtxCmd = RotateCtxCmd {
        flags: 0x1234_5678,
        handle: TEST_HANDLE,
        target_locality: 0x9876_5432,
    };

    #[test]
    fn test_deserialize_rotate_context() {
        let mut command = CommandHdr::new_for_test(Command::RotateCtx(TEST_ROTATE_CTX_CMD))
            .as_bytes()
            .to_vec();
        command.extend(TEST_ROTATE_CTX_CMD.as_bytes());
        assert_eq!(
            Ok(Command::RotateCtx(TEST_ROTATE_CTX_CMD)),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_rotate_context() {
        let mut dpe =
            DpeInstance::<OpensslCrypto, DefaultPlatform>::new_for_test(Support::default())
                .unwrap();
        // Make sure it returns an error if the command is marked unsupported.
        assert_eq!(
            Err(DpeErrorCode::InvalidCommand),
            RotateCtxCmd {
                handle: ContextHandle::default(),
                flags: 0,
                target_locality: 0
            }
            .execute(&mut dpe, TEST_LOCALITIES[0])
        );

        // Make a new instance that supports RotateContext.
        let mut dpe = DpeInstance::<OpensslCrypto, DefaultPlatform>::new_for_test(Support {
            rotate_context: true,
            ..Support::default()
        })
        .unwrap();
        InitCtxCmd::new_use_default()
            .execute(&mut dpe, TEST_LOCALITIES[0])
            .unwrap();

        // Invalid handle.
        assert_eq!(
            Err(DpeErrorCode::InvalidHandle),
            RotateCtxCmd {
                handle: TEST_HANDLE,
                flags: 0,
                target_locality: 0
            }
            .execute(&mut dpe, TEST_LOCALITIES[0])
        );

        // Wrong locality.
        assert_eq!(
            Err(DpeErrorCode::InvalidLocality),
            RotateCtxCmd {
                handle: ContextHandle::default(),
                flags: 0,
                target_locality: 0
            }
            .execute(&mut dpe, TEST_LOCALITIES[1])
        );

        // Caller's locality already has default context.
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            RotateCtxCmd {
                handle: ContextHandle::default(),
                flags: RotateCtxCmd::TARGET_IS_DEFAULT,
                target_locality: 0
            }
            .execute(&mut dpe, TEST_LOCALITIES[0])
        );

        // Rotate default handle.
        assert_eq!(
            Ok(Response::RotateCtx(NewHandleResp {
                handle: SIMULATION_HANDLE,
                resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
            })),
            RotateCtxCmd {
                handle: ContextHandle::default(),
                flags: 0,
                target_locality: 0
            }
            .execute(&mut dpe, TEST_LOCALITIES[0])
        );

        // New handle is all 0s if caller requests default handle
        assert_eq!(
            Ok(Response::RotateCtx(NewHandleResp {
                handle: ContextHandle::default(),
                resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
            })),
            RotateCtxCmd {
                handle: SIMULATION_HANDLE,
                flags: RotateCtxCmd::TARGET_IS_DEFAULT,
                target_locality: 0
            }
            .execute(&mut dpe, TEST_LOCALITIES[0])
        );
    }
}
