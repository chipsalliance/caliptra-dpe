// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::{ActiveContextArgs, Context, ContextHandle, ContextType},
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{DpeErrorCode, NewHandleResp, Response},
};
use bitflags::bitflags;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq};
use cfg_if::cfg_if;

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
pub struct InitCtxCmd(pub u32);

bitflags! {
    impl InitCtxCmd: u32 {
        const SIMULATION_FLAG_MASK = 1u32 << 31;
        const DEFAULT_FLAG_MASK = 1u32 << 30;
    }
}

impl InitCtxCmd {
    pub const fn new_use_default() -> InitCtxCmd {
        Self::DEFAULT_FLAG_MASK
    }

    pub const fn flag_is_simulation(&self) -> bool {
        self.contains(Self::SIMULATION_FLAG_MASK)
    }

    const fn flag_is_default(&self) -> bool {
        self.contains(Self::DEFAULT_FLAG_MASK)
    }

    pub const fn new_simulation() -> InitCtxCmd {
        Self::SIMULATION_FLAG_MASK
    }
}

impl CommandExecution for InitCtxCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        // This function can only be called once for non-simulation contexts.
        if (self.flag_is_default() && dpe.has_initialized())
            || (self.flag_is_simulation() && !dpe.support.simulation())
        {
            return Err(DpeErrorCode::ArgumentNotSupported);
        }

        // A flag must be set, but it can't be both flags. The base DPE CDI is locked for
        // non-simulation contexts once it is used once to prevent later software from accessing the
        // CDI.
        if !(self.flag_is_default() ^ self.flag_is_simulation()) {
            return Err(DpeErrorCode::InvalidArgument);
        }

        cfg_if! {
            if #[cfg(not(feature = "no-cfi"))] {
                cfi_assert!(!self.flag_is_default() || !dpe.has_initialized());
                cfi_assert!(!self.flag_is_simulation() || dpe.support.simulation());
                cfi_assert!(self.flag_is_default() ^ self.flag_is_simulation());
            }
        }

        let idx = dpe
            .get_next_inactive_context_pos()
            .ok_or(DpeErrorCode::MaxTcis)?;
        let (context_type, handle) = if self.flag_is_default() {
            dpe.has_initialized = true.into();
            (ContextType::Normal, ContextHandle::default())
        } else {
            // Simulation.
            (ContextType::Simulation, dpe.generate_new_handle(env)?)
        };

        dpe.contexts[idx].activate(&ActiveContextArgs {
            context_type,
            locality,
            handle: &handle,
            tci_type: 0,
            parent_idx: Context::ROOT_INDEX,
            allow_x509: true,
            uses_internal_input_info: false,
            uses_internal_input_dice: false,
            allow_export_cdi: true,
        });
        Ok(Response::InitCtx(NewHandleResp {
            handle,
            resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{tests::DEFAULT_PLATFORM, Command, CommandHdr},
        context::ContextState,
        dpe_instance::{
            tests::{TestTypes, TEST_LOCALITIES},
            DpeInstanceFlags,
        },
        support::Support,
    };
    use caliptra_cfi_lib_git::CfiCounter;
    use crypto::OpensslCrypto;
    use zerocopy::IntoBytes;

    const TEST_INIT_CTX_CMD: InitCtxCmd = InitCtxCmd(0x1234_5678);

    #[test]
    fn test_deserialize_init_ctx() {
        CfiCounter::reset_for_test();
        let mut command = CommandHdr::new_for_test(Command::INITIALIZE_CONTEXT)
            .as_bytes()
            .to_vec();
        command.extend(TEST_INIT_CTX_CMD.as_bytes());
        assert_eq!(
            Ok(Command::InitCtx(&TEST_INIT_CTX_CMD)),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_initialize_context() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DEFAULT_PLATFORM,
        };
        let mut dpe =
            DpeInstance::new(&mut env, Support::default(), DpeInstanceFlags::empty()).unwrap();

        let handle = match InitCtxCmd::new_use_default()
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap()
        {
            Response::InitCtx(resp) => resp.handle,
            _ => panic!("Wrong response type."),
        };
        // Make sure default context is 0x0.
        assert_eq!(ContextHandle::default(), handle);

        // Try to double initialize the default context.
        assert_eq!(
            Err(DpeErrorCode::ArgumentNotSupported),
            InitCtxCmd::new_use_default().execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // Try not setting any flags.
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            InitCtxCmd::empty().execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // Try simulation when not supported.
        assert_eq!(
            Err(DpeErrorCode::ArgumentNotSupported),
            InitCtxCmd::new_simulation().execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // Change to support simulation.
        let mut dpe =
            DpeInstance::new(&mut env, Support::SIMULATION, DpeInstanceFlags::empty()).unwrap();

        // Try setting both flags.
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            (InitCtxCmd::DEFAULT_FLAG_MASK | InitCtxCmd::SIMULATION_FLAG_MASK).execute(
                &mut dpe,
                &mut env,
                TEST_LOCALITIES[0]
            )
        );

        // Set all handles as active.
        for context in dpe.contexts.iter_mut() {
            context.state = ContextState::Active;
        }

        // Try to initialize a context when it is full.
        assert_eq!(
            Err(DpeErrorCode::MaxTcis),
            InitCtxCmd::new_simulation().execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
    }
}
