// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::{ActiveContextArgs, Context, ContextHandle, ContextType},
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{DpeErrorCode, NewHandleResp, Response, ResponseHdr},
};

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::FromBytes)]
#[cfg_attr(test, derive(zerocopy::AsBytes))]
pub struct InitCtxCmd {
    flags: u32,
}

impl InitCtxCmd {
    const SIMULATION_FLAG_MASK: u32 = 1 << 31;
    const DEFAULT_FLAG_MASK: u32 = 1 << 30;

    pub const fn new_use_default() -> InitCtxCmd {
        InitCtxCmd {
            flags: Self::DEFAULT_FLAG_MASK,
        }
    }

    const fn flag_is_simulation(&self) -> bool {
        self.flags & Self::SIMULATION_FLAG_MASK != 0
    }

    const fn flag_is_default(&self) -> bool {
        self.flags & Self::DEFAULT_FLAG_MASK != 0
    }

    #[cfg(test)]
    pub const fn new_simulation() -> InitCtxCmd {
        InitCtxCmd {
            flags: Self::SIMULATION_FLAG_MASK,
        }
    }
}

impl CommandExecution for InitCtxCmd {
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
            allow_ca: true,
            allow_x509: true,
        });
        Ok(Response::InitCtx(NewHandleResp {
            handle,
            resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{Command, CommandHdr},
        context::ContextState,
        dpe_instance::tests::{TestTypes, TEST_LOCALITIES},
        support::Support,
        U8Bool,
    };
    use crypto::OpensslCrypto;
    use platform::DefaultPlatform;
    use zerocopy::AsBytes;

    const TEST_INIT_CTX_CMD: InitCtxCmd = InitCtxCmd { flags: 0x1234_5678 };

    #[test]
    fn test_deserialize_init_ctx() {
        let mut command = CommandHdr::new_for_test(Command::InitCtx(TEST_INIT_CTX_CMD))
            .as_bytes()
            .to_vec();
        command.extend(TEST_INIT_CTX_CMD.as_bytes());
        assert_eq!(
            Ok(Command::InitCtx(TEST_INIT_CTX_CMD)),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_initialize_context() {
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::default()).unwrap();

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
            InitCtxCmd { flags: 0 }.execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // Try simulation when not supported.
        assert_eq!(
            Err(DpeErrorCode::ArgumentNotSupported),
            InitCtxCmd::new_simulation().execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // Change to support simulation.
        let mut dpe = DpeInstance::new(
            &mut env,
            Support {
                simulation: U8Bool::new(true),
                ..Support::default()
            },
        )
        .unwrap();

        // Try setting both flags.
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            InitCtxCmd { flags: 3 << 30 }.execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
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
