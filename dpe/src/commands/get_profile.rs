// Licensed under the Apache-2.0 license.

use super::CommandExecution;
use crate::{
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{DpeErrorCode, Response},
};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;

#[repr(C)]
#[derive(
    Debug,
    PartialEq,
    Eq,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    Default,
)]
pub struct GetProfileCmd;

impl CommandExecution for GetProfileCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        _locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        let resp = dpe.get_profile(&mut env.platform, env.state.support)?;

        Ok(Response::GetProfile(resp))
    }
}
