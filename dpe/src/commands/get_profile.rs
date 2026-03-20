// Licensed under the Apache-2.0 license.

use super::CommandExecution;
use crate::{
    dpe_instance::{DpeEnv, DpeInstance},
    mutresp,
    response::{DpeErrorCode, GetProfileResp},
};
#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_impl_fn;

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
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    fn execute_serialized(
        &self,
        dpe: &mut DpeInstance,
        env: &mut dyn DpeEnv,
        _locality: u32,
        out: &mut [u8],
    ) -> Result<usize, DpeErrorCode> {
        let response = mutresp::<GetProfileResp>(dpe.profile, out)?;
        let support = env.state().support;
        *response = dpe.get_profile(env.platform(), support)?;

        Ok(size_of_val(response))
    }
}
