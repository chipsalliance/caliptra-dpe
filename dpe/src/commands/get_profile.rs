// Licensed under the Apache-2.0 license.

use super::CommandExecution;
use crate::{
    dpe_instance::{DpeEnv, DpeInstance},
    error::DpeErrorCode,
    response::GetProfileResp,
};
#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_dpe_response_buffer::ResponseBuffer;
use zerocopy::IntoBytes;

#[repr(C, align(4))]
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
        out: &mut dyn ResponseBuffer,
    ) -> Result<usize, DpeErrorCode> {
        let support = env.state().support;
        let resp: GetProfileResp = dpe.get_profile(env.platform(), support)?;
        let bytes = resp.as_bytes();
        out.write_at(0, bytes)
            .map_err(|_| DpeErrorCode::InvalidResponseBuf)?;
        Ok(bytes.len())
    }
}
