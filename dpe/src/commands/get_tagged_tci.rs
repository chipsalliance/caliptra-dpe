// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{DpeErrorCode, GetTaggedTciResp, Response, ResponseHdr},
};

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::FromBytes)]
#[cfg_attr(test, derive(zerocopy::AsBytes))]
pub struct GetTaggedTciCmd {
    tag: u32,
}

impl CommandExecution for GetTaggedTciCmd {
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        _env: &mut DpeEnv<impl DpeTypes>,
        _: u32,
    ) -> Result<Response, DpeErrorCode> {
        // Make sure this command is supported.
        if !dpe.support.tagging() {
            return Err(DpeErrorCode::InvalidCommand);
        }

        // Tags are unique across all contexts, so we just need to return the first context
        // we find with the requested tag.
        let ctx = dpe
            .contexts
            .iter()
            .find(|c| c.has_tag() && c.tag == self.tag)
            .ok_or(DpeErrorCode::BadTag)?;

        Ok(Response::GetTaggedTci(GetTaggedTciResp {
            tci_cumulative: ctx.tci.tci_cumulative,
            tci_current: ctx.tci.tci_current,
            resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
        }))
    }
}
