use crate::profile;
use crate::{DpeError, MAX_HANDLES};

use core::option::Option;

// ABI Command/Response structures

#[repr(C)]
pub struct CommandHdr {
    pub magic: u32,
    pub cmd_id: u32,
    pub profile: u32,
}

#[repr(C)]
pub struct ResponseHdr {
    pub magic: u32,
    pub status: u32,
    pub profile: u32,
}

#[repr(C)]
pub struct GetProfileCmd {
    pub hdr: CommandHdr,
}

#[repr(C)]
pub struct GetProfileResp {
    pub hdr: ResponseHdr,
    pub flags: u32,
}

#[repr(C)]
pub struct InitCtxCmd {
    pub hdr: CommandHdr,
}

#[repr(C)]
pub struct InitCtxResp {
    pub hdr: ResponseHdr,
}

struct Context {
    parent: Option<&'static Context>,
    tci: [u8; profile::TCI_SIZE],
    simulation: bool,
}

impl Context {
    const fn new() -> Context {
        Context {
            parent: None,
            tci: [0; profile::TCI_SIZE],
            simulation: false,
        }
    }
}

pub struct DpeInstance {
    contexts: [Context; MAX_HANDLES],
}

impl DpeInstance {
    pub fn new() -> DpeInstance {
        const CONTEXT_INITIALIZER: Context = Context::new();
        DpeInstance {
            contexts: [CONTEXT_INITIALIZER; MAX_HANDLES],
        }
    }

    pub fn get_profile(
        &mut self,
        cmd: &mut GetProfileCmd,
        resp: &mut GetProfileResp,
    ) -> Result<(), DpeError> {
        Ok(())
    }

    pub fn initialize_context(
        &mut self,
        cmd: &mut InitCtxCmd,
        resp: &mut InitCtxResp,
    ) -> Result<(), DpeError> {
        Ok(())
    }
}
