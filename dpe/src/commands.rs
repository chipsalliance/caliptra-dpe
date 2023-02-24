use crate::profile;
use crate::{DpeError, MAX_HANDLES};

fn set_flag(field: &mut u32, mask: u32, value: bool) {
    *field = if value { *field | mask } else { *field & !mask };
}

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

#[repr(transparent)]
pub struct TciMeasurement([u8; profile::TCI_SIZE]);

impl Default for TciMeasurement {
    fn default() -> Self {
        Self([0; profile::TCI_SIZE])
    }
}

#[repr(C, align(4))]
#[derive(Default)]
struct TciNodeData {
    tci_type: u32,

    // Bits
    // 31: INTERNAL
    // 30-0: Reserved. Must be zero
    flags: u32,
    tci_cumulative: TciMeasurement,
    tci_current: TciMeasurement,
}

impl TciNodeData {
    const INTERNAL_FLAG_MASK: u32 = 1 << 31;

    const fn flag_is_internal(self) -> bool {
        self.flags & Self::INTERNAL_FLAG_MASK != 0
    }

    fn set_flag_is_internal(&mut self, value: bool) {
        set_flag(&mut self.flags, Self::INTERNAL_FLAG_MASK, value);
    }

    const fn new() -> TciNodeData {
        TciNodeData {
            tci_type: 0,
            flags: 0,
            tci_cumulative: TciMeasurement([0; profile::TCI_SIZE]),
            tci_current: TciMeasurement([0; profile::TCI_SIZE]),
        }
    }
}

#[repr(C, align(4))]
struct Context {
    tci: TciNodeData,
    // Bitmap of the node indices that are children of this node
    children: u32,
    // Index in DPE instance of the parent context. 0xFF if this node is the root
    parent_idx: u8,
    simulation: bool,
    is_active: bool,
}

impl Context {
    const fn new() -> Context {
        Context {
            tci: TciNodeData::new(),
            children: 0,
            parent_idx: 0xFF,
            simulation: false,
            is_active: false,
        }
    }
}

pub struct DpeInstance {
    contexts: [Context; MAX_HANDLES],
}

impl DpeInstance {
    pub const fn new() -> DpeInstance {
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
