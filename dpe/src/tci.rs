// Licensed under the Apache-2.0 license.
use crate::{_set_flag, response::DpeErrorCode, DPE_PROFILE};
use core::mem::size_of;

#[repr(C, align(4))]
#[derive(Default, Copy, Clone)]
pub(crate) struct TciNodeData {
    pub tci_type: u32,

    // Bits
    // 31: INTERNAL
    // 30-0: Reserved. Must be zero
    flags: u32,
    pub tci_cumulative: TciMeasurement,
    pub tci_current: TciMeasurement,
}

impl TciNodeData {
    const INTERNAL_FLAG_MASK: u32 = 1 << 31;

    pub const fn flag_is_internal(&self) -> bool {
        self.flags & Self::INTERNAL_FLAG_MASK != 0
    }

    fn _set_flag_is_internal(&mut self, value: bool) {
        _set_flag(&mut self.flags, Self::INTERNAL_FLAG_MASK, value);
    }

    pub const fn new() -> TciNodeData {
        TciNodeData {
            tci_type: 0,
            flags: 0,
            tci_cumulative: TciMeasurement([0; DPE_PROFILE.get_tci_size()]),
            tci_current: TciMeasurement([0; DPE_PROFILE.get_tci_size()]),
        }
    }

    pub fn serialize(&self, dst: &mut [u8]) -> Result<usize, DpeErrorCode> {
        if dst.len() < size_of::<Self>() {
            return Err(DpeErrorCode::InternalError);
        }

        let mut offset: usize = 0;
        dst[offset..offset + size_of::<u32>()].copy_from_slice(&self.tci_type.to_le_bytes());
        offset += size_of::<u32>();
        dst[offset..offset + self.tci_cumulative.0.len()].copy_from_slice(&self.tci_cumulative.0);
        offset += self.tci_cumulative.0.len();
        dst[offset..offset + self.tci_current.0.len()].copy_from_slice(&self.tci_current.0);
        offset += self.tci_current.0.len();

        Ok(offset)
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct TciMeasurement(pub [u8; DPE_PROFILE.get_tci_size()]);

impl Default for TciMeasurement {
    fn default() -> Self {
        Self([0; DPE_PROFILE.get_tci_size()])
    }
}
