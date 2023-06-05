// Licensed under the Apache-2.0 license.
use crate::{_set_flag, response::DpeErrorCode, DPE_PROFILE};
use core::mem::size_of;
use zerocopy::AsBytes;

#[repr(C, align(4))]
#[derive(Default, Copy, Clone, AsBytes)]
#[cfg_attr(test, derive(zerocopy::FromBytes))]
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

        dst[offset..offset + size_of::<u32>()].copy_from_slice(&self.flags.to_le_bytes());
        offset += size_of::<u32>();

        dst[offset..offset + self.tci_cumulative.0.len()].copy_from_slice(&self.tci_cumulative.0);
        offset += self.tci_cumulative.0.len();

        dst[offset..offset + self.tci_current.0.len()].copy_from_slice(&self.tci_current.0);
        offset += self.tci_current.0.len();

        Ok(offset)
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, AsBytes)]
#[cfg_attr(test, derive(PartialEq, Eq, zerocopy::FromBytes))]
pub struct TciMeasurement(pub [u8; DPE_PROFILE.get_tci_size()]);

impl Default for TciMeasurement {
    fn default() -> Self {
        Self([0; DPE_PROFILE.get_tci_size()])
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use zerocopy::AsBytes;

    #[test]
    fn test_serialize_tci_node_data() {
        let tci_node_data = TciNodeData {
            tci_type: 0x1234_5678,
            flags: 0x9876_5432,
            tci_cumulative: TciMeasurement(core::array::from_fn(|i| (i + 1) as u8)),
            tci_current: TciMeasurement(core::array::from_fn(|i| (0xff - i) as u8)),
        };
        // Test too small slice.
        let mut response_buffer = [0; size_of::<TciNodeData>() - 1];
        assert_eq!(
            Err(DpeErrorCode::InternalError),
            tci_node_data.serialize(response_buffer.as_mut_slice())
        );
        let mut response_buffer = [0; size_of::<TciNodeData>()];

        assert_eq!(
            2 * DPE_PROFILE.get_tci_size() + 2 * 4,
            tci_node_data.serialize(&mut response_buffer).unwrap()
        );
        assert_eq!(tci_node_data.as_bytes(), response_buffer);
    }
}
