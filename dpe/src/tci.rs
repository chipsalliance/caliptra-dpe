// Licensed under the Apache-2.0 license.
use crate::DPE_PROFILE;
use zerocopy::{AsBytes, FromBytes};
use zeroize::ZeroizeOnDrop;

#[repr(C, align(4))]
#[derive(Default, Clone, AsBytes, FromBytes, PartialEq, Eq, ZeroizeOnDrop)]
pub struct TciNodeData {
    pub tci_type: u32,
    pub tci_cumulative: TciMeasurement,
    pub tci_current: TciMeasurement,
    pub locality: u32,
}

impl TciNodeData {
    pub const fn new() -> TciNodeData {
        TciNodeData {
            tci_type: 0,
            tci_cumulative: TciMeasurement([0; DPE_PROFILE.get_tci_size()]),
            tci_current: TciMeasurement([0; DPE_PROFILE.get_tci_size()]),
            locality: 0,
        }
    }
}

#[repr(transparent)]
#[derive(Clone, Debug, AsBytes, FromBytes, PartialEq, Eq, ZeroizeOnDrop)]
pub struct TciMeasurement(pub [u8; DPE_PROFILE.get_tci_size()]);

impl Default for TciMeasurement {
    fn default() -> Self {
        Self([0; DPE_PROFILE.get_tci_size()])
    }
}
