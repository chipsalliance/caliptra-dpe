// Licensed under the Apache-2.0 license.
use crate::DPE_PROFILE;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
use zeroize::Zeroize;

#[repr(C, align(4))]
#[derive(
    Default, Copy, Clone, IntoBytes, FromBytes, PartialEq, Eq, KnownLayout, Immutable, Zeroize,
)]
pub struct TciNodeData {
    pub tci_type: u32,
    pub tci_cumulative: TciMeasurement,
    pub tci_current: TciMeasurement,
    pub locality: u32,
    pub svn: u32,
}

impl TciNodeData {
    pub const fn new() -> TciNodeData {
        TciNodeData {
            tci_type: 0,
            tci_cumulative: TciMeasurement([0; DPE_PROFILE.tci_size()]),
            tci_current: TciMeasurement([0; DPE_PROFILE.tci_size()]),
            locality: 0,
            svn: 0,
        }
    }
}

#[repr(transparent)]
#[derive(
    Copy, Clone, Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq, Zeroize,
)]
pub struct TciMeasurement(pub [u8; DPE_PROFILE.tci_size()]);

impl Default for TciMeasurement {
    fn default() -> Self {
        Self([0; DPE_PROFILE.tci_size()])
    }
}
