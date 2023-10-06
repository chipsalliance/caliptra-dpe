// Licensed under the Apache-2.0 license.
use bitflags::bitflags;
use zerocopy::{AsBytes, FromBytes};
use zeroize::Zeroize;

#[derive(Default, AsBytes, FromBytes, Zeroize)]
#[repr(C)]
pub struct Support(u32);

bitflags! {
    impl Support: u32 {
        const SIMULATION = 1u32 << 31;
        const EXTEND_TCI = 1u32 << 30;
        const AUTO_INIT = 1u32 << 29;
        const TAGGING = 1u32 << 28;
        const ROTATE_CONTEXT = 1u32 << 27;
        const X509 = 1u32 << 26;
        const CSR = 1u32 << 25;
        const IS_SYMMETRIC = 1u32 << 24;
        const INTERNAL_INFO = 1u32 << 23;
        const INTERNAL_DICE = 1u32 << 22;
        const IS_CA = 1u32 << 21;
    }
}

impl Support {
    pub fn simulation(&self) -> bool {
        self.contains(Support::SIMULATION)
    }
    pub fn extend_tci(&self) -> bool {
        self.contains(Support::EXTEND_TCI)
    }
    pub fn auto_init(&self) -> bool {
        self.contains(Support::AUTO_INIT)
    }
    pub fn tagging(&self) -> bool {
        self.contains(Support::TAGGING)
    }
    pub fn rotate_context(&self) -> bool {
        self.contains(Support::ROTATE_CONTEXT)
    }
    pub fn x509(&self) -> bool {
        self.contains(Support::X509)
    }
    pub fn csr(&self) -> bool {
        self.contains(Support::CSR)
    }
    pub fn is_symmetric(&self) -> bool {
        self.contains(Support::IS_SYMMETRIC)
    }
    pub fn internal_info(&self) -> bool {
        self.contains(Support::INTERNAL_INFO)
    }
    pub fn internal_dice(&self) -> bool {
        self.contains(Support::INTERNAL_DICE)
    }
    pub fn is_ca(&self) -> bool {
        self.contains(Support::IS_CA)
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::bitflags_join;

    pub const SUPPORT: Support = bitflags_join!(
        Support::SIMULATION,
        Support::AUTO_INIT,
        Support::TAGGING,
        Support::ROTATE_CONTEXT,
        Support::X509
    );

    #[test]
    fn test_get_support_flags() {
        // Supports simulation flag.
        let flags = Support::SIMULATION.bits();
        assert_eq!(flags, 1 << 31);
        // Supports extended TCI flag.
        let flags = Support::EXTEND_TCI.bits();
        assert_eq!(flags, 1 << 30);
        // Supports auto-init.
        let flags = Support::AUTO_INIT.bits();
        assert_eq!(flags, 1 << 29);
        // Supports tagging.
        let flags = Support::TAGGING.bits();
        assert_eq!(flags, 1 << 28);
        // Supports rotate context.
        let flags = Support::ROTATE_CONTEXT.bits();
        assert_eq!(flags, 1 << 27);
        // Supports certify key.
        let flags = Support::X509.bits();
        assert_eq!(flags, 1 << 26);
        // Supports certify csr.
        let flags = Support::CSR.bits();
        assert_eq!(flags, 1 << 25);
        // Supports is symmetric.
        let flags = Support::IS_SYMMETRIC.bits();
        assert_eq!(flags, 1 << 24);
        // Supports internal info.
        let flags = Support::INTERNAL_INFO.bits();
        assert_eq!(flags, 1 << 23);
        // Supports internal DICE.
        let flags = Support::INTERNAL_DICE.bits();
        assert_eq!(flags, 1 << 22);
        // Supports is ca.
        let flags = Support::IS_CA.bits();
        assert_eq!(flags, 1 << 21);
        // Supports a couple combos.
        let flags = (Support::SIMULATION
            | Support::AUTO_INIT
            | Support::ROTATE_CONTEXT
            | Support::CSR
            | Support::INTERNAL_DICE)
            .bits();
        assert_eq!(
            flags,
            (1 << 31) | (1 << 29) | (1 << 27) | (1 << 25) | (1 << 22)
        );
        let flags = (Support::EXTEND_TCI
            | Support::TAGGING
            | Support::X509
            | Support::IS_SYMMETRIC
            | Support::INTERNAL_INFO)
            .bits();
        assert_eq!(
            flags,
            (1 << 30) | (1 << 28) | (1 << 26) | (1 << 24) | (1 << 23)
        );
        // Supports everything.
        let flags = Support::all().bits();
        assert_eq!(
            flags,
            (1 << 31)
                | (1 << 30)
                | (1 << 29)
                | (1 << 28)
                | (1 << 27)
                | (1 << 26)
                | (1 << 25)
                | (1 << 24)
                | (1 << 23)
                | (1 << 22)
                | (1 << 21)
        );
    }
}
