// Licensed under the Apache-2.0 license.
use crate::U8Bool;
use zerocopy::{AsBytes, FromBytes};

#[derive(Default, AsBytes, FromBytes)]
#[repr(C)]
pub struct Support {
    pub simulation: U8Bool,
    pub extend_tci: U8Bool,
    pub auto_init: U8Bool,
    pub tagging: U8Bool,
    pub rotate_context: U8Bool,
    pub x509: U8Bool,
    pub csr: U8Bool,
    pub is_symmetric: U8Bool,
    pub internal_info: U8Bool,
    pub internal_dice: U8Bool,
    pub is_ca: U8Bool,
}

impl Support {
    pub fn simulation(&self) -> bool {
        self.simulation.get()
    }
    pub fn extend_tci(&self) -> bool {
        self.extend_tci.get()
    }
    pub fn auto_init(&self) -> bool {
        self.auto_init.get()
    }
    pub fn tagging(&self) -> bool {
        self.tagging.get()
    }
    pub fn rotate_context(&self) -> bool {
        self.rotate_context.get()
    }
    pub fn x509(&self) -> bool {
        self.x509.get()
    }
    pub fn csr(&self) -> bool {
        self.csr.get()
    }
    pub fn is_symmetric(&self) -> bool {
        self.is_symmetric.get()
    }
    pub fn internal_info(&self) -> bool {
        self.internal_info.get()
    }
    pub fn internal_dice(&self) -> bool {
        self.internal_dice.get()
    }
    pub fn is_ca(&self) -> bool {
        self.is_ca.get()
    }

    /// Returns all the flags bit-wise OR'ed together in the same configuration as the `GetProfile`
    /// command.
    pub fn get_flags(&self) -> u32 {
        self.get_simulation_flag()
            | self.get_extend_tci_flag()
            | self.get_auto_init_flag()
            | self.get_tagging_flag()
            | self.get_rotate_context_flag()
            | self.get_x509_flag()
            | self.get_csr_flag()
            | self.get_is_symmetric_flag()
            | self.get_internal_info_flag()
            | self.get_internal_dice_flag()
            | self.get_is_ca_flag()
    }
    fn get_simulation_flag(&self) -> u32 {
        u32::from(self.simulation.get()) << 31
    }
    fn get_extend_tci_flag(&self) -> u32 {
        u32::from(self.extend_tci.get()) << 30
    }
    fn get_auto_init_flag(&self) -> u32 {
        u32::from(self.auto_init.get()) << 29
    }
    fn get_tagging_flag(&self) -> u32 {
        u32::from(self.tagging.get()) << 28
    }
    fn get_rotate_context_flag(&self) -> u32 {
        u32::from(self.rotate_context.get()) << 27
    }
    fn get_x509_flag(&self) -> u32 {
        u32::from(self.x509.get()) << 26
    }
    fn get_csr_flag(&self) -> u32 {
        u32::from(self.csr.get()) << 25
    }
    fn get_is_symmetric_flag(&self) -> u32 {
        u32::from(self.is_symmetric.get()) << 24
    }
    fn get_internal_info_flag(&self) -> u32 {
        u32::from(self.internal_info.get()) << 23
    }
    fn get_internal_dice_flag(&self) -> u32 {
        u32::from(self.internal_dice.get()) << 22
    }
    fn get_is_ca_flag(&self) -> u32 {
        u32::from(self.is_ca.get()) << 21
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    pub const SUPPORT: Support = Support {
        simulation: U8Bool::new(true),
        extend_tci: U8Bool::new(false),
        auto_init: U8Bool::new(true),
        tagging: U8Bool::new(true),
        rotate_context: U8Bool::new(true),
        x509: U8Bool::new(true),
        csr: U8Bool::new(false),
        is_symmetric: U8Bool::new(false),
        internal_info: U8Bool::new(false),
        internal_dice: U8Bool::new(false),
        is_ca: U8Bool::new(false),
    };

    #[test]
    fn test_get_support_flags() {
        // Supports simulation flag.
        let flags = Support {
            simulation: U8Bool::new(true),
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 31);
        // Supports extended TCI flag.
        let flags = Support {
            extend_tci: U8Bool::new(true),
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 30);
        // Supports auto-init.
        let flags = Support {
            auto_init: U8Bool::new(true),
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 29);
        // Supports tagging.
        let flags = Support {
            tagging: U8Bool::new(true),
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 28);
        // Supports rotate context.
        let flags = Support {
            rotate_context: U8Bool::new(true),
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 27);
        // Supports certify key.
        let flags = Support {
            x509: U8Bool::new(true),
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 26);
        // Supports certify csr.
        let flags = Support {
            csr: U8Bool::new(true),
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 25);
        // Supports is symmetric.
        let flags = Support {
            is_symmetric: U8Bool::new(true),
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 24);
        // Supports internal info.
        let flags = Support {
            internal_info: U8Bool::new(true),
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 23);
        // Supports internal DICE.
        let flags = Support {
            internal_dice: U8Bool::new(true),
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 22);
        // Supports a couple combos.
        let flags = Support {
            simulation: U8Bool::new(true),
            auto_init: U8Bool::new(true),
            rotate_context: U8Bool::new(true),
            csr: U8Bool::new(true),
            internal_dice: U8Bool::new(true),
            ..Support::default()
        }
        .get_flags();
        assert_eq!(
            flags,
            (1 << 31) | (1 << 29) | (1 << 27) | (1 << 25) | (1 << 22)
        );
        let flags = Support {
            extend_tci: U8Bool::new(true),
            tagging: U8Bool::new(true),
            x509: U8Bool::new(true),
            is_symmetric: U8Bool::new(true),
            internal_info: U8Bool::new(true),
            ..Support::default()
        }
        .get_flags();
        assert_eq!(
            flags,
            (1 << 30) | (1 << 28) | (1 << 26) | (1 << 24) | (1 << 23)
        );
        // Supports everything.
        let flags = Support {
            simulation: U8Bool::new(true),
            extend_tci: U8Bool::new(true),
            auto_init: U8Bool::new(true),
            tagging: U8Bool::new(true),
            rotate_context: U8Bool::new(true),
            x509: U8Bool::new(true),
            csr: U8Bool::new(true),
            is_symmetric: U8Bool::new(true),
            internal_info: U8Bool::new(true),
            internal_dice: U8Bool::new(true),
            is_ca: U8Bool::new(true),
        }
        .get_flags();
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
