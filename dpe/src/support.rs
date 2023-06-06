// Licensed under the Apache-2.0 license.

#[derive(Default)]
pub struct Support {
    pub simulation: bool,
    pub extend_tci: bool,
    pub auto_init: bool,
    pub tagging: bool,
    pub rotate_context: bool,
    pub x509: bool,
    pub csr: bool,
    pub is_symmetric: bool,
    pub nd_derivation: bool,
    pub internal_info: bool,
    pub internal_dice: bool,
    pub is_ca: bool,
}

impl Support {
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
            | self.get_nd_derivation_flag()
            | self.get_internal_info_flag()
            | self.get_internal_dice_flag()
            | self.get_is_ca_flag()
    }
    fn get_simulation_flag(&self) -> u32 {
        u32::from(self.simulation) << 31
    }
    fn get_extend_tci_flag(&self) -> u32 {
        u32::from(self.extend_tci) << 30
    }
    fn get_auto_init_flag(&self) -> u32 {
        u32::from(self.auto_init) << 29
    }
    fn get_tagging_flag(&self) -> u32 {
        u32::from(self.tagging) << 28
    }
    fn get_rotate_context_flag(&self) -> u32 {
        u32::from(self.rotate_context) << 27
    }
    fn get_x509_flag(&self) -> u32 {
        u32::from(self.x509) << 26
    }
    fn get_csr_flag(&self) -> u32 {
        u32::from(self.csr) << 25
    }
    fn get_is_symmetric_flag(&self) -> u32 {
        u32::from(self.is_symmetric) << 24
    }
    fn get_nd_derivation_flag(&self) -> u32 {
        u32::from(self.nd_derivation) << 23
    }
    fn get_internal_info_flag(&self) -> u32 {
        u32::from(self.internal_info) << 22
    }
    fn get_internal_dice_flag(&self) -> u32 {
        u32::from(self.internal_dice) << 21
    }
    fn get_is_ca_flag(&self) -> u32 {
        u32::from(self.is_ca) << 20
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    pub const SUPPORT: Support = Support {
        simulation: true,
        extend_tci: false,
        auto_init: true,
        tagging: true,
        rotate_context: true,
        x509: true,
        csr: false,
        is_symmetric: false,
        nd_derivation: false,
        internal_info: false,
        internal_dice: false,
        is_ca: false,
    };

    #[test]
    fn test_get_support_flags() {
        // Supports simulation flag.
        let flags = Support {
            simulation: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 31);
        // Supports extended TCI flag.
        let flags = Support {
            extend_tci: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 30);
        // Supports auto-init.
        let flags = Support {
            auto_init: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 29);
        // Supports tagging.
        let flags = Support {
            tagging: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 28);
        // Supports rotate context.
        let flags = Support {
            rotate_context: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 27);
        // Supports certify key.
        let flags = Support {
            x509: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 26);
        // Supports certify csr.
        let flags = Support {
            csr: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 25);
        // Supports is symmetric.
        let flags = Support {
            is_symmetric: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 24);
        // Supports nd derivation.
        let flags = Support {
            nd_derivation: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 23);
        // Supports internal info.
        let flags = Support {
            internal_info: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 22);
        // Supports internal DICE.
        let flags = Support {
            internal_dice: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 21);
        // Supports a couple combos.
        let flags = Support {
            simulation: true,
            auto_init: true,
            rotate_context: true,
            csr: true,
            nd_derivation: true,
            internal_dice: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(
            flags,
            (1 << 31) | (1 << 29) | (1 << 27) | (1 << 25) | (1 << 23) | (1 << 21)
        );
        let flags = Support {
            extend_tci: true,
            tagging: true,
            x509: true,
            is_symmetric: true,
            internal_info: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(
            flags,
            (1 << 30) | (1 << 28) | (1 << 26) | (1 << 24) | (1 << 22)
        );
        // Supports everything.
        let flags = Support {
            simulation: true,
            extend_tci: true,
            auto_init: true,
            tagging: true,
            rotate_context: true,
            x509: true,
            csr: true,
            is_symmetric: true,
            nd_derivation: true,
            internal_info: true,
            internal_dice: true,
            is_ca: true,
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
                | (1 << 20)
        );
    }
}
