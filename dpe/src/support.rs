// Licensed under the Apache-2.0 license.

#[derive(Default)]
pub struct Support {
    pub simulation: bool,
    pub extend_tci: bool,
    pub auto_init: bool,
    pub tagging: bool,
    pub rotate_context: bool,
    pub certify_key: bool,
    pub certify_csr: bool,
    pub internal_info: bool,
    pub internal_dice: bool,
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
            | self.get_certify_key_flag()
            | self.get_certify_csr_flag()
            | self.get_internal_info_flag()
            | self.get_internal_dice_flag()
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
    fn get_certify_key_flag(&self) -> u32 {
        u32::from(self.certify_key) << 26
    }
    fn get_certify_csr_flag(&self) -> u32 {
        u32::from(self.certify_csr) << 25
    }
    fn get_internal_info_flag(&self) -> u32 {
        u32::from(self.internal_info) << 24
    }
    fn get_internal_dice_flag(&self) -> u32 {
        u32::from(self.internal_dice) << 23
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
        certify_key: true,
        certify_csr: false,
        internal_info: false,
        internal_dice: false,
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
            certify_key: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 26);
        // Supports certify csr.
        let flags = Support {
            certify_csr: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 25);
        // Supports internal info.
        let flags = Support {
            internal_info: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 24);
        // Supports internal DICE.
        let flags = Support {
            internal_dice: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 23);
        // Supports a couple combos.
        let flags = Support {
            simulation: true,
            auto_init: true,
            rotate_context: true,
            certify_csr: true,
            internal_dice: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(
            flags,
            (1 << 31) | (1 << 29) | (1 << 27) | (1 << 25) | (1 << 23)
        );
        let flags = Support {
            extend_tci: true,
            tagging: true,
            certify_key: true,
            internal_info: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, (1 << 30) | (1 << 28) | (1 << 26) | (1 << 24));
        // Supports everything.
        let flags = Support {
            simulation: true,
            extend_tci: true,
            auto_init: true,
            tagging: true,
            rotate_context: true,
            certify_key: true,
            certify_csr: true,
            internal_info: true,
            internal_dice: true,
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
        );
    }
}
