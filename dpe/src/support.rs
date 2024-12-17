// Licensed under the Apache-2.0 license.
use bitflags::bitflags;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
use zeroize::Zeroize;

#[derive(Default, IntoBytes, FromBytes, KnownLayout, Immutable, Zeroize, Copy, Clone)]
#[repr(C)]
pub struct Support(u32);

bitflags! {
    impl Support: u32 {
        const SIMULATION = 1u32 << 31;
        const RECURSIVE = 1u32 << 30;
        const AUTO_INIT = 1u32 << 29;
        const ROTATE_CONTEXT = 1u32 << 27;
        const X509 = 1u32 << 26;
        const CSR = 1u32 << 25;
        const IS_SYMMETRIC = 1u32 << 24;
        const INTERNAL_INFO = 1u32 << 22;
        const INTERNAL_DICE = 1u32 << 21;
        const RETAIN_PARENT_CONTEXT = 1u32 << 19;
    }
}

impl Support {
    pub fn simulation(&self) -> bool {
        self.contains(Support::SIMULATION)
    }
    pub fn recursive(&self) -> bool {
        self.contains(Support::RECURSIVE)
    }
    pub fn auto_init(&self) -> bool {
        self.contains(Support::AUTO_INIT)
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
    pub fn retain_parent_context(&self) -> bool {
        self.contains(Support::RETAIN_PARENT_CONTEXT)
    }

    /// Disables supported features based on compilation features
    pub fn preprocess_support(&self) -> Support {
        #[allow(unused_mut)]
        let mut support = Support::empty();
        #[cfg(feature = "disable_simulation")]
        {
            support.insert(Support::SIMULATION);
        }
        #[cfg(feature = "disable_recursive")]
        {
            support.insert(Support::RECURSIVE);
        }
        #[cfg(feature = "disable_auto_init")]
        {
            support.insert(Support::AUTO_INIT);
        }
        #[cfg(feature = "disable_rotate_context")]
        {
            support.insert(Support::ROTATE_CONTEXT);
        }
        #[cfg(feature = "disable_x509")]
        {
            support.insert(Support::X509);
        }
        #[cfg(feature = "disable_csr")]
        {
            support.insert(Support::CSR);
        }
        #[cfg(feature = "disable_is_symmetric")]
        {
            support.insert(Support::IS_SYMMETRIC);
        }
        #[cfg(feature = "disable_internal_info")]
        {
            support.insert(Support::INTERNAL_INFO);
        }
        #[cfg(feature = "disable_internal_dice")]
        {
            support.insert(Support::INTERNAL_DICE);
        }
        #[cfg(feature = "disable_retain_parent_context")]
        {
            support.insert(Support::RETAIN_PARENT_CONTEXT);
        }
        self.difference(support)
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::bitflags_join;

    pub const SUPPORT: Support = bitflags_join!(
        Support::SIMULATION,
        Support::AUTO_INIT,
        Support::ROTATE_CONTEXT,
        Support::X509,
        Support::RETAIN_PARENT_CONTEXT
    );

    #[test]
    fn test_get_support_flags() {
        // Supports simulation flag.
        let flags = Support::SIMULATION.bits();
        assert_eq!(flags, 1 << 31);
        // Supports recursive flag.
        let flags = Support::RECURSIVE.bits();
        assert_eq!(flags, 1 << 30);
        // Supports auto-init.
        let flags = Support::AUTO_INIT.bits();
        assert_eq!(flags, 1 << 29);
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
        assert_eq!(flags, 1 << 22);
        // Supports internal DICE.
        let flags = Support::INTERNAL_DICE.bits();
        assert_eq!(flags, 1 << 21);
        let flags = Support::RETAIN_PARENT_CONTEXT.bits();
        assert_eq!(flags, 1 << 19);
        // Supports a couple combos.
        let flags = (Support::SIMULATION
            | Support::AUTO_INIT
            | Support::ROTATE_CONTEXT
            | Support::CSR
            | Support::INTERNAL_DICE)
            .bits();
        assert_eq!(
            flags,
            (1 << 31) | (1 << 29) | (1 << 27) | (1 << 25) | (1 << 21)
        );
        let flags =
            (Support::RECURSIVE | Support::X509 | Support::IS_SYMMETRIC | Support::INTERNAL_INFO)
                .bits();
        assert_eq!(flags, (1 << 30) | (1 << 26) | (1 << 24) | (1 << 22));
        // Supports everything.
        let flags = Support::all().bits();
        assert_eq!(
            flags,
            (1 << 31)
                | (1 << 30)
                | (1 << 29)
                | (1 << 27)
                | (1 << 26)
                | (1 << 25)
                | (1 << 24)
                | (1 << 22)
                | (1 << 21)
                | (1 << 19)
        );
    }
}
