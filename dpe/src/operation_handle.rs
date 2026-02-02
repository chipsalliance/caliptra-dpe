// Licensed under the Apache-2.0 license.

use constant_time_eq::constant_time_eq_16;
use crypto::Crypto;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
use zeroize::Zeroize;

use crate::{
    dpe_instance::{DpeEnv, DpeTypes},
    response::DpeErrorCode,
};

#[repr(C)]
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    IntoBytes,
    FromBytes,
    Immutable,
    KnownLayout,
    Zeroize,
    PartialEq,
    Eq,
)]
pub struct OperationHandle(pub [u8; OperationHandle::SIZE]);

impl OperationHandle {
    pub const SIZE: usize = 16;
    pub const MAX_NEW_HANDLE_ATTEMPTS: usize = 8;
    const DEFAULT: OperationHandle = OperationHandle([0; Self::SIZE]);

    /// Returns the default operation handle.
    pub const fn default() -> OperationHandle {
        Self::DEFAULT
    }

    pub fn generate(env: &mut DpeEnv<impl DpeTypes>) -> Result<OperationHandle, DpeErrorCode> {
        for _ in 0..Self::MAX_NEW_HANDLE_ATTEMPTS {
            let mut handle = OperationHandle::default();
            env.crypto.rand_bytes(&mut handle.0)?;
            if !handle.is_default() {
                return Ok(handle);
            }
        }
        Err(DpeErrorCode::InternalError)
    }

    #[inline(never)]
    pub fn equals(&self, other: &OperationHandle) -> bool {
        constant_time_eq_16(&self.0, &other.0)
    }

    /// Whether the handle is the default operation handle.
    pub fn is_default(&self) -> bool {
        self.equals(&Self::DEFAULT)
    }

    /// Whether the handle is all zeros.
    pub fn blank(&self) -> bool {
        self.is_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dpe_instance::tests::test_env, State};

    #[test]
    fn test_operation_blank_and_default() {
        let handle = OperationHandle([1; OperationHandle::SIZE]);
        assert!(!handle.is_default());
        assert!(!handle.blank());

        let handle = OperationHandle::default();
        assert!(handle.is_default());
        assert!(handle.blank());
    }

    #[test]
    fn test_operation_handle_generation() {
        let mut state = State::default();
        let mut env = test_env(&mut state);
        let handle = OperationHandle::generate(&mut env).unwrap();
        assert!(!handle.is_default());
        assert!(!handle.blank());
    }
}
