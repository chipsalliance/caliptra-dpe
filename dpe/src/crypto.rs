/*++
Licensed under the Apache-2.0 license.
Abstract:
    Generic trait definition of Cryptographic functions.
--*/

use crate::response::DpeErrorCode;

pub trait Crypto {
    /// Fills the buffer with random values.
    ///
    /// # Arguments
    ///
    /// * `dst` - The buffer to be filled.
    fn rand_bytes(&self, dst: &mut [u8]) -> Result<(), DpeErrorCode>;

    /// Cryptographically hashes the given buffer.
    ///
    /// # Arguments
    ///
    /// * `profile` - Which profile is being used. This will tell the platform which algorithm to
    ///   use.
    /// * `bytes` - Value to be hashed.
    /// * `digest` - Where the computed digest should be written.
    fn _hash(&self, profile: u32, bytes: &[u8], digest: &mut [u8]) -> Result<(), DpeErrorCode>;
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Uses known values for outputs to simulate operations that can be easily checked in tests.
    pub struct DeterministicCrypto;

    impl Crypto for DeterministicCrypto {
        /// Uses incrementing values for each byte.
        fn rand_bytes(&self, dst: &mut [u8]) -> Result<(), DpeErrorCode> {
            for (i, char) in dst.iter_mut().enumerate() {
                *char = (i + 1) as u8;
            }
            Ok(())
        }

        fn _hash(
            &self,
            _profile: u32,
            _bytes: &[u8],
            _digest: &mut [u8],
        ) -> Result<(), DpeErrorCode> {
            todo!()
        }
    }
}
