/*++
Licensed under the Apache-2.0 license.

Abstract:
    Generic trait definition of Cryptographic functions.
--*/

use crate::{response::DpeErrorCode, profile};

pub trait Crypto {
    type Rng: Rng;
    type Hash: Hash;
    fn rng(&mut self) -> &mut Self::Rng;
    fn hash(&mut self) -> &mut Self::Hash;
}

pub trait Rng {
    fn rand_bytes(&self, dst: &mut [u8]) -> Result<(), DpeErrorCode>;
}

pub trait Hash {
    fn hash(
        &self,
        bytes: &[u8],
        digest: &mut [u8; profile::DIGEST_SIZE],
    ) -> Result<(), DpeErrorCode>;
}
