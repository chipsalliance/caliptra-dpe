/*++
Licensed under the Apache-2.0 license.
Abstract:
    Generic trait definition of Cryptographic functions.
--*/

#[cfg(feature = "openssl")]
pub use crate::openssl::*;

#[cfg(feature = "openssl")]
pub mod openssl;

use core::fmt::{Error, Write};

#[derive(Debug, Clone, Copy)]
pub enum AlgLen {
    Bit256,
    Bit384,
}

const MAX_HASH_SIZE: usize = 384 / 8;

impl AlgLen {
    pub const fn size(self) -> usize {
        match self {
            AlgLen::Bit256 => 256 / 8,
            AlgLen::Bit384 => 384 / 8,
        }
    }
}

#[derive(Debug)]
pub enum CryptoError {
    AbstractionLayer,
    CryptoLibError,
}

pub trait Hasher: Sized {
    /// Adds a chunk to the running hash.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Value to add to hash.
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError>;

    /// Finish a running hash operation and return the result.
    ///
    /// Once this function has been called, the object can no longer be used and
    /// a new one must be created to hash more data.
    ///
    /// # Arguments
    ///
    /// * `digest` - Where the computed digest should be written.
    fn finish(self, digest: &mut [u8]) -> Result<(), CryptoError>;
}

pub trait Crypto {
    type Cdi;
    type Hasher: Hasher;

    /// Fills the buffer with random values.
    ///
    /// # Arguments
    ///
    /// * `dst` - The buffer to be filled.
    fn rand_bytes(dst: &mut [u8]) -> Result<(), CryptoError>;

    /// Cryptographically hashes the given buffer.
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithm to use.
    /// * `bytes` - Value to be hashed.
    /// * `digest` - Where the computed digest should be written.
    fn hash(algs: AlgLen, bytes: &[u8], digest: &mut [u8]) -> Result<(), CryptoError> {
        let mut hasher = Self::hash_initialize(algs)?;
        hasher.update(bytes)?;
        hasher.finish(digest)
    }

    /// Compute the serial number of an ECDSA public key by computing the hash
    /// over the point in uncompressed format.
    ///
    /// This function outputs the serial number as a hex string
    ///
    /// # Arguments
    ///
    /// * `algs` - Length of algorithm to use.
    /// * `x` - x portion of EC public key
    /// * `y` - y portion of EC public key
    /// * `serial` - Output buffer to write serial number
    fn get_pubkey_serial(
        algs: AlgLen,
        x: &[u8],
        y: &[u8],
        serial: &mut [u8],
    ) -> Result<(), CryptoError> {
        if serial.len() < algs.size() * 2 {
            return Err(CryptoError::CryptoLibError);
        }

        let mut hasher = Self::hash_initialize(algs)?;
        let mut pub_digest = [0u8; MAX_HASH_SIZE];
        hasher.update(&[0x4u8])?;
        hasher.update(x)?;
        hasher.update(y)?;
        hasher.finish(&mut pub_digest[..algs.size()])?;

        let mut w = BufWriter {
            buf: serial,
            offset: 0,
        };
        w.write_hex_str(&pub_digest[..algs.size()])
    }

    /// Initialize a running hash. Returns an object that will be able to complete the rest.
    ///
    /// Used for hashing multiple buffers that may not be in consecutive memory.
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithm to use.
    fn hash_initialize(algs: AlgLen) -> Result<Self::Hasher, CryptoError>;

    /// Derive a CDI based on the current base CDI and measurements.
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `measurement_digest` - A digest of the measurements which should be
    ///   used for CDI derivation
    /// * `info` - Caller-supplied info string to use in CDI derivation
    fn derive_cdi(
        algs: AlgLen,
        measurement_digest: &[u8],
        info: &[u8],
    ) -> Result<Self::Cdi, CryptoError>;

    /// Derives an ECDSA keypair from `cdi` and returns the public key
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `cdi` - CDI from which to derive the signing key
    /// * `label` - Caller-supplied label to use in asymmetric key derivation
    /// * `info` - Caller-supplied info string to use in asymmetric key derivation
    /// * `pub_x` - Destination for public key's X component.
    /// * `pub_y` - Destination for public key's Y component.
    ///
    /// Returns a derived public key
    fn derive_ecdsa_pub(
        algs: AlgLen,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
        pub_x: &mut [u8],
        pub_y: &mut [u8],
    ) -> Result<(), CryptoError>;

    /// Sign `digest` with the platform Alias Key
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `digest` - Digest of data to be signed.
    /// * `sig_r` - Destination for signature's R component.
    /// * `sig_s` - Destination for signature's S component.
    fn ecdsa_sign_with_alias(
        algs: AlgLen,
        digest: &[u8],
        sig_r: &mut [u8],
        sig_s: &mut [u8],
    ) -> Result<(), CryptoError>;

    /// Compute the serial number string for the alias public key
    ///
    /// # Arguments
    ///
    /// * `algs` - Length of algorithm to use.
    /// * `serial` - Output buffer to write serial number
    fn get_ecdsa_alias_serial(algs: AlgLen, serial: &mut [u8]) -> Result<(), CryptoError>;
}

/// Writer for a static buffer
struct BufWriter<'a> {
    buf: &'a mut [u8],
    offset: usize,
}

impl Write for BufWriter<'_> {
    fn write_str(&mut self, s: &str) -> Result<(), Error> {
        if s.len() > self.buf.len().saturating_sub(self.offset) {
            return Err(Error::default());
        }

        self.buf[self.offset..self.offset + s.len()].copy_from_slice(s.as_bytes());
        self.offset += s.len();

        Ok(())
    }
}

impl BufWriter<'_> {
    fn write_hex_str(&mut self, src: &[u8]) -> Result<(), CryptoError> {
        for &b in src {
            write!(self, "{b:02x}").map_err(|_| CryptoError::CryptoLibError)?;
        }

        Ok(())
    }
}
