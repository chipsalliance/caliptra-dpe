/*++
Licensed under the Apache-2.0 license.

Abstract:
    Helper struct for controlling and viewing bitmaps.
--*/

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Default)]
pub struct Bitmap(u32);

impl Bitmap {
    /// Empty flags.
    pub const fn const_default() -> Bitmap {
        Bitmap(0)
    }

    /// Bitmap with only one flag set.
    pub const fn flag(flag: usize) -> Bitmap {
        assert!(flag < u32::BITS as usize);
        Bitmap(1 << flag)
    }

    /// Get the value of the given flag.
    pub const fn get(&self, flag: usize) -> bool {
        assert!(flag < u32::BITS as usize);
        self.0 & 1 << flag != 0
    }

    /// Get all of the flags together.
    pub const fn get_all(&self) -> u32 {
        self.0
    }

    /// Set a flag to the given value.
    pub fn set(&mut self, flag: usize, value: bool) {
        assert!(flag < u32::BITS as usize);
        let mask = 1 << flag;
        self.0 = if value { self.0 | mask } else { self.0 & !mask };
    }

    /// Iterate over all of the bits set to 1 in the bitmap. Each iteration returns the bit index. 0
    /// is the least significant and 31 is the most significant.
    ///
    /// # Arguments
    ///
    /// * `mask` - bits to be ignored
    pub fn iter(&self, mask: u32) -> BitmapIter {
        BitmapIter(self.0 & !mask)
    }

    #[cfg(test)]
    /// Initialize the bitmap with the given flags pre-set.
    pub const fn new_mask(flags: u32) -> Bitmap {
        Bitmap(flags)
    }
}

impl From<u32> for Bitmap {
    fn from(flags: u32) -> Self {
        Bitmap(flags)
    }
}

pub struct BitmapIter(u32);

impl Iterator for BitmapIter {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        if self.0 == 0 {
            return None;
        }
        let idx = self.0.trailing_zeros() as usize;
        self.0 &= !(1 << idx);
        Some(idx)
    }
}
