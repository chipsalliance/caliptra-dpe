// Licensed under the Apache-2.0 license

#![no_std]

#[derive(Debug, PartialEq, Eq)]
pub enum ResponseBufError {
    Overflow,
}

/// Sink for a serialized DPE response.
pub trait ResponseBuffer {
    /// Zero the entire backing storage.
    fn clear(&mut self) -> Result<(), ResponseBufError>;

    /// Write `bytes` starting at `offset`.
    ///
    /// Returns `Overflow` if `offset + bytes.len()` exceeds the backing
    /// store capacity.
    fn write_at(&mut self, offset: usize, bytes: &[u8]) -> Result<(), ResponseBufError>;

    /// Read back a range of already-written bytes by invoking `f` one or more
    /// times with consecutive chunks that together cover exactly the bytes in
    /// `range`.
    ///
    /// Implementations can `f` exactly once, e.g. if they are backed by
    /// contiguous storage.
    /// Implementations backed by word-addressed storage (e.g. MBOX SRAM) may
    /// call `f` multiple times to handle unaligned head/tail bytes.
    fn read_range(
        &self,
        range: core::ops::Range<usize>,
        f: &mut dyn FnMut(&[u8]) -> Result<(), ResponseBufError>,
    ) -> Result<(), ResponseBufError>;

    /// Total number of bytes the backing store can hold.
    fn capacity(&self) -> usize;
}

/// A [`ResponseBuffer`] view that shifts every offset by a fixed `base`.
///
/// Writes at `offset` on this wrapper land at `base + offset` in the
/// underlying buffer.  Useful when one response buffer is divided into a header
/// section (written directly at absolute offsets by the caller) and a body
/// section managed by a subsystem that writes relative to its own 0-origin.
pub struct OffsetResponseBuffer<'a> {
    inner: &'a mut dyn ResponseBuffer,
    base: usize,
}

impl<'a> OffsetResponseBuffer<'a> {
    pub fn new(inner: &'a mut dyn ResponseBuffer, base: usize) -> Self {
        Self { inner, base }
    }
}

impl ResponseBuffer for OffsetResponseBuffer<'_> {
    fn clear(&mut self) -> Result<(), ResponseBufError> {
        self.inner.clear()
    }

    fn write_at(&mut self, offset: usize, bytes: &[u8]) -> Result<(), ResponseBufError> {
        let adjusted = self
            .base
            .checked_add(offset)
            .ok_or(ResponseBufError::Overflow)?;
        self.inner.write_at(adjusted, bytes)
    }

    fn read_range(
        &self,
        range: core::ops::Range<usize>,
        f: &mut dyn FnMut(&[u8]) -> Result<(), ResponseBufError>,
    ) -> Result<(), ResponseBufError> {
        let start = self
            .base
            .checked_add(range.start)
            .ok_or(ResponseBufError::Overflow)?;
        let end = self
            .base
            .checked_add(range.end)
            .ok_or(ResponseBufError::Overflow)?;
        self.inner.read_range(start..end, f)
    }

    fn capacity(&self) -> usize {
        self.inner.capacity().saturating_sub(self.base)
    }
}

/// `ResponseBuffer` backed by a mutable byte slice.  Suitable for tests and
/// any context with writable ordinary memory (e.g. the DPE openssl cert tests).
pub struct SliceResponseBuffer<'a> {
    buf: &'a mut [u8],
}

impl<'a> SliceResponseBuffer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf }
    }
}

impl<'a> ResponseBuffer for SliceResponseBuffer<'a> {
    fn clear(&mut self) -> Result<(), ResponseBufError> {
        for b in self.buf.iter_mut() {
            *b = 0;
        }
        Ok(())
    }

    fn write_at(&mut self, offset: usize, bytes: &[u8]) -> Result<(), ResponseBufError> {
        let end = offset
            .checked_add(bytes.len())
            .ok_or(ResponseBufError::Overflow)?;
        self.buf
            .get_mut(offset..end)
            .ok_or(ResponseBufError::Overflow)?
            .copy_from_slice(bytes);
        Ok(())
    }

    fn read_range(
        &self,
        range: core::ops::Range<usize>,
        f: &mut dyn FnMut(&[u8]) -> Result<(), ResponseBufError>,
    ) -> Result<(), ResponseBufError> {
        let bytes = self.buf.get(range).ok_or(ResponseBufError::Overflow)?;
        f(bytes)
    }

    fn capacity(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_buf(n: usize) -> alloc::vec::Vec<u8> {
        alloc::vec![0u8; n]
    }

    extern crate alloc;

    #[test]
    fn write_sequential() {
        let mut storage = make_buf(4);
        let mut buf = SliceResponseBuffer::new(&mut storage);
        buf.write_at(0, &[0xAA]).unwrap();
        buf.write_at(1, &[0xBB]).unwrap();
        buf.write_at(2, &[0xCC]).unwrap();
        buf.write_at(3, &[0xDD]).unwrap();
        assert_eq!(storage, &[0xAA, 0xBB, 0xCC, 0xDD][..]);
    }

    #[test]
    fn write_overflow() {
        let mut storage = make_buf(1);
        let mut buf = SliceResponseBuffer::new(&mut storage);
        assert_eq!(buf.write_at(1, &[0x02]), Err(ResponseBufError::Overflow));
    }

    #[test]
    fn write_word_aligned() {
        let mut storage = make_buf(8);
        let mut buf = SliceResponseBuffer::new(&mut storage);
        buf.write_at(0, &0x04030201u32.to_le_bytes()).unwrap();
        buf.write_at(4, &0x08070605u32.to_le_bytes()).unwrap();
        assert_eq!(
            storage[..],
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn write_multi_byte() {
        let data = [0x10u8, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70];
        let mut storage = make_buf(data.len());
        let mut buf = SliceResponseBuffer::new(&mut storage);
        buf.write_at(0, &data).unwrap();
        assert_eq!(storage[..], data);
    }

    #[test]
    fn overwrite_in_place() {
        let mut storage = make_buf(4);
        let mut buf = SliceResponseBuffer::new(&mut storage);
        buf.write_at(0, &[0x00, 0x00, 0x00, 0x00]).unwrap();
        buf.write_at(1, &[0xAA, 0xBB]).unwrap();
        assert_eq!(storage[..], [0x00, 0xAA, 0xBB, 0x00]);
    }

    #[test]
    fn write_past_end_rejected() {
        let mut storage = make_buf(4);
        let mut buf = SliceResponseBuffer::new(&mut storage);
        assert_eq!(buf.write_at(0, &[0u8; 5]), Err(ResponseBufError::Overflow));
    }

    #[test]
    fn clear_zeroes() {
        let mut storage = make_buf(8);
        let mut buf = SliceResponseBuffer::new(&mut storage);
        buf.write_at(0, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
            .unwrap();
        buf.clear().unwrap();
        assert_eq!(storage, &[0u8; 8][..]);
    }

    #[test]
    fn write_after_clear() {
        let mut storage = make_buf(8);
        let mut buf = SliceResponseBuffer::new(&mut storage);
        buf.write_at(0, &[0xFFu8; 8]).unwrap();
        buf.clear().unwrap();
        buf.write_at(0, &[0x42]).unwrap();
        assert_eq!(storage[0], 0x42);
    }

    #[test]
    fn offset_response_buffer() {
        // 8-byte backing store with base = 3; effective window is storage[3..8].
        let mut storage = make_buf(8);

        // capacity() = inner.capacity() - base
        {
            let mut slice_buf = SliceResponseBuffer::new(&mut storage);
            let obuf = OffsetResponseBuffer::new(&mut slice_buf, 3);
            assert_eq!(obuf.capacity(), 5);
        }

        // write_at(offset) lands at storage[base + offset]
        {
            let mut slice_buf = SliceResponseBuffer::new(&mut storage);
            let mut obuf = OffsetResponseBuffer::new(&mut slice_buf, 3);
            obuf.write_at(0, &[0xAA, 0xBB]).unwrap(); // → storage[3..5]
            obuf.write_at(2, &[0xCC]).unwrap(); // → storage[5]
        }
        assert_eq!(storage[3..6], [0xAA, 0xBB, 0xCC]);

        // read_range(r) reads storage[base+r.start .. base+r.end]
        {
            let mut slice_buf = SliceResponseBuffer::new(&mut storage);
            let obuf = OffsetResponseBuffer::new(&mut slice_buf, 3);
            let mut captured = alloc::vec::Vec::new();
            obuf.read_range(0..3, &mut |chunk| {
                captured.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();
            assert_eq!(captured, [0xAA, 0xBB, 0xCC]);
        }

        // clear() zeroes the entire underlying buffer
        {
            let mut slice_buf = SliceResponseBuffer::new(&mut storage);
            let mut obuf = OffsetResponseBuffer::new(&mut slice_buf, 3);
            obuf.clear().unwrap();
        }
        assert_eq!(storage, &[0u8; 8][..]);

        // Error: base + offset wraps usize::MAX
        {
            let mut slice_buf = SliceResponseBuffer::new(&mut storage);
            let mut obuf = OffsetResponseBuffer::new(&mut slice_buf, usize::MAX);
            assert_eq!(
                obuf.write_at(1, &[0x01]),
                Err(ResponseBufError::Overflow)
            );
        }

        // Error: write lands past the inner buffer's end
        {
            let mut slice_buf = SliceResponseBuffer::new(&mut storage);
            let mut obuf = OffsetResponseBuffer::new(&mut slice_buf, 3);
            // base(3) + offset(6) = 9, but inner capacity is 8
            assert_eq!(
                obuf.write_at(6, &[0x01]),
                Err(ResponseBufError::Overflow)
            );
        }

        // Error: read_range start addition wraps usize::MAX
        {
            let mut slice_buf = SliceResponseBuffer::new(&mut storage);
            let obuf = OffsetResponseBuffer::new(&mut slice_buf, usize::MAX);
            assert_eq!(
                obuf.read_range(1..2, &mut |_| Ok(())),
                Err(ResponseBufError::Overflow)
            );
        }

        // Error: read_range end addition wraps (start is fine, end overflows)
        {
            let mut slice_buf = SliceResponseBuffer::new(&mut storage);
            let obuf = OffsetResponseBuffer::new(&mut slice_buf, usize::MAX - 1);
            // base + end = (usize::MAX - 1) + 2 overflows
            assert_eq!(
                obuf.read_range(0..2, &mut |_| Ok(())),
                Err(ResponseBufError::Overflow)
            );
        }

        // Error: read_range falls outside inner buffer capacity
        {
            let mut slice_buf = SliceResponseBuffer::new(&mut storage);
            let obuf = OffsetResponseBuffer::new(&mut slice_buf, 3);
            // base(3) + end(6) = 9 > 8
            assert_eq!(
                obuf.read_range(0..6, &mut |_| Ok(())),
                Err(ResponseBufError::Overflow)
            );
        }
    }
}
