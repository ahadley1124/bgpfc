//! Bounds-checked cursor over a byte slice.
//!
//! All wire parsing goes through [`Reader`] so that no decoder indexes a
//! slice by hand (AGENTS.md §7). Running out of bytes yields [`Truncated`],
//! which each message decoder maps to the NOTIFICATION the RFC prescribes
//! for that message.

use std::fmt;

/// The input ended before the field being read was complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Truncated;

impl fmt::Display for Truncated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("input truncated")
    }
}

impl std::error::Error for Truncated {}

/// Forward-only cursor over `&[u8]`. Every read is bounds-checked; big-endian
/// integers, as everywhere in BGP.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Start reading at the beginning of `buf`.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Whether every byte has been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }

    /// Number of bytes consumed so far.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Consume and return the next `n` bytes.
    ///
    /// # Errors
    /// [`Truncated`] if fewer than `n` bytes remain; nothing is consumed then.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Truncated> {
        let end = self.pos.checked_add(n).ok_or(Truncated)?;
        let bytes = self.buf.get(self.pos..end).ok_or(Truncated)?;
        self.pos = end;
        Ok(bytes)
    }

    /// Everything that remains, without consuming it.
    #[must_use]
    pub fn rest_peek(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// Consume and return everything that remains.
    pub fn rest(&mut self) -> &'a [u8] {
        let bytes = &self.buf[self.pos..];
        self.pos = self.buf.len();
        bytes
    }

    /// Consume a sub-reader over the next `n` bytes, so that a length-prefixed
    /// field can be parsed without its parser seeing past its end.
    ///
    /// # Errors
    /// [`Truncated`] if fewer than `n` bytes remain.
    pub fn sub(&mut self, n: usize) -> Result<Reader<'a>, Truncated> {
        self.take(n).map(Reader::new)
    }

    /// Consume one octet.
    ///
    /// # Errors
    /// [`Truncated`] if the input is exhausted.
    pub fn u8(&mut self) -> Result<u8, Truncated> {
        let b = *self.buf.get(self.pos).ok_or(Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    /// Consume a big-endian 16-bit integer.
    ///
    /// # Errors
    /// [`Truncated`] if fewer than two bytes remain.
    pub fn u16(&mut self) -> Result<u16, Truncated> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Consume a big-endian 32-bit integer.
    ///
    /// # Errors
    /// [`Truncated`] if fewer than four bytes remain.
    pub fn u32(&mut self) -> Result<u32, Truncated> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Consume exactly `N` bytes as an array.
    ///
    /// # Errors
    /// [`Truncated`] if fewer than `N` bytes remain.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Truncated> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }
}

/// Big-endian append helpers for encoders.
pub trait WriteBytes {
    /// Append one octet.
    fn put_u8(&mut self, v: u8);
    /// Append a big-endian 16-bit integer.
    fn put_u16(&mut self, v: u16);
    /// Append a big-endian 32-bit integer.
    fn put_u32(&mut self, v: u32);
    /// Append a byte slice.
    fn put_bytes(&mut self, v: &[u8]);
}

impl WriteBytes for Vec<u8> {
    fn put_u8(&mut self, v: u8) {
        self.push(v);
    }
    fn put_u16(&mut self, v: u16) {
        self.extend_from_slice(&v.to_be_bytes());
    }
    fn put_u32(&mut self, v: u32) {
        self.extend_from_slice(&v.to_be_bytes());
    }
    fn put_bytes(&mut self, v: &[u8]) {
        self.extend_from_slice(v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_in_order_and_stops_at_the_end() {
        let mut r = Reader::new(&[1, 0, 2, 0, 0, 0, 3, 9, 8]);
        assert_eq!(r.u8(), Ok(1));
        assert_eq!(r.u16(), Ok(2));
        assert_eq!(r.u32(), Ok(3));
        assert_eq!(r.remaining(), 2);
        assert_eq!(r.take(3), Err(Truncated));
        assert_eq!(r.position(), 7, "a failed take consumes nothing");
        assert_eq!(r.array::<2>(), Ok([9, 8]));
        assert!(r.is_empty());
        assert_eq!(r.u8(), Err(Truncated));
    }

    #[test]
    fn sub_reader_is_bounded() {
        let mut r = Reader::new(&[2, 0xaa, 0xbb, 0xcc]);
        let n = usize::from(r.u8().unwrap());
        let mut s = r.sub(n).unwrap();
        assert_eq!(s.u16(), Ok(0xaabb));
        assert_eq!(s.u8(), Err(Truncated));
        assert_eq!(r.rest(), &[0xcc]);
    }

    #[test]
    fn writer_is_big_endian() {
        let mut v = Vec::new();
        v.put_u8(1);
        v.put_u16(0x0203);
        v.put_u32(0x0405_0607);
        v.put_bytes(&[8]);
        assert_eq!(v, [1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
