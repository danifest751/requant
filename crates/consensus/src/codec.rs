//! Canonical binary encoding (CHAIN.md §1): little-endian integers, CompactSize `varint`, no trailing data.

use crate::Error;

#[derive(Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn u8(&mut self, x: u8) {
        self.0.push(x);
    }
    pub fn u32(&mut self, x: u32) {
        self.0.extend_from_slice(&x.to_le_bytes());
    }
    pub fn u64(&mut self, x: u64) {
        self.0.extend_from_slice(&x.to_le_bytes());
    }
    pub fn raw(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    pub fn varint(&mut self, x: u64) {
        match x {
            0..=0xfc => self.u8(x as u8),
            0xfd..=0xffff => {
                self.u8(0xfd);
                self.0.extend_from_slice(&(x as u16).to_le_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.u8(0xfe);
                self.u32(x as u32);
            }
            _ => {
                self.u8(0xff);
                self.u64(x);
            }
        }
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.varint(b.len() as u64);
        self.raw(b);
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.buf.len() - self.pos < n {
            return Err(Error::Decode("truncated"));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn arr32(&mut self) -> Result<[u8; 32], Error> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    pub fn arr64(&mut self) -> Result<[u8; 64], Error> {
        Ok(self.take(64)?.try_into().unwrap())
    }

    /// Shortest-form CompactSize no larger than `max`.
    pub fn varint(&mut self, max: u64) -> Result<u64, Error> {
        let v = match self.u8()? {
            x @ 0..=0xfc => x as u64,
            0xfd => {
                let v = self.u16()? as u64;
                if v < 0xfd {
                    return Err(Error::Decode("non-canonical varint"));
                }
                v
            }
            0xfe => {
                let v = self.u32()? as u64;
                if v <= 0xffff {
                    return Err(Error::Decode("non-canonical varint"));
                }
                v
            }
            _ => {
                let v = self.u64()?;
                if v <= 0xffff_ffff {
                    return Err(Error::Decode("non-canonical varint"));
                }
                v
            }
        };
        if v > max {
            return Err(Error::Decode("length above limit"));
        }
        Ok(v)
    }

    pub fn bytes(&mut self, max: usize) -> Result<&'a [u8], Error> {
        let n = self.varint(max as u64)? as usize;
        self.take(n)
    }

    pub fn finish(self) -> Result<(), Error> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(Error::Decode("trailing data"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip_and_canonical() {
        for x in [0u64, 1, 0xfc, 0xfd, 0xffff, 0x1_0000, 0xffff_ffff, 0x1_0000_0000, u64::MAX] {
            let mut w = Writer::default();
            w.varint(x);
            let mut r = Reader::new(&w.0);
            assert_eq!(r.varint(u64::MAX).unwrap(), x);
            r.finish().unwrap();
        }
        for bad in [&[0xfd, 0xfc, 0x00][..], &[0xfe, 0xff, 0xff, 0, 0], &[0xff, 1, 0, 0, 0, 0, 0, 0, 0]] {
            assert!(Reader::new(bad).varint(u64::MAX).is_err());
        }
        assert!(Reader::new(&[5]).varint(4).is_err());
        assert!(Reader::new(&[1, 2]).finish().is_err());
        assert!(Reader::new(&[3, 1]).bytes(10).is_err());
    }
}
