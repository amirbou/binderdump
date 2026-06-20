// Decodes an AIDL parcel buffer into per-parameter values using a resolved
// Method signature. Pure byte logic — no Wireshark types. Best-effort: the
// first undecodable type (or any overrun) stops the walk and the remaining
// bytes are surfaced raw by the caller.

// 4-byte-aligned cursor over a parcel buffer. AIDL aligns every write to 4
// bytes; 64-bit values occupy 8. All readers return None on overrun.
pub struct ParcelCursor<'a> {
    pub pos: usize,
    buf: &'a [u8],
}

impl<'a> ParcelCursor<'a> {
    pub fn new(buf: &'a [u8], start: usize) -> Self {
        Self { pos: start, buf }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    pub fn read_i32(&mut self) -> Option<i32> {
        Some(i32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    pub fn read_u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    pub fn read_i64(&mut self) -> Option<i64> {
        Some(i64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    pub fn read_u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    pub fn read_f32(&mut self) -> Option<f32> {
        Some(f32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    pub fn read_f64(&mut self) -> Option<f64> {
        Some(f64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    pub fn read_bool(&mut self) -> Option<bool> {
        self.read_i32().map(|v| v != 0)
    }

    // String16: int32 char_count (-1 = null), then (char_count+1) char16_t
    // units (UTF-16 LE + u16 NUL), whole region padded to 4 bytes.
    // Outer None = overrun; inner None = null.
    pub fn read_string16(&mut self) -> Option<Option<String>> {
        let char_count = self.read_i32()?;
        if char_count < 0 {
            return Some(None);
        }
        let n = char_count as usize;
        let units_bytes = n.checked_mul(2)?;
        // pad the (units + u16 NUL) region to 4 bytes (Parcel::writeInplace).
        // correct only because the cursor is 4-aligned here — every reader
        // consumes a multiple of 4; a non-multiple reader would break this.
        let padded = crate::token::pad_to_4(units_bytes.checked_add(2)?);
        let chars = self.take(units_bytes)?;
        self.take(padded - units_bytes)?;
        let units: Vec<u16> = chars
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(Some(String::from_utf16_lossy(&units)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_i32_and_advances() {
        let buf = 42i32.to_le_bytes();
        let mut c = ParcelCursor::new(&buf, 0);
        assert_eq!(c.read_i32(), Some(42));
        assert_eq!(c.pos, 4);
    }

    #[test]
    fn reads_i64_takes_eight_bytes() {
        let buf = 0x0102030405060708i64.to_le_bytes();
        let mut c = ParcelCursor::new(&buf, 0);
        assert_eq!(c.read_i64(), Some(0x0102030405060708));
        assert_eq!(c.pos, 8);
    }

    #[test]
    fn read_bool_is_nonzero_int32() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        let mut c = ParcelCursor::new(&buf, 0);
        assert_eq!(c.read_bool(), Some(true));
        assert_eq!(c.read_bool(), Some(false));
    }

    #[test]
    fn read_f64_roundtrips() {
        let buf = 3.5f64.to_le_bytes();
        let mut c = ParcelCursor::new(&buf, 0);
        assert_eq!(c.read_f64(), Some(3.5));
    }

    #[test]
    fn read_string16_decodes_and_pads() {
        // "hi" -> count 2; body = (2+1)*2 = 6 padded to 8 (units 'h','i', u16
        // NUL, then 2 pad bytes); a following int param starts at offset 12.
        let mut buf = Vec::new();
        buf.extend_from_slice(&2i32.to_le_bytes());
        buf.extend_from_slice(&(b'h' as u16).to_le_bytes());
        buf.extend_from_slice(&(b'i' as u16).to_le_bytes());
        buf.extend_from_slice(&[0, 0]); // u16 NUL
        buf.extend_from_slice(&[0, 0]); // pad to 4-byte boundary
        buf.extend_from_slice(&7i32.to_le_bytes());
        let mut c = ParcelCursor::new(&buf, 0);
        assert_eq!(c.read_string16(), Some(Some("hi".to_string())));
        assert_eq!(c.read_i32(), Some(7));
    }

    #[test]
    fn read_string16_one_char_includes_nul_unit() {
        // "a" -> count 1; body = (1+1)*2 = 4 (unit 'a' + u16 NUL), already
        // 4-aligned; following int at offset 8.
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&(b'a' as u16).to_le_bytes());
        buf.extend_from_slice(&[0, 0]); // u16 NUL
        buf.extend_from_slice(&9i32.to_le_bytes());
        let mut c = ParcelCursor::new(&buf, 0);
        assert_eq!(c.read_string16(), Some(Some("a".to_string())));
        assert_eq!(c.read_i32(), Some(9));
    }

    #[test]
    fn read_string16_null() {
        let buf = (-1i32).to_le_bytes();
        let mut c = ParcelCursor::new(&buf, 0);
        assert_eq!(c.read_string16(), Some(None));
    }

    #[test]
    fn overrun_returns_none() {
        let buf = [0u8; 2];
        let mut c = ParcelCursor::new(&buf, 0);
        assert_eq!(c.read_i32(), None);
    }
}
