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

use crate::model::{Direction, Method, Prim, TypeRef};

#[derive(Clone, Debug, PartialEq)]
pub enum DecodedValue {
    I64(i64),
    U64(u64),
    F64(f64),
    Bool(bool),
    Str(Option<String>),
    Raw,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DecodedNode {
    pub name: String,
    pub type_label: String,
    pub start: usize,
    pub len: usize,
    pub value: DecodedValue,
}

// decode the in/inout parameters of `method` from `buf` starting at `start`.
// out-only params carry no bytes outbound and are skipped. The first param
// whose type we can't decode (or any overrun) appends a single Raw node over
// the remaining bytes and stops — every later offset would be unreliable.
pub fn decode_aidl_params(method: &Method, buf: &[u8], start: usize) -> Vec<DecodedNode> {
    let mut cur = ParcelCursor::new(buf, start);
    let mut nodes = Vec::new();

    for param in &method.params {
        if param.direction == Direction::Out {
            continue;
        }
        let before = cur.pos;
        let decoded = decode_one(&mut cur, &param.ty);
        match decoded {
            Some((value, label)) => nodes.push(DecodedNode {
                name: param.name.clone(),
                type_label: label,
                start: before,
                len: cur.pos - before,
                value,
            }),
            None => {
                nodes.push(raw_tail(param.name.clone(), before, buf.len()));
                return nodes;
            }
        }
    }
    nodes
}

fn raw_tail(name: String, start: usize, buf_len: usize) -> DecodedNode {
    DecodedNode {
        name,
        type_label: "raw".to_string(),
        start,
        len: buf_len.saturating_sub(start),
        value: DecodedValue::Raw,
    }
}

// returns (value, type_label) or None if this type isn't decodable in this
// sub-project (containers/parcelables come later) or the buffer ran out.
fn decode_one(cur: &mut ParcelCursor, ty: &TypeRef) -> Option<(DecodedValue, String)> {
    match ty {
        TypeRef::Primitive(p) => decode_prim(cur, *p),
        TypeRef::String => cur
            .read_string16()
            .map(|s| (DecodedValue::Str(s), "String".to_string())),
        // Array/List/Map/IBinder/UserDefined: not in this sub-project.
        _ => None,
    }
}

fn decode_prim(cur: &mut ParcelCursor, prim: Prim) -> Option<(DecodedValue, String)> {
    let (v, label) = match prim {
        Prim::Bool => (DecodedValue::Bool(cur.read_bool()?), "boolean"),
        // byte/char/short are int32-promoted on the wire.
        Prim::I8 | Prim::U8 => (DecodedValue::I64(cur.read_i32()? as i64), "byte"),
        Prim::Char => (DecodedValue::U64(cur.read_u32()? as u64), "char"),
        Prim::I16 | Prim::U16 => (DecodedValue::I64(cur.read_i32()? as i64), "short"),
        Prim::I32 => (DecodedValue::I64(cur.read_i32()? as i64), "int"),
        Prim::U32 => (DecodedValue::U64(cur.read_u32()? as u64), "int"),
        Prim::I64 => (DecodedValue::I64(cur.read_i64()?), "long"),
        Prim::U64 => (DecodedValue::U64(cur.read_u64()?), "long"),
        Prim::F32 => (DecodedValue::F64(cur.read_f32()? as f64), "float"),
        Prim::F64 => (DecodedValue::F64(cur.read_f64()?), "double"),
    };
    Some((v, label.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Direction, Method, Parameter, Prim, TypeRef};

    fn in_param(name: &str, ty: TypeRef) -> Parameter {
        Parameter {
            name: name.to_string(),
            ty,
            direction: Direction::In,
        }
    }

    fn method(params: Vec<Parameter>) -> Method {
        Method {
            name: "m".into(),
            params,
            return_type: None,
            oneway: false,
            code: None,
        }
    }

    #[test]
    fn decodes_int_and_string() {
        let m = method(vec![
            in_param("count", TypeRef::Primitive(Prim::I32)),
            in_param("name", TypeRef::String),
        ]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&5i32.to_le_bytes());
        buf.extend_from_slice(&2i32.to_le_bytes()); // "hi"
        buf.extend_from_slice(&(b'h' as u16).to_le_bytes());
        buf.extend_from_slice(&(b'i' as u16).to_le_bytes());
        buf.extend_from_slice(&[0, 0]); // u16 NUL
        buf.extend_from_slice(&[0, 0]); // pad to 4-byte boundary
        let nodes = decode_aidl_params(&m, &buf, 0);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "count");
        assert!(matches!(nodes[0].value, DecodedValue::I64(5)));
        assert_eq!(nodes[0].start, 0);
        assert_eq!(nodes[0].len, 4);
        assert_eq!(nodes[1].name, "name");
        assert!(matches!(&nodes[1].value, DecodedValue::Str(Some(s)) if s == "hi"));
    }

    #[test]
    fn out_param_is_skipped_on_request() {
        let mut m = method(vec![in_param("x", TypeRef::Primitive(Prim::I32))]);
        m.params[0].direction = Direction::Out;
        let buf = 9i32.to_le_bytes();
        let nodes = decode_aidl_params(&m, &buf, 0);
        assert!(nodes.is_empty());
    }

    #[test]
    fn unknown_type_stops_with_raw_tail() {
        let m = method(vec![
            in_param("x", TypeRef::Primitive(Prim::I32)),
            in_param("obj", TypeRef::UserDefined("a.b.Foo".into())), // not decodable yet
            in_param("y", TypeRef::Primitive(Prim::I32)),
        ]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let nodes = decode_aidl_params(&m, &buf, 0);
        assert_eq!(nodes.len(), 2);
        assert!(matches!(nodes[0].value, DecodedValue::I64(1)));
        assert!(matches!(nodes[1].value, DecodedValue::Raw));
        assert_eq!(nodes[1].start, 4);
        assert_eq!(nodes[1].len, 4); // remaining bytes
    }

    #[test]
    fn overrun_emits_raw_tail() {
        let m = method(vec![
            in_param("a", TypeRef::Primitive(Prim::I32)),
            in_param("b", TypeRef::Primitive(Prim::I64)), // wants 8 bytes, only 2 left
        ]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&[0, 0]);
        let nodes = decode_aidl_params(&m, &buf, 0);
        assert!(matches!(nodes[0].value, DecodedValue::I64(1)));
        assert!(matches!(nodes.last().unwrap().value, DecodedValue::Raw));
    }

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
