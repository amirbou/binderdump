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

    // advance pos by n; None on overrun.
    pub fn skip(&mut self, n: usize) -> Option<()> {
        let end = self.pos.checked_add(n)?;
        self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(())
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
use crate::registry::Registry;

#[derive(Clone, Debug, PartialEq)]
pub enum DecodedValue {
    I64(i64),
    U64(u64),
    F64(f64),
    Bool(bool),
    Str(Option<String>),
    Enum {
        repr: i64,
        variants: Vec<(i64, String)>,
    },
    Array {
        len: usize,
        null: bool,
    },
    Bytes, // byte[]; the bytes live at node.start/len
    Raw,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DecodedNode {
    pub name: String,
    pub type_label: String,
    pub start: usize,
    pub len: usize,
    pub value: DecodedValue,
    pub children: Vec<DecodedNode>,
}

// decode the in/inout parameters of `method` from `buf` starting at `start`.
// out-only params carry no bytes outbound and are skipped. The first param
// whose type we can't decode (or any overrun) appends a single Raw node over
// the remaining bytes and stops — every later offset would be unreliable.
pub fn decode_aidl_params(
    reg: &Registry,
    sdk: u32,
    method: &Method,
    buf: &[u8],
    start: usize,
) -> Vec<DecodedNode> {
    let mut cur = ParcelCursor::new(buf, start);
    let mut nodes = Vec::new();

    for param in &method.params {
        if param.direction == Direction::Out {
            continue;
        }
        let before = cur.pos;
        match decode_value(reg, sdk, &mut cur, &param.ty) {
            Some(mut node) => {
                node.name = param.name.clone();
                nodes.push(node);
            }
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
        children: vec![],
    }
}

fn node(
    value: DecodedValue,
    label: &str,
    start: usize,
    len: usize,
    children: Vec<DecodedNode>,
) -> DecodedNode {
    DecodedNode {
        name: String::new(),
        type_label: label.to_string(),
        start,
        len,
        value,
        children,
    }
}

// returns a DecodedNode (name left empty, caller fills it) or None if
// undecodable / buffer overrun.
fn decode_value(
    reg: &Registry,
    sdk: u32,
    cur: &mut ParcelCursor,
    ty: &TypeRef,
) -> Option<DecodedNode> {
    let start = cur.pos;
    match ty {
        TypeRef::Primitive(p) => {
            let (v, label) = decode_prim(cur, *p)?;
            Some(node(v, &label, start, cur.pos - start, vec![]))
        }
        TypeRef::String => {
            let s = cur.read_string16()?;
            Some(node(
                DecodedValue::Str(s),
                "String",
                start,
                cur.pos - start,
                vec![],
            ))
        }
        TypeRef::UserDefined(fqn) => {
            // non-enum / unknown UserDefined -> None -> Raw
            let e = reg.enum_def(sdk, fqn)?;
            let repr = read_backing(cur, e.backing)?;
            let variants: Vec<(i64, String)> =
                e.consts.iter().map(|(n, v)| (*v, n.clone())).collect();
            Some(node(
                DecodedValue::Enum { repr, variants },
                &e.fqn,
                start,
                cur.pos - start,
                vec![],
            ))
        }
        TypeRef::Array(el) | TypeRef::List(el) => decode_array(reg, sdk, cur, el, start),
        // Map and IBinder are not decodable here (2c / not a simple value).
        TypeRef::Map(_, _) | TypeRef::IBinder => None,
    }
}

// read an enum's backing primitive as i64.
fn read_backing(cur: &mut ParcelCursor, backing: Prim) -> Option<i64> {
    match backing {
        // all sub-int types are promoted to int32 on the wire.
        Prim::I8
        | Prim::U8
        | Prim::I16
        | Prim::U16
        | Prim::I32
        | Prim::U32
        | Prim::Char
        | Prim::Bool => Some(cur.read_i32()? as i64),
        Prim::I64 | Prim::U64 => cur.read_i64(),
        Prim::F32 | Prim::F64 => None, // enums are never float-backed
    }
}

fn decode_array(
    reg: &Registry,
    sdk: u32,
    cur: &mut ParcelCursor,
    el: &TypeRef,
    arr_start: usize,
) -> Option<DecodedNode> {
    let count = cur.read_i32()?;
    if count < 0 {
        return Some(node(
            DecodedValue::Array { len: 0, null: true },
            "array",
            arr_start,
            cur.pos - arr_start,
            vec![],
        ));
    }
    let n = count as usize;
    // byte[]/byte-list: packed n data bytes then padded to 4. the Bytes node's
    // start/len cover the n DATA bytes (not the count, not the padding); the
    // cursor still advances past the padding.
    if matches!(el.as_ref_prim(), Some(Prim::I8) | Some(Prim::U8)) {
        let data_start = cur.pos;
        cur.skip(crate::token::pad_to_4(n))?;
        return Some(node(DecodedValue::Bytes, "byte[]", data_start, n, vec![]));
    }
    let mut children = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        match decode_value(reg, sdk, cur, el) {
            Some(child) => children.push(child),
            // truncate + stop the whole param walk (best-effort)
            None => return None,
        }
    }
    Some(node(
        DecodedValue::Array {
            len: n,
            null: false,
        },
        "array",
        arr_start,
        cur.pos - arr_start,
        children,
    ))
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
    use crate::model::{Direction, EnumDef, Method, OverlayLayer, Parameter, Prim, TypeRef};
    use crate::registry::Registry;
    use std::collections::HashMap;

    fn reg_with_enum(fqn: &str, backing: Prim, consts: Vec<(&str, i64)>) -> Registry {
        let mut o = OverlayLayer {
            source_path: "t".into(),
            interfaces: Default::default(),
            enums: Default::default(),
            parcelables: Default::default(),
        };
        o.enums.insert(
            fqn.into(),
            EnumDef {
                fqn: fqn.into(),
                backing,
                consts: consts
                    .into_iter()
                    .map(|(n, v)| (n.to_string(), v))
                    .collect(),
            },
        );
        Registry::from_parts(vec![o], None, HashMap::new())
    }

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
    fn decodes_scalar_enum_int_backing() {
        let reg = reg_with_enum("a.E", Prim::I32, vec![("OFF", 0), ("ON", 1)]);
        let m = method(vec![in_param("state", TypeRef::UserDefined("a.E".into()))]);
        let buf = 1i32.to_le_bytes();
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0);
        assert_eq!(nodes.len(), 1);
        match &nodes[0].value {
            DecodedValue::Enum { repr, variants } => {
                assert_eq!(*repr, 1);
                assert!(variants.contains(&(1, "ON".to_string())));
            }
            v => panic!("expected enum, got {:?}", v),
        }
    }

    #[test]
    fn decodes_int_array() {
        let reg = Registry::empty();
        let m = method(vec![in_param(
            "xs",
            TypeRef::Array(Box::new(TypeRef::Primitive(Prim::I32))),
        )]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&3i32.to_le_bytes()); // count
        for v in [10i32, 20, 30] {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0);
        assert!(matches!(
            nodes[0].value,
            DecodedValue::Array {
                len: 3,
                null: false
            }
        ));
        assert_eq!(nodes[0].children.len(), 3);
        assert!(matches!(nodes[0].children[1].value, DecodedValue::I64(20)));
    }

    #[test]
    fn decodes_null_array() {
        let reg = Registry::empty();
        let m = method(vec![in_param(
            "xs",
            TypeRef::Array(Box::new(TypeRef::Primitive(Prim::I32))),
        )]);
        let buf = (-1i32).to_le_bytes();
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0);
        assert!(matches!(
            nodes[0].value,
            DecodedValue::Array { len: 0, null: true }
        ));
    }

    #[test]
    fn decodes_byte_array_packed_padded() {
        let reg = Registry::empty();
        let m = method(vec![
            in_param("b", TypeRef::Array(Box::new(TypeRef::Primitive(Prim::I8)))),
            in_param("after", TypeRef::Primitive(Prim::I32)),
        ]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&5i32.to_le_bytes()); // count 5
        buf.extend_from_slice(&[1, 2, 3, 4, 5, 0, 0, 0]); // 5 bytes + pad to 8
        buf.extend_from_slice(&7i32.to_le_bytes()); // following int proves cursor landed past the pad
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0);
        assert!(matches!(nodes[0].value, DecodedValue::Bytes));
        assert_eq!(nodes[0].start, 4);
        assert_eq!(nodes[0].len, 5);
        assert!(matches!(nodes[1].value, DecodedValue::I64(7)));
    }

    #[test]
    fn decodes_nested_int_array() {
        let reg = Registry::empty();
        let inner = TypeRef::Array(Box::new(TypeRef::Primitive(Prim::I32)));
        let m = method(vec![in_param("g", TypeRef::Array(Box::new(inner)))]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&2i32.to_le_bytes()); // outer count 2
        buf.extend_from_slice(&1i32.to_le_bytes()); // inner0 count 1
        buf.extend_from_slice(&9i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes()); // inner1 count 0
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0);
        assert!(matches!(nodes[0].value, DecodedValue::Array { len: 2, .. }));
        assert_eq!(nodes[0].children.len(), 2);
        assert!(matches!(
            nodes[0].children[0].value,
            DecodedValue::Array { len: 1, .. }
        ));
        assert!(matches!(
            nodes[0].children[0].children[0].value,
            DecodedValue::I64(9)
        ));
    }

    #[test]
    fn unknown_userdefined_falls_back_to_raw() {
        let reg = Registry::empty();
        let m = method(vec![in_param(
            "p",
            TypeRef::UserDefined("a.SomeParcelable".into()),
        )]);
        let buf = [0u8; 8];
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0);
        assert!(matches!(nodes[0].value, DecodedValue::Raw));
    }

    #[test]
    fn decodes_int_and_string() {
        let reg = Registry::empty();
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
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0);
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
        let reg = Registry::empty();
        let mut m = method(vec![in_param("x", TypeRef::Primitive(Prim::I32))]);
        m.params[0].direction = Direction::Out;
        let buf = 9i32.to_le_bytes();
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0);
        assert!(nodes.is_empty());
    }

    #[test]
    fn unknown_type_stops_with_raw_tail() {
        let reg = Registry::empty();
        let m = method(vec![
            in_param("x", TypeRef::Primitive(Prim::I32)),
            in_param("obj", TypeRef::UserDefined("a.b.Foo".into())), // not decodable
            in_param("y", TypeRef::Primitive(Prim::I32)),
        ]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0);
        assert_eq!(nodes.len(), 2);
        assert!(matches!(nodes[0].value, DecodedValue::I64(1)));
        assert!(matches!(nodes[1].value, DecodedValue::Raw));
        assert_eq!(nodes[1].start, 4);
        assert_eq!(nodes[1].len, 4); // remaining bytes
    }

    #[test]
    fn overrun_emits_raw_tail() {
        let reg = Registry::empty();
        let m = method(vec![
            in_param("a", TypeRef::Primitive(Prim::I32)),
            in_param("b", TypeRef::Primitive(Prim::I64)), // wants 8 bytes, only 2 left
        ]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&[0, 0]);
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0);
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

    // end-to-end: resolve a real AOSP interface+method whose param is an enum from
    // the committed corpus, then decode a parcel value and assert the enum variant.
    // IThermal.getCoolingDevicesWithType(in CoolingType type) is code 2 (0-indexed
    // method 1 in the interface; AIDL base_code=1 so method[1] = code 2).
    // CoolingType.FAN = 0, BATTERY = 1, CPU = 2, GPU = 3 (from corpus file).
    #[test]
    fn decodes_corpus_enum_via_import_qualification() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let aosp_dir = std::path::PathBuf::from(manifest_dir).join("data/aosp");
        let reg = Registry::with_aosp_dir(aosp_dir);

        // resolve the interface to get the method
        let sdk = 34u32;
        let iface_fqn = "android.hardware.thermal.IThermal";
        // getCoolingDevicesWithType is the second method (code 2)
        let method = match reg.resolve(sdk, iface_fqn, 2) {
            crate::registry::Lookup::Hit { method, .. } => method.clone(),
            other => panic!("expected Hit for IThermal code 2, got {:?}", other),
        };
        assert_eq!(method.name, "getCoolingDevicesWithType");
        assert_eq!(method.params.len(), 1);
        // the param type must be the fully-qualified enum fqn after parser fix
        assert_eq!(
            method.params[0].ty,
            TypeRef::UserDefined("android.hardware.thermal.CoolingType".into()),
            "param type must be fqn after import qualification"
        );

        // decode CoolingType::FAN (value 0) from a 4-byte parcel
        let buf = 0i32.to_le_bytes();
        let nodes = decode_aidl_params(&reg, sdk, &method, &buf, 0);
        assert_eq!(nodes.len(), 1);
        match &nodes[0].value {
            DecodedValue::Enum { repr, variants } => {
                assert_eq!(*repr, 0);
                assert!(
                    variants.contains(&(0, "FAN".to_string())),
                    "expected FAN in variants, got {:?}",
                    variants
                );
            }
            v => panic!(
                "expected Enum, got {:?} (parser likely not qualifying the type)",
                v
            ),
        }
    }
}
