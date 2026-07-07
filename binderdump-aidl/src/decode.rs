// Decodes an AIDL parcel buffer into per-parameter values using a resolved
// Method signature. Pure byte logic — no Wireshark types. Best-effort: the
// first undecodable type (or any overrun) stops the walk and the remaining
// bytes are surfaced raw by the caller.

use crate::binder_object;

// 4-byte-aligned cursor over a parcel buffer. AIDL aligns every write to 4
// bytes; 64-bit values occupy 8. All readers return None on overrun.
// `overran` is set to true when a take()/skip() fails a bounds check; callers
// use it to distinguish a genuine buffer overrun from an undecodable type.
pub struct ParcelCursor<'a> {
    pub pos: usize,
    pub overran: bool,
    buf: &'a [u8],
    offsets: &'a [u8],
}

impl<'a> ParcelCursor<'a> {
    pub fn new(buf: &'a [u8], start: usize) -> Self {
        Self {
            pos: start,
            overran: false,
            buf,
            offsets: &[],
        }
    }

    // attach the transaction offsets array (8-byte LE binder_size_t entries) so
    // read_binder_object can locate inline flat_binder_objects.
    pub fn with_offsets(mut self, offsets: &'a [u8]) -> Self {
        self.offsets = offsets;
        self
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let Some(end) = self.pos.checked_add(n) else {
            self.overran = true;
            return None;
        };
        match self.buf.get(self.pos..end) {
            Some(slice) => {
                self.pos = end;
                Some(slice)
            }
            None => {
                self.overran = true;
                None
            }
        }
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
        let Some(end) = self.pos.checked_add(n) else {
            self.overran = true;
            return None;
        };
        if self.buf.get(self.pos..end).is_none() {
            self.overran = true;
            return None;
        }
        self.pos = end;
        Some(())
    }

    pub fn buf_len(&self) -> usize {
        self.buf.len()
    }

    pub fn seek(&mut self, pos: usize) -> Option<()> {
        if pos > self.buf.len() {
            return None;
        }
        self.pos = pos;
        Some(())
    }

    // A strong-binder arg is a flat_binder_object written inline in the data buffer, its byte
    // offset listed in the transaction offsets array. 64-bit kernel: 8-byte LE offset entries;
    // flat_binder_object = [u32 type][u32 flags][u64 binder|handle][u64 cookie] = 24 bytes
    // (<linux/android/binder.h>). If the cursor sits at a listed binder/handle object, returns
    // (value, strong) and advances 24 bytes; otherwise None (caller halts).
    pub fn read_binder_object(&mut self) -> Option<(u64, bool)> {
        let pos = self.pos;
        if !binder_object::offset_entries(self.offsets).any(|o| o == pos) {
            return None;
        }
        let type_tag = self.read_u32()?;
        let strong = match binder_object::classify(type_tag) {
            binder_object::Kind::Binder => true,
            binder_object::Kind::Handle => false,
            _ => return None, // fd/ptr/fda/unknown: not a plain IBinder
        };
        let _flags = self.read_u32()?;
        let value = self.read_u64()?; // local binder ptr, or remote handle in the low 32 bits
        let _cookie = self.read_u64()?;
        Some((value, strong))
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

    // String8: int32 byte_len (-1 = null), then byte_len UTF-8 bytes + a u8 NUL,
    // whole region padded to 4 bytes (Parcel::writeInplace). Outer None = overrun;
    // inner None = null. frameworks/native/libs/binder/Parcel.cpp writeString8.
    // Correct only because the cursor is 4-aligned here (every reader consumes a
    // multiple of 4) — same invariant as read_string16.
    pub fn read_string8(&mut self) -> Option<Option<String>> {
        let byte_len = self.read_i32()?;
        if byte_len < 0 {
            return Some(None);
        }
        let n = byte_len as usize;
        let padded = crate::token::pad_to_4(n.checked_add(1)?);
        let bytes = self.take(n)?;
        self.take(padded - n)?;
        Some(Some(String::from_utf8_lossy(bytes).into_owned()))
    }

    // CString (Parcel::writeCString): the C-string bytes through a NUL terminator, padded to 4
    // bytes, NO length prefix. Outer None = overrun (no NUL before buffer end); inner is always
    // Some (writeCString(nullptr) is not used by these interfaces). frameworks/native Parcel.cpp.
    // Correct only because the cursor is 4-aligned here (every reader consumes a multiple of 4).
    pub fn read_cstring(&mut self) -> Option<Option<String>> {
        let rest = self.buf.get(self.pos..)?;
        let nul = rest.iter().position(|&b| b == 0)?;
        let bytes = rest[..nul].to_vec();
        let total = crate::token::pad_to_4(nul.checked_add(1)?); // bytes + NUL, padded to 4
        self.skip(total)?;
        Some(Some(String::from_utf8_lossy(&bytes).into_owned()))
    }
}

use crate::model::{Direction, Method, Prim, TypeRef};
use crate::registry::Registry;

// cap decoder recursion so a crafted/corrupt parcel (deeply nested maps/lists/parcelables)
// can't overflow the host stack and crash tshark. counts every recursive frame, not logical nesting.
const MAX_DECODE_DEPTH: u32 = 128;

// true if we've recursed too deep. warns once at the boundary so a truncated decode is
// visible rather than silently swallowed (a real parcel never approaches the cap).
pub(crate) fn depth_exceeded(depth: u32) -> bool {
    if depth >= MAX_DECODE_DEPTH {
        eprintln!(
            "binderdump: parcel decode recursion cap ({MAX_DECODE_DEPTH}) hit; truncating (likely a malformed parcel)"
        );
        return true;
    }
    false
}

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
    Parcelable {
        fqn: String,
        null: bool,
    }, // children = decoded fields (+ optional raw remainder)
    Union {
        fqn: String,
        null: bool,
    }, // single child = active member (none if null)
    Map {
        len: usize,
        null: bool,
    }, // children = MapEntry nodes
    MapEntry, // children = [key, value]
    Bundle {
        len: usize,
        null: bool,
    }, // children = one node per entry, each named by its key
    Serializable {
        class_name: Option<String>,
    }, // leaf; the Java object stream is opaque
    Binder {
        handle: u64,
        strong: bool,
    }, // a strong-binder arg; strong = local binder, else a remote handle
    Raw,
    RawTail {
        reason: String,
    }, // decode stopped here; `reason` says why (undecodable type / overrun)
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
    offsets: &[u8],
) -> Vec<DecodedNode> {
    let mut cur = ParcelCursor::new(buf, start).with_offsets(offsets);
    let mut nodes = Vec::new();

    for param in &method.params {
        if param.direction == Direction::Out {
            continue;
        }
        let before = cur.pos;
        cur.overran = false;
        match decode_value(reg, sdk, &mut cur, &param.ty, 0) {
            Some(mut node) => {
                node.name = param.name.clone();
                nodes.push(node);
            }
            None => {
                let reason = if cur.overran {
                    "buffer overrun".to_string()
                } else {
                    format!("param {} (undecodable type {:?})", param.name, param.ty)
                };
                nodes.push(raw_tail(param.name.clone(), before, buf.len(), reason));
                return nodes;
            }
        }
    }
    nodes
}

// Binder reply status (exception) codes — frameworks/native/libs/binder/Status.cpp
// and frameworks/base Parcel.java. The reply payload begins with this header.
#[allow(dead_code)]
mod ex {
    pub const NONE: i32 = 0;
    pub const SERVICE_SPECIFIC: i32 = -8;
    pub const PARCELABLE: i32 = -9;
    pub const HAS_NOTED_APPOPS_REPLY_HEADER: i32 = -127;
    pub const HAS_REPLY_HEADER: i32 = -128; // strict-mode "fat" reply header
}

fn ex_name(code: i32) -> &'static str {
    match code {
        -1 => "EX_SECURITY",
        -2 => "EX_BAD_PARCELABLE",
        -3 => "EX_ILLEGAL_ARGUMENT",
        -4 => "EX_NULL_POINTER",
        -5 => "EX_ILLEGAL_STATE",
        -6 => "EX_NETWORK_MAIN_THREAD",
        -7 => "EX_UNSUPPORTED_OPERATION",
        -8 => "EX_SERVICE_SPECIFIC",
        -9 => "EX_PARCELABLE",
        -129 => "EX_TRANSACTION_FAILED",
        _ => "EX_UNKNOWN",
    }
}

// skip a reply header (Status::skipUnusedHeader): int32 size at the header start,
// then advance to header_start + size (size counts from the size int itself).
fn skip_reply_header(cur: &mut ParcelCursor) -> Option<()> {
    let header_start = cur.pos;
    let size = cur.read_i32()?;
    if size < 4 {
        return None; // a real header is at least the 4-byte size int
    }
    cur.seek(header_start.checked_add(size as usize)?)
}

// read the reply status header (Status::readFromParcel). Returns the exception code
// (0 = success), skipping the appops/strict-mode reply headers. None on overrun.
fn read_reply_status(cur: &mut ParcelCursor) -> Option<i32> {
    let mut code = cur.read_i32()?;
    if code == ex::HAS_NOTED_APPOPS_REPLY_HEADER {
        skip_reply_header(cur)?;
        code = cur.read_i32()?;
    }
    if code == ex::HAS_REPLY_HEADER {
        skip_reply_header(cur)?;
        code = ex::NONE; // fat reply headers only occur when there's no exception
    }
    Some(code)
}

// after a non-zero status: String16 message, a remote stack-trace header (int32 size,
// skipped if non-zero), then an int32 service-specific code for EX_SERVICE_SPECIFIC.
// best-effort: returns whatever it could decode. the status int is already consumed.
fn decode_exception(cur: &mut ParcelCursor, code: i32) -> Vec<DecodedNode> {
    let code_start = cur.pos.saturating_sub(4);
    let mut n = node(
        DecodedValue::Str(Some(ex_name(code).to_string())),
        "exception",
        code_start,
        4,
        vec![],
    );
    n.name = "exception".to_string();
    let mut out = vec![n];
    let mstart = cur.pos;
    let Some(msg) = cur.read_string16() else {
        return out;
    };
    let mut mn = node(
        DecodedValue::Str(msg),
        "exception.message",
        mstart,
        cur.pos - mstart,
        vec![],
    );
    mn.name = "exception.message".to_string();
    out.push(mn);
    // remote stack-trace header: int32 size; skip `size` bytes from the size int if non-zero.
    let rstart = cur.pos;
    let Some(rsize) = cur.read_i32() else {
        return out;
    };
    if rsize > 0 {
        if let Some(end) = rstart.checked_add(rsize as usize) {
            let _ = cur.seek(end);
        }
    }
    if code == ex::SERVICE_SPECIFIC {
        let sstart = cur.pos;
        if let Some(svc) = cur.read_i32() {
            let mut sn = node(
                DecodedValue::I64(svc as i64),
                "exception.serviceSpecific",
                sstart,
                4,
                vec![],
            );
            sn.name = "exception.serviceSpecific".to_string();
            out.push(sn);
        }
    }
    out
}

// true if a method has a real return value (void parses to UserDefined("void")).
pub fn has_return_value(method: &Method) -> bool {
    match &method.return_type {
        None => false,
        Some(TypeRef::UserDefined(s)) if s == "void" => false,
        Some(_) => true,
    }
}

// true if a request carries no inbound payload — the method declares no In/InOut
// params, so an empty Parameters region is expected, not a decode failure.
pub fn takes_no_input_params(method: &Method) -> bool {
    !method
        .params
        .iter()
        .any(|p| matches!(p.direction, Direction::In | Direction::InOut))
}

// true if a reply carries no return payload — the method returns void and has no
// Out/InOut params, so an empty Reply region is expected, not a decode failure.
pub fn produces_no_reply_data(method: &Method) -> bool {
    !has_return_value(method)
        && !method
            .params
            .iter()
            .any(|p| matches!(p.direction, Direction::Out | Direction::InOut))
}

// decode an AIDL reply: status header, then on success the return value followed by
// out/inout params in declaration order (complement of decode_aidl_params, which
// decodes In/InOut args). Replies have no interface token, so `start` is 0.
pub fn decode_aidl_reply(
    reg: &Registry,
    sdk: u32,
    method: &Method,
    buf: &[u8],
    start: usize,
    offsets: &[u8],
) -> Vec<DecodedNode> {
    let mut cur = ParcelCursor::new(buf, start).with_offsets(offsets);
    let mut nodes = Vec::new();

    let Some(code) = read_reply_status(&mut cur) else {
        return nodes;
    };
    if code != ex::NONE {
        return decode_exception(&mut cur, code);
    }
    if has_return_value(method) {
        if let Some(rt) = &method.return_type {
            let before = cur.pos;
            cur.overran = false;
            match decode_value(reg, sdk, &mut cur, rt, 0) {
                Some(mut n) => {
                    n.name = "return".to_string();
                    nodes.push(n);
                }
                None => {
                    let reason = if cur.overran {
                        "buffer overrun".to_string()
                    } else {
                        format!("return value (undecodable type {:?})", rt)
                    };
                    nodes.push(raw_tail("return".to_string(), before, buf.len(), reason));
                    return nodes;
                }
            }
        }
    }
    for param in &method.params {
        if param.direction == Direction::In {
            continue;
        }
        let before = cur.pos;
        cur.overran = false;
        match decode_value(reg, sdk, &mut cur, &param.ty, 0) {
            Some(mut n) => {
                n.name = param.name.clone();
                nodes.push(n);
            }
            None => {
                let reason = if cur.overran {
                    "buffer overrun".to_string()
                } else {
                    format!("param {} (undecodable type {:?})", param.name, param.ty)
                };
                nodes.push(raw_tail(param.name.clone(), before, buf.len(), reason));
                return nodes;
            }
        }
    }
    nodes
}

// Native (hand-written C++) interfaces write the reply with NO AIDL status header — the
// BpXxx reads reply values directly, in a per-method order. Decode the method's out/inout
// params in declaration order (the reply field order, including a synthetic `out int status`),
// with no header and no return value. Best-effort: a field that fails appends a raw tail.
pub fn decode_native_reply(
    reg: &Registry,
    sdk: u32,
    method: &Method,
    buf: &[u8],
    start: usize,
    offsets: &[u8],
) -> Vec<DecodedNode> {
    let mut cur = ParcelCursor::new(buf, start).with_offsets(offsets);
    let mut nodes = Vec::new();
    for param in &method.params {
        if param.direction == Direction::In {
            continue;
        }
        let before = cur.pos;
        cur.overran = false;
        match decode_value(reg, sdk, &mut cur, &param.ty, 0) {
            Some(mut n) => {
                n.name = param.name.clone();
                nodes.push(n);
            }
            None => {
                let reason = if cur.overran {
                    "buffer overrun".to_string()
                } else {
                    format!("param {} (undecodable type {:?})", param.name, param.ty)
                };
                nodes.push(raw_tail(param.name.clone(), before, buf.len(), reason));
                return nodes;
            }
        }
    }
    nodes
}

pub(crate) fn raw_tail(name: String, start: usize, buf_len: usize, reason: String) -> DecodedNode {
    DecodedNode {
        name,
        type_label: "raw".to_string(),
        start,
        len: buf_len.saturating_sub(start),
        value: DecodedValue::RawTail { reason },
        children: vec![],
    }
}

pub(crate) fn node(
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
    depth: u32,
) -> Option<DecodedNode> {
    if depth_exceeded(depth) {
        return None;
    }
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
        TypeRef::String8 => {
            let s = cur.read_string8()?;
            Some(node(
                DecodedValue::Str(s),
                "String8",
                start,
                cur.pos - start,
                vec![],
            ))
        }
        TypeRef::CString => {
            let s = cur.read_cstring()?;
            Some(node(
                DecodedValue::Str(s),
                "CString",
                start,
                cur.pos - start,
                vec![],
            ))
        }
        TypeRef::UserDefined(fqn) => {
            if let Some(n) = crate::native_struct::decode(reg, sdk, cur, fqn, start, depth + 1) {
                return Some(n);
            }
            if let Some(label) = bundle_label(fqn) {
                // AIDL Java backend writes a Bundle/PersistableBundle arg (or struct field)
                // via Parcel.writeTypedObject: int32 presence (0=null, 1=present) then
                // writeToParcel (system/tools/aidl aidl_to_java.cpp, SDK 23+). Bundle is a
                // Java-only type, so this is always the wire form. (The nested-in-Map path
                // uses writeValue -> writeBundle, which has no flag, and is handled in
                // decode_inline_value.)
                match cur.read_i32()? {
                    0 => Some(node(
                        DecodedValue::Bundle { len: 0, null: true },
                        label,
                        start,
                        cur.pos - start,
                        vec![],
                    )),
                    1 => decode_bundle_body(reg, sdk, cur, label, start, depth + 1),
                    _ => None,
                }
            } else if let Some(e) = reg.enum_def(sdk, fqn) {
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
            } else if reg.parcelable_def(sdk, fqn).is_some() {
                decode_parcelable_arg(reg, sdk, cur, fqn, start, depth + 1)
            } else if reg.is_interface(sdk, fqn) {
                // interface-typed params are inline flat_binder_objects, same wire form as IBinder
                match cur.read_binder_object() {
                    Some((handle, strong)) => Some(node(
                        DecodedValue::Binder { handle, strong },
                        "IBinder",
                        start,
                        cur.pos - start,
                        vec![],
                    )),
                    None => None,
                }
            } else {
                decode_union(reg, sdk, cur, fqn, start, depth + 1)
            }
        }
        TypeRef::Array(el) | TypeRef::List(el) => decode_array(reg, sdk, cur, el, start, depth + 1),
        TypeRef::Nullable(inner) => decode_nullable(reg, sdk, cur, inner, start, depth + 1),
        TypeRef::Map(_, _) => decode_map(reg, sdk, cur, start, depth + 1),
        // HIDL-only types have no AIDL wire form; callers surface them as opaque.
        TypeRef::FixedArray(_, _) | TypeRef::HidlHandle | TypeRef::HidlMemory => None,
        TypeRef::IBinder => match cur.read_binder_object() {
            Some((handle, strong)) => Some(node(
                DecodedValue::Binder { handle, strong },
                "IBinder",
                start,
                cur.pos - start,
                vec![],
            )),
            None => None, // not at a known binder object (e.g. no offsets) -> caller halts
        },
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
    depth: u32,
) -> Option<DecodedNode> {
    if depth_exceeded(depth) {
        return None;
    }
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
        match decode_value(reg, sdk, cur, el, depth + 1) {
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

// a @nullable parcelable is preceded by an int32 presence flag (0=null, 1=present);
// String/array/List/Map encode null inline (no flag), so decode the inner directly.
fn decode_nullable(
    reg: &Registry,
    sdk: u32,
    cur: &mut ParcelCursor,
    inner: &TypeRef,
    start: usize,
    depth: u32,
) -> Option<DecodedNode> {
    if depth_exceeded(depth) {
        return None;
    }
    if let TypeRef::UserDefined(fqn) = inner {
        let is_struct_parcelable = reg.enum_def(sdk, fqn).is_none()
            && reg
                .parcelable_def(sdk, fqn)
                .is_some_and(|p| !p.fields.is_empty());
        let is_union = !is_struct_parcelable
            && reg
                .union_def(sdk, fqn)
                .is_some_and(|u| !u.fields.is_empty());
        if is_struct_parcelable || is_union {
            let present = cur.read_i32()?;
            if present == 0 {
                let v = if is_union {
                    DecodedValue::Union {
                        fqn: fqn.clone(),
                        null: true,
                    }
                } else {
                    DecodedValue::Parcelable {
                        fqn: fqn.clone(),
                        null: true,
                    }
                };
                return Some(node(v, fqn, start, cur.pos - start, vec![]));
            }
            return if is_union {
                decode_union(reg, sdk, cur, fqn, cur.pos, depth + 1)
            } else {
                decode_parcelable(reg, sdk, cur, fqn, cur.pos, depth + 1)
            };
        }
    }
    decode_value(reg, sdk, cur, inner, depth + 1) // inline-null types
}

// union: int32 tag (0-based field index) then the selected member. no size header,
// so an out-of-range tag or an undecodable member is undecodable here — the caller
// stops (top level) or resyncs (a parcelable field, via its own size boundary).
fn decode_union(
    reg: &Registry,
    sdk: u32,
    cur: &mut ParcelCursor,
    fqn: &str,
    start: usize,
    depth: u32,
) -> Option<DecodedNode> {
    if depth_exceeded(depth) {
        return None;
    }
    let u = reg.union_def(sdk, fqn)?;
    if u.fields.is_empty() {
        return None;
    }
    let fields = u.fields.clone(); // release the reg borrow before &mut cur
    let ufqn = u.fqn.clone();
    let tag = cur.read_i32()?;
    let idx = usize::try_from(tag).ok()?;
    let field = fields.get(idx)?; // out-of-range tag -> None
    let mut child = decode_value(reg, sdk, cur, &field.ty, depth + 1)?; // member undecodable -> None
    child.name = field.name.clone();
    Some(node(
        DecodedValue::Union {
            fqn: ufqn,
            null: false,
        },
        fqn,
        start,
        cur.pos - start,
        vec![child],
    ))
}

// A structured parcelable passed as an AIDL arg or struct field. The Java backend
// writes it via Parcel.writeTypedObject (int32 presence flag 0=null/1=present, identical
// for @nullable and non-null); the C++ backend writes a non-null parcelable directly with
// no flag. A structured parcelable's size header is always >= 4 (decode_parcelable rejects
// < 4), so a leading 0 or 1 is unambiguously a presence flag and a leading >= 4 is the size
// itself — letting us accept both wire forms without per-interface backend metadata.
// (system/tools/aidl aidl_to_java.cpp writeTypedObject; decode_parcelable size>=4 invariant.)
fn decode_parcelable_arg(
    reg: &Registry,
    sdk: u32,
    cur: &mut ParcelCursor,
    fqn: &str,
    start: usize,
    depth: u32,
) -> Option<DecodedNode> {
    let p = reg.parcelable_def(sdk, fqn)?;
    // unstructured / forward-declared parcelables have no size header to lean on; defer to
    // decode_parcelable, which returns None for them.
    if p.fields.is_empty() {
        return decode_parcelable(reg, sdk, cur, fqn, start, depth);
    }
    let save = cur.pos;
    match cur.read_i32()? {
        0 => Some(node(
            DecodedValue::Parcelable {
                fqn: p.fqn.clone(),
                null: true,
            },
            fqn,
            start,
            cur.pos - start,
            vec![],
        )),
        // presence flag = present: the size header is the next int (start at cur.pos).
        1 => decode_parcelable(reg, sdk, cur, fqn, cur.pos, depth),
        // no flag: the int we read is the size header itself; rewind and decode in place.
        _ => {
            cur.pos = save;
            decode_parcelable(reg, sdk, cur, fqn, save, depth)
        }
    }
}

// decode a structured AIDL parcelable: int32 size (incl. itself), fields in
// declaration order guarded by the boundary, then resync to start+size.
fn decode_parcelable(
    reg: &Registry,
    sdk: u32,
    cur: &mut ParcelCursor,
    fqn: &str,
    start: usize,
    depth: u32,
) -> Option<DecodedNode> {
    if depth_exceeded(depth) {
        return None;
    }
    let p = reg.parcelable_def(sdk, fqn)?;
    if p.fields.is_empty() {
        return None; // unstructured / forward-declared: no size header on the wire
    }
    let raw_size = cur.read_i32()?;
    if raw_size < 4 {
        return None;
    }
    let size = raw_size as usize;
    let end = start.checked_add(size)?;
    if end > cur.buf_len() {
        return None;
    }
    // clone fields + fqn to release the reg borrow before the &mut cur loop
    let fields = p.fields.clone();
    let pfqn = p.fqn.clone();
    let mut children = Vec::new();
    for field in &fields {
        if cur.pos - start >= size {
            break; // boundary: trailing fields absent (older sender)
        }
        match decode_value(reg, sdk, cur, &field.ty, depth + 1) {
            Some(mut n) => {
                n.name = field.name.clone();
                children.push(n);
            }
            None => {
                // undecodable field (map/union/etc) — width unknown; surface the
                // rest of the block as raw and stop this block's fields.
                if cur.pos < end {
                    children.push(node(
                        DecodedValue::Bytes,
                        "raw",
                        cur.pos,
                        end - cur.pos,
                        vec![],
                    ));
                }
                break;
            }
        }
    }
    cur.seek(end)?; // resync to the block boundary regardless
    Some(node(
        DecodedValue::Parcelable {
            fqn: pfqn,
            null: false,
        },
        fqn,
        start,
        size,
        children,
    ))
}

// Android Parcel.writeValue type tags (frameworks/base Parcel.java).
#[allow(dead_code)]
mod val {
    pub const NULL: i32 = -1;
    pub const STRING: i32 = 0;
    pub const INTEGER: i32 = 1;
    pub const MAP: i32 = 2;
    pub const BUNDLE: i32 = 3;
    pub const PARCELABLE: i32 = 4;
    pub const SHORT: i32 = 5;
    pub const LONG: i32 = 6;
    pub const FLOAT: i32 = 7;
    pub const DOUBLE: i32 = 8;
    pub const BOOLEAN: i32 = 9;
    pub const CHARSEQUENCE: i32 = 10;
    pub const LIST: i32 = 11;
    pub const SPARSEARRAY: i32 = 12;
    pub const BYTEARRAY: i32 = 13;
    pub const STRINGARRAY: i32 = 14;
    pub const IBINDER: i32 = 15;
    pub const PARCELABLEARRAY: i32 = 16;
    pub const OBJECTARRAY: i32 = 17;
    pub const INTARRAY: i32 = 18;
    pub const LONGARRAY: i32 = 19;
    pub const BYTE: i32 = 20;
    pub const SERIALIZABLE: i32 = 21;
    pub const SPARSEBOOLEANARRAY: i32 = 22;
    pub const BOOLEANARRAY: i32 = 23;
    pub const PERSISTABLEBUNDLE: i32 = 25;
    pub const SIZE: i32 = 26;
    pub const SIZEF: i32 = 27;
    pub const DOUBLEARRAY: i32 = 28;
    pub const CHAR: i32 = 29;
    pub const SHORTARRAY: i32 = 30;
    pub const CHARARRAY: i32 = 31;
    pub const FLOATARRAY: i32 = 32;
}

fn is_length_prefixed(tag: i32) -> bool {
    matches!(
        tag,
        val::MAP
            | val::PARCELABLE
            | val::LIST
            | val::SPARSEARRAY
            | val::PARCELABLEARRAY
            | val::OBJECTARRAY
            | val::SERIALIZABLE
    )
}

// read one self-describing Parcel.writeValue: int32 tag + payload.
// name is left empty (caller sets key/value/element).
fn decode_parcel_value(
    reg: &Registry,
    sdk: u32,
    cur: &mut ParcelCursor,
    depth: u32,
) -> Option<DecodedNode> {
    if depth_exceeded(depth) {
        return None;
    }
    let start = cur.pos;
    let tag = cur.read_i32()?;
    if is_length_prefixed(tag) {
        let len = cur.read_i32()?;
        if len < 0 {
            return None;
        }
        let end = cur.pos.checked_add(len as usize)?;
        if end > cur.buf_len() {
            return None;
        }
        let body_start = cur.pos;
        let decoded = match tag {
            val::MAP => decode_map(reg, sdk, cur, body_start, depth + 1),
            val::LIST | val::OBJECTARRAY => decode_value_list(reg, sdk, cur, body_start, depth + 1),
            val::PARCELABLEARRAY => decode_value_list(reg, sdk, cur, body_start, depth + 1),
            val::PARCELABLE => decode_value_parcelable(reg, sdk, cur, body_start, depth + 1),
            val::SPARSEARRAY => decode_sparse_array(reg, sdk, cur, body_start, depth + 1),
            val::SERIALIZABLE => decode_value_serializable(cur, body_start, end, depth + 1),
            _ => None, // anything else: opaque blob
        };
        // resync to block end regardless (best-effort containment)
        cur.seek(end)?;
        return Some(decoded.unwrap_or_else(|| {
            node(
                DecodedValue::Bytes,
                val_label(tag),
                body_start,
                end - body_start,
                vec![],
            )
        }));
    }
    decode_inline_value(reg, sdk, cur, tag, start, depth)
}

// VAL_LIST / VAL_OBJECTARRAY / VAL_PARCELABLEARRAY body: int32 count + count values.
fn decode_value_list(
    reg: &Registry,
    sdk: u32,
    cur: &mut ParcelCursor,
    start: usize,
    depth: u32,
) -> Option<DecodedNode> {
    if depth_exceeded(depth) {
        return None;
    }
    let n = cur.read_i32()?;
    if n < 0 {
        return Some(node(
            DecodedValue::Array { len: 0, null: true },
            "list",
            start,
            cur.pos - start,
            vec![],
        ));
    }
    let mut children = Vec::with_capacity((n as usize).min(1024));
    for _ in 0..n {
        children.push(decode_parcel_value(reg, sdk, cur, depth + 1)?);
    }
    Some(node(
        DecodedValue::Array {
            len: n as usize,
            null: false,
        },
        "list",
        start,
        cur.pos - start,
        children,
    ))
}

// VAL_PARCELABLE body: String16 class-name (Parcel.writeString, no tag prefix) then structured block.
fn decode_value_parcelable(
    reg: &Registry,
    sdk: u32,
    cur: &mut ParcelCursor,
    _start: usize,
    depth: u32,
) -> Option<DecodedNode> {
    if depth_exceeded(depth) {
        return None;
    }
    // outer None = overrun; inner None = null class name -> undecodable
    let name = cur.read_string16()??;
    let pstart = cur.pos;
    decode_parcelable(reg, sdk, cur, &name, pstart, depth + 1)
}

// VAL_SPARSEARRAY body: int32 count + count x (int32 key, writeValue value).
fn decode_sparse_array(
    reg: &Registry,
    sdk: u32,
    cur: &mut ParcelCursor,
    start: usize,
    depth: u32,
) -> Option<DecodedNode> {
    if depth_exceeded(depth) {
        return None;
    }
    let n = cur.read_i32()?;
    if n < 0 {
        return Some(node(
            DecodedValue::Map { len: 0, null: true },
            "SparseArray",
            start,
            cur.pos - start,
            vec![],
        ));
    }
    let mut entries = Vec::with_capacity((n as usize).min(1024));
    for _ in 0..n {
        let epos = cur.pos;
        let key = cur.read_i32()?;
        let mut v = decode_parcel_value(reg, sdk, cur, depth + 1)?;
        v.name = "value".to_string();
        let k = node(DecodedValue::I64(key as i64), "key", epos, 4, vec![]);
        entries.push(node(
            DecodedValue::MapEntry,
            "entry",
            epos,
            cur.pos - epos,
            vec![k, v],
        ));
    }
    Some(node(
        DecodedValue::Map {
            len: n as usize,
            null: false,
        },
        "SparseArray",
        start,
        cur.pos - start,
        entries,
    ))
}

fn decode_inline_value(
    reg: &Registry,
    sdk: u32,
    cur: &mut ParcelCursor,
    tag: i32,
    start: usize,
    depth: u32,
) -> Option<DecodedNode> {
    let mk = |v, label, cur: &ParcelCursor| node(v, label, start, cur.pos - start, vec![]);
    match tag {
        val::NULL => Some(mk(DecodedValue::Str(None), "null", cur)),
        val::STRING => {
            let s = cur.read_string16()?;
            Some(mk(DecodedValue::Str(s), "String", cur))
        }
        val::INTEGER => Some(mk(DecodedValue::I64(cur.read_i32()? as i64), "int", cur)),
        val::SHORT => Some(mk(DecodedValue::I64(cur.read_i32()? as i64), "short", cur)),
        val::BYTE => Some(mk(DecodedValue::I64(cur.read_i32()? as i64), "byte", cur)),
        val::CHAR => Some(mk(DecodedValue::U64(cur.read_u32()? as u64), "char", cur)),
        val::BOOLEAN => Some(mk(DecodedValue::Bool(cur.read_i32()? != 0), "boolean", cur)),
        val::LONG => Some(mk(DecodedValue::I64(cur.read_i64()?), "long", cur)),
        val::FLOAT => Some(mk(DecodedValue::F64(cur.read_f32()? as f64), "float", cur)),
        val::DOUBLE => Some(mk(DecodedValue::F64(cur.read_f64()?), "double", cur)),
        val::SIZE => {
            cur.read_i32()?;
            cur.read_i32()?;
            Some(mk(DecodedValue::Raw, "Size", cur))
        }
        val::SIZEF => {
            cur.read_f32()?;
            cur.read_f32()?;
            Some(mk(DecodedValue::Raw, "SizeF", cur))
        }
        val::BYTEARRAY => {
            let n = cur.read_i32()?;
            if n < 0 {
                return Some(mk(DecodedValue::Bytes, "byte[]", cur));
            }
            let dstart = cur.pos;
            cur.skip(crate::token::pad_to_4(n as usize))?;
            Some(node(
                DecodedValue::Bytes,
                "byte[]",
                dstart,
                n as usize,
                vec![],
            ))
        }
        val::INTARRAY
        | val::LONGARRAY
        | val::DOUBLEARRAY
        | val::BOOLEANARRAY
        | val::SHORTARRAY
        | val::CHARARRAY
        | val::FLOATARRAY
        | val::STRINGARRAY => decode_value_array(cur, tag, start),
        val::CHARSEQUENCE => {
            // frameworks/base/core/java/android/text/TextUtils.java writeToParcel:
            // int32 kind, then writeString8(text). kind==1 plain; kind==0 Spanned, where
            // opaque ParcelableSpans (no length prefix) follow the text. String8 here since
            // SDK 33 (verified android13-release, our floor). We decode the plain case; a
            // styled CharSequence is undecodable, so we bail before consuming anything past
            // the kind so the caller resyncs cleanly.
            let kind = cur.read_i32()?;
            if kind != 1 {
                return None;
            }
            let s = cur.read_string8()?;
            Some(mk(DecodedValue::Str(s), "CharSequence", cur))
        }
        val::BUNDLE => decode_bundle_body(reg, sdk, cur, "Bundle", start, depth + 1),
        val::PERSISTABLEBUNDLE => {
            decode_bundle_body(reg, sdk, cur, "PersistableBundle", start, depth + 1)
        }
        val::SPARSEBOOLEANARRAY => {
            let n = cur.read_i32()?;
            if n < 0 {
                return Some(mk(
                    DecodedValue::Array { len: 0, null: true },
                    "SparseBooleanArray",
                    cur,
                ));
            }
            let mut entries = Vec::with_capacity((n as usize).min(1024));
            for _ in 0..n {
                let epos = cur.pos;
                let key = cur.read_i32()?;
                let b = cur.read_i32()? != 0;
                let k = node(DecodedValue::I64(key as i64), "key", epos, 4, vec![]);
                let v = node(DecodedValue::Bool(b), "value", epos + 4, 4, vec![]);
                entries.push(node(
                    DecodedValue::MapEntry,
                    "entry",
                    epos,
                    cur.pos - epos,
                    vec![k, v],
                ));
            }
            Some(node(
                DecodedValue::Map {
                    len: n as usize,
                    null: false,
                },
                "SparseBooleanArray",
                start,
                cur.pos - start,
                entries,
            ))
        }
        // VAL_IBINDER (flat binder object) is undecodable here.
        _ => None,
    }
}

// a count-prefixed homogeneous array (each element a fixed-width slot or String16).
fn decode_value_array(cur: &mut ParcelCursor, tag: i32, start: usize) -> Option<DecodedNode> {
    let n = cur.read_i32()?;
    if n < 0 {
        return Some(node(
            DecodedValue::Array { len: 0, null: true },
            "array",
            start,
            cur.pos - start,
            vec![],
        ));
    }
    let mut children = Vec::with_capacity((n as usize).min(1024));
    for _ in 0..n {
        let es = cur.pos;
        let (v, label): (DecodedValue, &str) = match tag {
            val::INTARRAY => (DecodedValue::I64(cur.read_i32()? as i64), "int"),
            val::LONGARRAY => (DecodedValue::I64(cur.read_i64()?), "long"),
            val::DOUBLEARRAY => (DecodedValue::F64(cur.read_f64()?), "double"),
            val::FLOATARRAY => (DecodedValue::F64(cur.read_f32()? as f64), "float"),
            val::BOOLEANARRAY => (DecodedValue::Bool(cur.read_i32()? != 0), "boolean"),
            val::SHORTARRAY => (DecodedValue::I64(cur.read_i32()? as i64), "short"),
            val::CHARARRAY => (DecodedValue::U64(cur.read_u32()? as u64), "char"),
            val::STRINGARRAY => (DecodedValue::Str(cur.read_string16()?), "String"),
            _ => return None,
        };
        children.push(node(v, label, es, cur.pos - es, vec![]));
    }
    Some(node(
        DecodedValue::Array {
            len: n as usize,
            null: false,
        },
        "array",
        start,
        cur.pos - start,
        children,
    ))
}

fn val_label(tag: i32) -> &'static str {
    match tag {
        val::MAP => "Map",
        val::LIST => "List",
        val::PARCELABLE => "Parcelable",
        val::SPARSEARRAY => "SparseArray",
        val::PARCELABLEARRAY => "Parcelable[]",
        val::OBJECTARRAY => "Object[]",
        val::SERIALIZABLE => "Serializable",
        _ => "value",
    }
}

// BUNDLE_MAGIC / BUNDLE_MAGIC_NATIVE from frameworks/base BaseBundle.java
// ("BNDL" / "BNDN"); both are valid Bundle bodies.
const BUNDLE_MAGIC: i32 = 0x4C44_4E42;
const BUNDLE_MAGIC_NATIVE: i32 = 0x4C44_4E44;

// android.os.Bundle / android.os.PersistableBundle, written via Parcel.writeBundle as
// [int32 length][int32 magic][arraymap]. Matched by the simple class name: the parser
// qualifies a bare `Bundle`/`PersistableBundle` by the using package, so the full fqn varies.
fn bundle_label(fqn: &str) -> Option<&'static str> {
    match fqn.rsplit('.').next().unwrap_or(fqn) {
        "Bundle" => Some("Bundle"),
        "PersistableBundle" => Some("PersistableBundle"),
        _ => None,
    }
}

// Decode a Bundle/PersistableBundle body. Cursor must be at the int32 length.
// Wire (BaseBundle.writeToParcelInner): [int32 length][int32 magic][arraymap], where
// length is the arraymap byte count only (excludes the 4-byte magic); length==0 is an
// empty bundle with no magic; via writeBundle a null bundle is [int32 -1]. The arraymap
// is [int32 N] + N x (String16 key, writeValue value). Best-effort: resync to the block
// end regardless, so a later sibling value still decodes.
fn decode_bundle_body(
    reg: &Registry,
    sdk: u32,
    cur: &mut ParcelCursor,
    label: &'static str,
    start: usize,
    depth: u32,
) -> Option<DecodedNode> {
    if depth_exceeded(depth) {
        return None;
    }
    let length = cur.read_i32()?;
    if length == -1 {
        return Some(node(
            DecodedValue::Bundle { len: 0, null: true },
            label,
            start,
            cur.pos - start,
            vec![],
        ));
    }
    if length == 0 {
        return Some(node(
            DecodedValue::Bundle {
                len: 0,
                null: false,
            },
            label,
            start,
            cur.pos - start,
            vec![],
        ));
    }
    if length < 0 || length % 4 != 0 {
        return None;
    }
    let magic = cur.read_i32()?;
    if magic != BUNDLE_MAGIC && magic != BUNDLE_MAGIC_NATIVE {
        return None;
    }
    let body_start = cur.pos;
    let end = body_start.checked_add(length as usize)?;
    if end > cur.buf_len() {
        return None;
    }
    let count = cur.read_i32()?;
    let mut children = Vec::with_capacity((count.max(0) as usize).min(1024));
    if count >= 0 {
        for _ in 0..count {
            if cur.pos >= end {
                break;
            }
            // a null key shouldn't occur; treat it as a stop and resync.
            let key = match cur.read_string16()? {
                Some(k) => k,
                None => break,
            };
            match decode_parcel_value(reg, sdk, cur, depth + 1) {
                Some(mut v) => {
                    v.name = key;
                    children.push(v);
                }
                None => break, // undecodable value: stop, resync below
            }
        }
    }
    cur.seek(end)?; // resync to block boundary regardless
    Some(node(
        DecodedValue::Bundle {
            len: children.len(),
            null: false,
        },
        label,
        start,
        cur.pos - start,
        children,
    ))
}

// VAL_SERIALIZABLE body: String16 class name + a byte[] of the Java object stream
// (frameworks/base Parcel.writeSerializable). The stream is opaque; we surface only the
// class name. Length-prefixed at the writeValue layer, so the caller resyncs to `end`.
fn decode_value_serializable(
    cur: &mut ParcelCursor,
    start: usize,
    end: usize,
    depth: u32,
) -> Option<DecodedNode> {
    if depth_exceeded(depth) {
        return None;
    }
    let class_name = cur.read_string16()?; // inner None = null class name
    Some(node(
        DecodedValue::Serializable { class_name },
        "Serializable",
        start,
        end - start,
        vec![],
    ))
}

// Map<String,V> (writeMap): int32 count (-1 null) then count x (value key, value value).
fn decode_map(
    reg: &Registry,
    sdk: u32,
    cur: &mut ParcelCursor,
    start: usize,
    depth: u32,
) -> Option<DecodedNode> {
    if depth_exceeded(depth) {
        return None;
    }
    let count = cur.read_i32()?;
    if count < 0 {
        return Some(node(
            DecodedValue::Map { len: 0, null: true },
            "map",
            start,
            cur.pos - start,
            vec![],
        ));
    }
    let mut entries = Vec::with_capacity((count as usize).min(1024));
    for _ in 0..count {
        let epos = cur.pos;
        let mut k = decode_parcel_value(reg, sdk, cur, depth + 1)?;
        k.name = "key".to_string();
        let mut v = decode_parcel_value(reg, sdk, cur, depth + 1)?;
        v.name = "value".to_string();
        entries.push(node(
            DecodedValue::MapEntry,
            "entry",
            epos,
            cur.pos - epos,
            vec![k, v],
        ));
    }
    Some(node(
        DecodedValue::Map {
            len: count as usize,
            null: false,
        },
        "map",
        start,
        cur.pos - start,
        entries,
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

    fn reg_with_parcelable(fqn: &str, fields: Vec<(&str, TypeRef)>) -> Registry {
        use crate::model::{Field, Parcelable};
        let mut o = OverlayLayer {
            source_path: "t".into(),
            interfaces: Default::default(),
            enums: Default::default(),
            parcelables: Default::default(),
            unions: Default::default(),
            typedefs: Default::default(),
        };
        o.parcelables.insert(
            fqn.into(),
            Parcelable {
                fqn: fqn.into(),
                fields: fields
                    .into_iter()
                    .map(|(n, ty)| Field {
                        name: n.to_string(),
                        ty,
                    })
                    .collect(),
            },
        );
        Registry::from_parts(vec![o], None, HashMap::new())
    }

    // a structured parcelable block: int32 size (incl itself) + body bytes.
    fn parcelable_block(body: &[u8]) -> Vec<u8> {
        let size = (body.len() + 4) as i32;
        let mut v = size.to_le_bytes().to_vec();
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn decodes_structured_parcelable_fields() {
        let reg = reg_with_parcelable(
            "a.P",
            vec![
                ("id", TypeRef::Primitive(Prim::I32)),
                ("name", TypeRef::String),
            ],
        );
        let m = method(vec![in_param("p", TypeRef::UserDefined("a.P".into()))]);
        let mut body = Vec::new();
        body.extend_from_slice(&7i32.to_le_bytes());
        body.extend_from_slice(&2i32.to_le_bytes());
        body.extend_from_slice(&(b'h' as u16).to_le_bytes());
        body.extend_from_slice(&(b'i' as u16).to_le_bytes());
        body.extend_from_slice(&[0, 0, 0, 0]); // NUL + pad
        let buf = parcelable_block(&body);
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(
            matches!(&nodes[0].value, DecodedValue::Parcelable { fqn, null: false } if fqn == "a.P")
        );
        assert_eq!(nodes[0].children.len(), 2);
        assert_eq!(nodes[0].children[0].name, "id");
        assert!(matches!(nodes[0].children[0].value, DecodedValue::I64(7)));
        assert!(matches!(&nodes[0].children[1].value, DecodedValue::Str(Some(s)) if s == "hi"));
    }

    #[test]
    fn decodes_java_backend_parcelable_arg() {
        // AIDL Java writeTypedObject prepends an int32 presence flag (1) before the
        // parcelable's size header; the size>=4 invariant disambiguates it, and the next
        // param must still decode (resync past flag + block).
        let reg = reg_with_parcelable("a.P", vec![("id", TypeRef::Primitive(Prim::I32))]);
        let m = method(vec![
            in_param("p", TypeRef::UserDefined("a.P".into())),
            in_param("after", TypeRef::Primitive(Prim::I32)),
        ]);
        let mut buf = 1i32.to_le_bytes().to_vec(); // presence = present
        buf.extend_from_slice(&parcelable_block(&7i32.to_le_bytes())); // [size][id=7]
        buf.extend_from_slice(&9i32.to_le_bytes());
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(
            matches!(&nodes[0].value, DecodedValue::Parcelable { fqn, null: false } if fqn == "a.P")
        );
        assert!(matches!(nodes[0].children[0].value, DecodedValue::I64(7)));
        assert_eq!(nodes[1].name, "after");
        assert!(matches!(nodes[1].value, DecodedValue::I64(9)));
    }

    #[test]
    fn decodes_null_parcelable_arg() {
        // writeTypedObject(null) is a bare int32 0.
        let reg = reg_with_parcelable("a.P", vec![("id", TypeRef::Primitive(Prim::I32))]);
        let m = method(vec![in_param("p", TypeRef::UserDefined("a.P".into()))]);
        let buf = 0i32.to_le_bytes();
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(
            matches!(&nodes[0].value, DecodedValue::Parcelable { fqn, null: true } if fqn == "a.P")
        );
    }

    #[test]
    fn parcelable_resyncs_and_next_param_decodes() {
        let reg = reg_with_parcelable("a.P", vec![("id", TypeRef::Primitive(Prim::I32))]);
        let m = method(vec![
            in_param("p", TypeRef::UserDefined("a.P".into())),
            in_param("after", TypeRef::Primitive(Prim::I32)),
        ]);
        let mut body = Vec::new();
        body.extend_from_slice(&5i32.to_le_bytes());
        body.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // extra trailing
        let mut buf = parcelable_block(&body);
        buf.extend_from_slice(&9i32.to_le_bytes());
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(matches!(nodes[0].children[0].value, DecodedValue::I64(5)));
        assert!(matches!(nodes[1].value, DecodedValue::I64(9)));
    }

    #[test]
    fn parcelable_short_block_omits_trailing_fields() {
        let reg = reg_with_parcelable(
            "a.P",
            vec![
                ("id", TypeRef::Primitive(Prim::I32)),
                ("extra", TypeRef::Primitive(Prim::I32)),
            ],
        );
        let m = method(vec![in_param("p", TypeRef::UserDefined("a.P".into()))]);
        let buf = parcelable_block(&5i32.to_le_bytes()); // size=8, only id
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert_eq!(nodes[0].children.len(), 1);
        assert!(matches!(nodes[0].children[0].value, DecodedValue::I64(5)));
    }

    #[test]
    fn parcelable_undecodable_field_yields_remainder() {
        // IBinder without offsets is undecodable; the parcelable surfaces the rest of the block
        // as a Bytes node and resyncs so the following param still decodes.
        let reg = reg_with_parcelable(
            "a.P",
            vec![
                ("id", TypeRef::Primitive(Prim::I32)),
                ("b", TypeRef::IBinder),
            ],
        );
        let m = method(vec![
            in_param("p", TypeRef::UserDefined("a.P".into())),
            in_param("after", TypeRef::Primitive(Prim::I32)),
        ]);
        let mut body = Vec::new();
        body.extend_from_slice(&3i32.to_le_bytes());
        body.extend_from_slice(&[1, 2, 3, 4]);
        let mut buf = parcelable_block(&body);
        buf.extend_from_slice(&9i32.to_le_bytes());
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(matches!(nodes[0].children[0].value, DecodedValue::I64(3)));
        assert!(matches!(
            nodes[0].children.last().unwrap().value,
            DecodedValue::Bytes
        ));
        assert!(matches!(nodes[1].value, DecodedValue::I64(9)));
    }

    #[test]
    fn zero_field_parcelable_is_undecodable() {
        let reg = reg_with_parcelable("a.Empty", vec![]);
        let m = method(vec![in_param("p", TypeRef::UserDefined("a.Empty".into()))]);
        let buf = [0u8; 8];
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(matches!(nodes[0].value, DecodedValue::RawTail { .. }));
    }

    #[test]
    fn nested_parcelable_field() {
        use crate::model::{Field, Parcelable};
        let mut o = OverlayLayer {
            source_path: "t".into(),
            interfaces: Default::default(),
            enums: Default::default(),
            parcelables: Default::default(),
            unions: Default::default(),
            typedefs: Default::default(),
        };
        o.parcelables.insert(
            "a.Inner".into(),
            Parcelable {
                fqn: "a.Inner".into(),
                fields: vec![Field {
                    name: "v".into(),
                    ty: TypeRef::Primitive(Prim::I32),
                }],
            },
        );
        o.parcelables.insert(
            "a.Outer".into(),
            Parcelable {
                fqn: "a.Outer".into(),
                fields: vec![Field {
                    name: "inner".into(),
                    ty: TypeRef::UserDefined("a.Inner".into()),
                }],
            },
        );
        let reg = Registry::from_parts(vec![o], None, HashMap::new());
        let m = method(vec![in_param("p", TypeRef::UserDefined("a.Outer".into()))]);
        let inner = parcelable_block(&42i32.to_le_bytes());
        let buf = parcelable_block(&inner);
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        let inner_node = &nodes[0].children[0];
        assert_eq!(inner_node.name, "inner");
        assert!(
            matches!(&inner_node.value, DecodedValue::Parcelable { fqn, .. } if fqn == "a.Inner")
        );
        assert!(matches!(
            inner_node.children[0].value,
            DecodedValue::I64(42)
        ));
    }

    #[test]
    fn nullable_parcelable_present_and_null() {
        let reg = reg_with_parcelable("a.P", vec![("id", TypeRef::Primitive(Prim::I32))]);
        let nty = TypeRef::Nullable(Box::new(TypeRef::UserDefined("a.P".into())));
        // present: flag=1 then the block; a following int must still decode.
        let m = method(vec![
            in_param("p", nty.clone()),
            in_param("after", TypeRef::Primitive(Prim::I32)),
        ]);
        let mut buf = 1i32.to_le_bytes().to_vec(); // presence flag = 1
        buf.extend_from_slice(&parcelable_block(&7i32.to_le_bytes()));
        buf.extend_from_slice(&9i32.to_le_bytes());
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(matches!(
            &nodes[0].value,
            DecodedValue::Parcelable { null: false, .. }
        ));
        assert!(matches!(nodes[0].children[0].value, DecodedValue::I64(7)));
        assert!(matches!(nodes[1].value, DecodedValue::I64(9)));

        // null: flag=0, no block; the following int decodes right after the flag.
        let m2 = method(vec![
            in_param("p", nty),
            in_param("after", TypeRef::Primitive(Prim::I32)),
        ]);
        let mut buf2 = 0i32.to_le_bytes().to_vec(); // presence flag = 0
        buf2.extend_from_slice(&9i32.to_le_bytes());
        let nodes2 = decode_aidl_params(&reg, 34, &m2, &buf2, 0, &[]);
        assert!(matches!(
            &nodes2[0].value,
            DecodedValue::Parcelable { null: true, .. }
        ));
        assert!(nodes2[0].children.is_empty());
        assert!(matches!(nodes2[1].value, DecodedValue::I64(9)));
    }

    #[test]
    fn nullable_string_decodes_inline_no_flag() {
        let reg = Registry::empty();
        let m = method(vec![in_param(
            "s",
            TypeRef::Nullable(Box::new(TypeRef::String)),
        )]);
        let mut buf = 2i32.to_le_bytes().to_vec(); // char_count 2 (no separate flag)
        buf.extend_from_slice(&(b'h' as u16).to_le_bytes());
        buf.extend_from_slice(&(b'i' as u16).to_le_bytes());
        buf.extend_from_slice(&[0, 0, 0, 0]);
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s == "hi"));
    }

    fn reg_with_enum(fqn: &str, backing: Prim, consts: Vec<(&str, i64)>) -> Registry {
        let mut o = OverlayLayer {
            source_path: "t".into(),
            interfaces: Default::default(),
            enums: Default::default(),
            parcelables: Default::default(),
            unions: Default::default(),
            typedefs: Default::default(),
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

    fn out_param(name: &str, ty: TypeRef) -> Parameter {
        Parameter {
            name: name.to_string(),
            ty,
            direction: Direction::Out,
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
    fn no_param_void_method_reads_empty() {
        let mut m = method(vec![]);
        m.return_type = Some(TypeRef::UserDefined("void".into()));
        assert!(takes_no_input_params(&m));
        assert!(produces_no_reply_data(&m));
    }

    #[test]
    fn out_only_method_has_no_input_but_has_reply() {
        let mut m = method(vec![out_param("y", TypeRef::Primitive(Prim::I32))]);
        m.return_type = None; // void return, but an out param flows back
        assert!(takes_no_input_params(&m));
        assert!(!produces_no_reply_data(&m)); // the out param is reply data
    }

    #[test]
    fn method_with_in_param_and_return_is_neither() {
        let mut m = method(vec![in_param("x", TypeRef::Primitive(Prim::I32))]);
        m.return_type = Some(TypeRef::Primitive(Prim::I32));
        assert!(!takes_no_input_params(&m));
        assert!(!produces_no_reply_data(&m));
    }

    #[test]
    fn inout_param_counts_as_both_input_and_reply() {
        let m = method(vec![Parameter {
            name: "io".into(),
            ty: TypeRef::Primitive(Prim::I32),
            direction: Direction::InOut,
        }]);
        assert!(!takes_no_input_params(&m));
        assert!(!produces_no_reply_data(&m));
    }

    #[test]
    fn decodes_scalar_enum_int_backing() {
        let reg = reg_with_enum("a.E", Prim::I32, vec![("OFF", 0), ("ON", 1)]);
        let m = method(vec![in_param("state", TypeRef::UserDefined("a.E".into()))]);
        let buf = 1i32.to_le_bytes();
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
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
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
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
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
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
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
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
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
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
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(matches!(nodes[0].value, DecodedValue::RawTail { .. }));
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
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
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
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
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
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert_eq!(nodes.len(), 2);
        assert!(matches!(nodes[0].value, DecodedValue::I64(1)));
        let tail = nodes.last().unwrap();
        assert!(
            matches!(&tail.value, DecodedValue::RawTail { reason } if reason.contains("undecodable")),
            "got {:?}",
            tail.value
        );
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
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(matches!(nodes[0].value, DecodedValue::I64(1)));
        let tail = nodes.last().unwrap();
        assert!(
            matches!(&tail.value, DecodedValue::RawTail { reason } if reason == "buffer overrun"),
            "got {:?}",
            tail.value
        );
    }

    #[test]
    fn undecodable_type_near_end_not_mislabeled_as_overrun() {
        // an unmodeled UserDefined param at position 4 with only 3 bytes remaining.
        // the old heuristic `before + 4 > buf.len()` fires here (4 + 4 = 8 > 7)
        // and would wrongly say "buffer overrun". the flag correctly says "undecodable"
        // because decode_union returns None from a registry miss — no take() fails.
        let reg = Registry::empty();
        let m = method(vec![
            in_param("x", TypeRef::Primitive(Prim::I32)),
            in_param("obj", TypeRef::UserDefined("a.b.Foo".into())),
        ]);
        let mut buf = 1i32.to_le_bytes().to_vec();
        buf.extend_from_slice(&[0xaa, 0xbb, 0xcc]); // 3 bytes remain (< 4)
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        let tail = nodes.last().unwrap();
        assert!(
            matches!(&tail.value, DecodedValue::RawTail { reason } if reason.contains("undecodable")),
            "got {:?}",
            tail.value
        );
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
    fn reads_string8() {
        // int32 len=5, "hello", NUL, pad to 4
        let mut buf = 5i32.to_le_bytes().to_vec();
        buf.extend_from_slice(b"hello\0");
        while buf.len() % 4 != 0 {
            buf.push(0);
        }
        let mut cur = ParcelCursor::new(&buf, 0);
        assert_eq!(cur.read_string8(), Some(Some("hello".to_string())));
        assert_eq!(cur.pos, buf.len());
    }

    #[test]
    fn reads_string8_null() {
        let buf = (-1i32).to_le_bytes();
        let mut cur = ParcelCursor::new(&buf, 0);
        assert_eq!(cur.read_string8(), Some(None));
    }

    #[test]
    fn reads_string8_overrun() {
        let buf = 9i32.to_le_bytes(); // claims 9 bytes, none follow
        let mut cur = ParcelCursor::new(&buf, 0);
        assert_eq!(cur.read_string8(), None);
    }

    #[test]
    fn reads_cstring() {
        // "egl\0" then pad to 4 (already 4)
        let buf = b"egl\0".to_vec();
        let mut c = ParcelCursor::new(&buf, 0);
        assert_eq!(c.read_cstring(), Some(Some("egl".to_string())));
        assert_eq!(c.pos, 4);
    }

    #[test]
    fn reads_cstring_padded() {
        // "ab\0" = 3 bytes -> padded to 4
        let mut buf = b"ab\0".to_vec();
        buf.push(0);
        buf.extend_from_slice(&7i32.to_le_bytes()); // sentinel after
        let mut c = ParcelCursor::new(&buf, 0);
        assert_eq!(c.read_cstring(), Some(Some("ab".to_string())));
        assert_eq!(c.pos, 4);
        assert_eq!(c.read_i32(), Some(7));
    }

    #[test]
    fn read_cstring_overrun_no_nul() {
        let buf = b"abc".to_vec(); // no NUL
        let mut c = ParcelCursor::new(&buf, 0);
        assert_eq!(c.read_cstring(), None);
    }

    #[test]
    fn decodes_string8_and_cstring_params() {
        let reg = Registry::empty();
        let m = method(vec![
            in_param("name", TypeRef::String8),
            in_param("path", TypeRef::CString),
        ]);
        let mut buf = Vec::new();
        // String8 "hi": i32 len=2, "hi", NUL, pad to 4
        buf.extend_from_slice(&2i32.to_le_bytes());
        buf.extend_from_slice(b"hi\0");
        buf.push(0);
        // CString "egl": "egl\0"
        buf.extend_from_slice(b"egl\0");
        let nodes = decode_aidl_params(&reg, 35, &m, &buf, 0, &[]);
        assert!(matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s == "hi"));
        assert!(matches!(&nodes[1].value, DecodedValue::Str(Some(s)) if s == "egl"));
    }

    #[test]
    fn overrun_returns_none() {
        let buf = [0u8; 2];
        let mut c = ParcelCursor::new(&buf, 0);
        assert_eq!(c.read_i32(), None);
    }

    fn reg_with_union(fqn: &str, fields: Vec<(&str, TypeRef)>) -> Registry {
        use crate::model::{Field, Union};
        let mut o = OverlayLayer {
            source_path: "t".into(),
            interfaces: Default::default(),
            enums: Default::default(),
            parcelables: Default::default(),
            unions: Default::default(),
            typedefs: Default::default(),
        };
        o.unions.insert(
            fqn.into(),
            Union {
                fqn: fqn.into(),
                fields: fields
                    .into_iter()
                    .map(|(n, ty)| Field {
                        name: n.to_string(),
                        ty,
                    })
                    .collect(),
            },
        );
        Registry::from_parts(vec![o], None, HashMap::new())
    }

    #[test]
    fn decodes_union_int_member() {
        let reg = reg_with_union(
            "a.U",
            vec![("n", TypeRef::Primitive(Prim::I32)), ("s", TypeRef::String)],
        );
        let m = method(vec![in_param("u", TypeRef::UserDefined("a.U".into()))]);
        let mut buf = 0i32.to_le_bytes().to_vec(); // tag 0 -> n
        buf.extend_from_slice(&42i32.to_le_bytes());
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(
            matches!(&nodes[0].value, DecodedValue::Union { fqn, null: false } if fqn == "a.U")
        );
        assert_eq!(nodes[0].children.len(), 1);
        assert_eq!(nodes[0].children[0].name, "n");
        assert!(matches!(nodes[0].children[0].value, DecodedValue::I64(42)));
    }

    #[test]
    fn decodes_union_string_member() {
        let reg = reg_with_union(
            "a.U",
            vec![("n", TypeRef::Primitive(Prim::I32)), ("s", TypeRef::String)],
        );
        let m = method(vec![in_param("u", TypeRef::UserDefined("a.U".into()))]);
        let mut buf = 1i32.to_le_bytes().to_vec(); // tag 1 -> s
        buf.extend_from_slice(&2i32.to_le_bytes()); // "hi"
        buf.extend_from_slice(&(b'h' as u16).to_le_bytes());
        buf.extend_from_slice(&(b'i' as u16).to_le_bytes());
        buf.extend_from_slice(&[0, 0, 0, 0]);
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert_eq!(nodes[0].children[0].name, "s");
        assert!(matches!(&nodes[0].children[0].value, DecodedValue::Str(Some(s)) if s == "hi"));
    }

    #[test]
    fn union_out_of_range_tag_is_raw() {
        let reg = reg_with_union("a.U", vec![("n", TypeRef::Primitive(Prim::I32))]);
        let m = method(vec![in_param("u", TypeRef::UserDefined("a.U".into()))]);
        let buf = 5i32.to_le_bytes().to_vec(); // tag 5, only field 0 exists
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(matches!(nodes[0].value, DecodedValue::RawTail { .. }));
    }

    #[test]
    fn nullable_union_present_and_null() {
        let reg = reg_with_union("a.U", vec![("n", TypeRef::Primitive(Prim::I32))]);
        let nty = TypeRef::Nullable(Box::new(TypeRef::UserDefined("a.U".into())));
        // present: flag=1, tag 0, value
        let m = method(vec![
            in_param("u", nty.clone()),
            in_param("after", TypeRef::Primitive(Prim::I32)),
        ]);
        let mut buf = 1i32.to_le_bytes().to_vec(); // present
        buf.extend_from_slice(&0i32.to_le_bytes()); // tag 0
        buf.extend_from_slice(&7i32.to_le_bytes()); // n=7
        buf.extend_from_slice(&9i32.to_le_bytes()); // after=9
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(matches!(
            &nodes[0].value,
            DecodedValue::Union { null: false, .. }
        ));
        assert!(matches!(nodes[0].children[0].value, DecodedValue::I64(7)));
        assert!(matches!(nodes[1].value, DecodedValue::I64(9)));
        // null: flag=0, following int decodes right after the flag
        let m2 = method(vec![
            in_param("u", nty),
            in_param("after", TypeRef::Primitive(Prim::I32)),
        ]);
        let mut buf2 = 0i32.to_le_bytes().to_vec(); // null
        buf2.extend_from_slice(&9i32.to_le_bytes());
        let nodes2 = decode_aidl_params(&reg, 34, &m2, &buf2, 0, &[]);
        assert!(matches!(
            &nodes2[0].value,
            DecodedValue::Union { null: true, .. }
        ));
        assert!(nodes2[0].children.is_empty());
        assert!(matches!(nodes2[1].value, DecodedValue::I64(9)));
    }

    #[test]
    fn union_field_in_parcelable_resyncs_on_bad_tag() {
        // a union field with an out-of-range tag -> parent parcelable emits raw remainder
        // + resyncs, so a following param still decodes.
        use crate::model::{Field, Parcelable, Union};
        let mut o = OverlayLayer {
            source_path: "t".into(),
            interfaces: Default::default(),
            enums: Default::default(),
            parcelables: Default::default(),
            unions: Default::default(),
            typedefs: Default::default(),
        };
        o.unions.insert(
            "a.U".into(),
            Union {
                fqn: "a.U".into(),
                fields: vec![Field {
                    name: "n".into(),
                    ty: TypeRef::Primitive(Prim::I32),
                }],
            },
        );
        o.parcelables.insert(
            "a.P".into(),
            Parcelable {
                fqn: "a.P".into(),
                fields: vec![Field {
                    name: "u".into(),
                    ty: TypeRef::UserDefined("a.U".into()),
                }],
            },
        );
        let reg = Registry::from_parts(vec![o], None, HashMap::new());
        let m = method(vec![
            in_param("p", TypeRef::UserDefined("a.P".into())),
            in_param("after", TypeRef::Primitive(Prim::I32)),
        ]);
        // P block: size, then union field = bad tag 9 + 4 junk bytes
        let mut body = 9i32.to_le_bytes().to_vec(); // union tag 9 (out of range)
        body.extend_from_slice(&[1, 2, 3, 4]);
        let size = (body.len() + 4) as i32;
        let mut buf = size.to_le_bytes().to_vec();
        buf.extend_from_slice(&body);
        buf.extend_from_slice(&9i32.to_le_bytes()); // after=9
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(matches!(&nodes[0].value, DecodedValue::Parcelable { .. }));
        assert!(matches!(
            nodes[0].children.last().unwrap().value,
            DecodedValue::Bytes
        )); // raw remainder
        assert!(matches!(nodes[1].value, DecodedValue::I64(9)));
    }

    #[test]
    fn list_of_parcelable_decodes() {
        // verifies array recursion already handles parcelable elements (2b side effect).
        use crate::model::{Field, Parcelable};
        let mut o = OverlayLayer {
            source_path: "t".into(),
            interfaces: Default::default(),
            enums: Default::default(),
            parcelables: Default::default(),
            unions: Default::default(),
            typedefs: Default::default(),
        };
        o.parcelables.insert(
            "a.P".into(),
            Parcelable {
                fqn: "a.P".into(),
                fields: vec![Field {
                    name: "v".into(),
                    ty: TypeRef::Primitive(Prim::I32),
                }],
            },
        );
        let reg = Registry::from_parts(vec![o], None, HashMap::new());
        let m = method(vec![in_param(
            "ps",
            TypeRef::Array(Box::new(TypeRef::UserDefined("a.P".into()))),
        )]);
        let mut buf = 2i32.to_le_bytes().to_vec(); // count 2
        for v in [5i32, 6] {
            let body = v.to_le_bytes();
            buf.extend_from_slice(&((body.len() + 4) as i32).to_le_bytes()); // P size=8
            buf.extend_from_slice(&body);
        }
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(matches!(nodes[0].value, DecodedValue::Array { len: 2, .. }));
        assert!(
            matches!(&nodes[0].children[0].value, DecodedValue::Parcelable { fqn, .. } if fqn == "a.P")
        );
        assert!(matches!(
            nodes[0].children[1].children[0].value,
            DecodedValue::I64(6)
        ));
    }

    fn val_i32(tag: i32, v: i32) -> Vec<u8> {
        let mut b = tag.to_le_bytes().to_vec();
        b.extend_from_slice(&v.to_le_bytes());
        b
    }

    // raw String16 (no tag prefix): int32 char_count + UTF-16 chars + u16 NUL, padded to 4.
    fn string16(s: &str) -> Vec<u8> {
        let utf16: Vec<u16> = s.encode_utf16().collect();
        let mut b = (utf16.len() as i32).to_le_bytes().to_vec();
        for u in &utf16 {
            b.extend_from_slice(&u.to_le_bytes());
        }
        b.extend_from_slice(&[0, 0]); // u16 NUL
        while b.len() % 4 != 0 {
            b.push(0);
        }
        b
    }

    fn val_string(s: &str) -> Vec<u8> {
        let mut b = 0i32.to_le_bytes().to_vec(); // VAL_STRING = 0
        b.extend_from_slice(&string16(s));
        b
    }

    // Bundle body: int32 length + int32 magic + arraymap(int32 count + per entry
    // String16 key + value bytes). length covers the arraymap only.
    fn bundle_body(entries: &[(&str, Vec<u8>)], native: bool) -> Vec<u8> {
        let mut arraymap = (entries.len() as i32).to_le_bytes().to_vec();
        for (k, v) in entries {
            arraymap.extend_from_slice(&string16(k));
            arraymap.extend_from_slice(v);
        }
        // BUNDLE_MAGIC=0x4C444E42, BUNDLE_MAGIC_NATIVE=0x4C444E44 (BaseBundle.java)
        let magic: i32 = if native { 0x4C44_4E44 } else { 0x4C44_4E42 };
        let mut b = (arraymap.len() as i32).to_le_bytes().to_vec();
        b.extend_from_slice(&magic.to_le_bytes());
        b.extend_from_slice(&arraymap);
        b
    }

    // raw String8 (no tag): int32 byte_count + UTF-8 bytes + u8 NUL, padded to 4.
    fn string8(s: &str) -> Vec<u8> {
        let mut b = (s.len() as i32).to_le_bytes().to_vec();
        b.extend_from_slice(s.as_bytes());
        b.push(0); // NUL
        while b.len() % 4 != 0 {
            b.push(0);
        }
        b
    }

    // VAL_CHARSEQUENCE(10): int32 kind + writeString8(text).
    fn val_charsequence(kind: i32, text: &str) -> Vec<u8> {
        let mut b = 10i32.to_le_bytes().to_vec(); // VAL_CHARSEQUENCE
        b.extend_from_slice(&kind.to_le_bytes());
        b.extend_from_slice(&string8(text));
        b
    }

    #[test]
    fn decodes_plain_charsequence_in_map() {
        let reg = Registry::empty();
        let m = method(vec![in_param(
            "cfg",
            TypeRef::Map(Box::new(TypeRef::String), Box::new(TypeRef::String)),
        )]);
        let mut buf = 1i32.to_le_bytes().to_vec(); // count 1
        buf.extend_from_slice(&val_string("k"));
        buf.extend_from_slice(&val_charsequence(1, "hello")); // kind 1 = plain
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        let entry = &nodes[0].children[0];
        assert!(matches!(&entry.children[1].value, DecodedValue::Str(Some(s)) if s == "hello"));
    }

    #[test]
    fn styled_charsequence_bails_safely() {
        // kind 0 = Spanned: spans are opaque, so the value is undecodable. The single-entry
        // map then fails wholesale and the param walk surfaces a raw tail (no panic, no corruption).
        let reg = Registry::empty();
        let m = method(vec![in_param(
            "cfg",
            TypeRef::Map(Box::new(TypeRef::String), Box::new(TypeRef::String)),
        )]);
        let mut buf = 1i32.to_le_bytes().to_vec(); // count 1
        buf.extend_from_slice(&val_string("k"));
        buf.extend_from_slice(&val_charsequence(0, "styled")); // kind 0 = spanned
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(matches!(nodes[0].value, DecodedValue::RawTail { .. }));
    }

    // VAL_BUNDLE(3)-tagged value (the nested-in-map form): tag + bundle body.
    fn val_bundle(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut b = 3i32.to_le_bytes().to_vec(); // VAL_BUNDLE
        b.extend_from_slice(&bundle_body(entries, false));
        b
    }

    // VAL_SERIALIZABLE(21), length-prefixed: int32 len + [String16 className][byte[] blob].
    fn val_serializable(class: &str, blob: &[u8]) -> Vec<u8> {
        let mut body = string16(class);
        body.extend_from_slice(&(blob.len() as i32).to_le_bytes()); // byte[] count
        body.extend_from_slice(blob);
        while body.len() % 4 != 0 {
            body.push(0);
        }
        let mut b = 21i32.to_le_bytes().to_vec(); // VAL_SERIALIZABLE
        b.extend_from_slice(&(body.len() as i32).to_le_bytes()); // length prefix
        b.extend_from_slice(&body);
        b
    }

    #[test]
    fn labels_serializable_in_map() {
        let reg = Registry::empty();
        let m = method(vec![in_param(
            "cfg",
            TypeRef::Map(Box::new(TypeRef::String), Box::new(TypeRef::String)),
        )]);
        let mut buf = 2i32.to_le_bytes().to_vec(); // count 2
        buf.extend_from_slice(&val_string("k1"));
        buf.extend_from_slice(&val_serializable(
            "java.lang.Integer",
            &[0xAC, 0xED, 0x00, 0x05],
        ));
        buf.extend_from_slice(&val_string("k2"));
        buf.extend_from_slice(&val_string("v2"));
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        let e0 = &nodes[0].children[0];
        assert!(matches!(
            &e0.children[1].value,
            DecodedValue::Serializable { class_name: Some(s) } if s == "java.lang.Integer"
        ));
        // following entry still decodes (length-prefix resync)
        let e1 = &nodes[0].children[1];
        assert!(matches!(&e1.children[1].value, DecodedValue::Str(Some(s)) if s == "v2"));
    }

    // a Bundle direct-param on the wire: AIDL Java writeTypedObject presence flag (1) + body.
    fn typed_bundle(entries: &[(&str, Vec<u8>)], native: bool) -> Vec<u8> {
        let mut b = 1i32.to_le_bytes().to_vec(); // presence = present
        b.extend_from_slice(&bundle_body(entries, native));
        b
    }

    #[test]
    fn decodes_empty_bundle_param() {
        let reg = Registry::empty();
        let m = method(vec![in_param(
            "b",
            TypeRef::UserDefined("android.os.Bundle".into()),
        )]);
        // presence=1, then an empty bundle body (length 0, no magic).
        let mut buf = 1i32.to_le_bytes().to_vec();
        buf.extend_from_slice(&0i32.to_le_bytes());
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(matches!(
            nodes[0].value,
            DecodedValue::Bundle {
                len: 0,
                null: false
            }
        ));
    }

    #[test]
    fn decodes_null_bundle_param() {
        let reg = Registry::empty();
        let m = method(vec![in_param(
            "b",
            TypeRef::UserDefined("android.os.Bundle".into()),
        )]);
        let buf = 0i32.to_le_bytes(); // writeTypedObject presence = null
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(matches!(
            nodes[0].value,
            DecodedValue::Bundle { len: 0, null: true }
        ));
    }

    #[test]
    fn decodes_populated_bundle_param() {
        let reg = Registry::empty();
        let m = method(vec![in_param(
            "b",
            TypeRef::UserDefined("android.os.Bundle".into()),
        )]);
        let buf = typed_bundle(&[("k", val_i32(1, 42))], false); // VAL_INTEGER=1
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(matches!(
            &nodes[0].value,
            DecodedValue::Bundle {
                len: 1,
                null: false
            }
        ));
        assert_eq!(nodes[0].children[0].name, "k");
        assert!(matches!(nodes[0].children[0].value, DecodedValue::I64(42)));
    }

    #[test]
    fn decodes_persistable_bundle_param() {
        let reg = Registry::empty();
        let m = method(vec![in_param(
            "b",
            TypeRef::UserDefined("android.os.PersistableBundle".into()),
        )]);
        let buf = typed_bundle(&[("k", val_i32(1, 7))], true); // native magic
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert_eq!(nodes[0].type_label, "PersistableBundle");
        assert!(matches!(
            nodes[0].value,
            DecodedValue::Bundle {
                len: 1,
                null: false
            }
        ));
    }

    #[test]
    fn bundle_param_resyncs_and_next_param_decodes() {
        // a Bundle param consumes presence(4) + length(4) + magic(4) + arraymap; this guards
        // both the writeTypedObject flag and the length/magic boundary (the historical off-by-4).
        let reg = Registry::empty();
        let m = method(vec![
            in_param("b", TypeRef::UserDefined("android.os.Bundle".into())),
            in_param("after", TypeRef::Primitive(Prim::I32)),
        ]);
        let mut buf = typed_bundle(&[("k", val_i32(1, 5))], false);
        buf.extend_from_slice(&9i32.to_le_bytes());
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(matches!(
            nodes[0].value,
            DecodedValue::Bundle {
                len: 1,
                null: false
            }
        ));
        assert_eq!(nodes[1].name, "after");
        assert!(matches!(nodes[1].value, DecodedValue::I64(9)));
    }

    #[test]
    fn decodes_bundle_nested_in_map() {
        // Map<String, Bundle> via VAL_BUNDLE-tagged value, with a 2nd entry to prove resync.
        let reg = Registry::empty();
        let m = method(vec![in_param(
            "cfg",
            TypeRef::Map(Box::new(TypeRef::String), Box::new(TypeRef::String)),
        )]);
        let mut buf = 2i32.to_le_bytes().to_vec(); // count 2
        buf.extend_from_slice(&val_string("k1"));
        buf.extend_from_slice(&val_bundle(&[("inner", val_i32(1, 1))]));
        buf.extend_from_slice(&val_string("k2"));
        buf.extend_from_slice(&val_string("v2"));
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(matches!(
            nodes[0].value,
            DecodedValue::Map {
                len: 2,
                null: false
            }
        ));
        let e0 = &nodes[0].children[0];
        assert!(matches!(
            e0.children[1].value,
            DecodedValue::Bundle {
                len: 1,
                null: false
            }
        ));
        let e1 = &nodes[0].children[1];
        assert!(matches!(&e1.children[1].value, DecodedValue::Str(Some(s)) if s == "v2"));
    }

    #[test]
    fn decodes_map_string_to_string() {
        let reg = Registry::empty();
        let m = method(vec![in_param(
            "cfg",
            TypeRef::Map(Box::new(TypeRef::String), Box::new(TypeRef::String)),
        )]);
        let mut buf = 1i32.to_le_bytes().to_vec(); // count 1
        buf.extend_from_slice(&val_string("k"));
        buf.extend_from_slice(&val_string("v"));
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(matches!(
            nodes[0].value,
            DecodedValue::Map {
                len: 1,
                null: false
            }
        ));
        let entry = &nodes[0].children[0];
        assert!(matches!(entry.value, DecodedValue::MapEntry));
        assert_eq!(entry.children[0].name, "key");
        assert!(matches!(&entry.children[0].value, DecodedValue::Str(Some(s)) if s == "k"));
        assert_eq!(entry.children[1].name, "value");
        assert!(matches!(&entry.children[1].value, DecodedValue::Str(Some(s)) if s == "v"));
    }

    #[test]
    fn decodes_map_string_to_integer() {
        let reg = Registry::empty();
        let m = method(vec![in_param(
            "cfg",
            TypeRef::Map(
                Box::new(TypeRef::String),
                Box::new(TypeRef::Primitive(Prim::I32)),
            ),
        )]);
        let mut buf = 1i32.to_le_bytes().to_vec(); // count 1
        buf.extend_from_slice(&val_string("k"));
        buf.extend_from_slice(&val_i32(1, 42)); // VAL_INTEGER=1, 42
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        let entry = &nodes[0].children[0];
        assert!(matches!(entry.children[1].value, DecodedValue::I64(42)));
    }

    #[test]
    fn decodes_null_map() {
        let reg = Registry::empty();
        let m = method(vec![in_param(
            "cfg",
            TypeRef::Map(Box::new(TypeRef::String), Box::new(TypeRef::String)),
        )]);
        let buf = (-1i32).to_le_bytes();
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(matches!(
            nodes[0].value,
            DecodedValue::Map { len: 0, null: true }
        ));
    }

    #[test]
    fn map_length_prefixed_value_resyncs_on_bad_body() {
        // VAL_LIST with a body whose count field is negative: decode_value_list
        // returns a null array, resync moves to block end; map is fully consumed.
        let reg = Registry::empty();
        let m = method(vec![in_param(
            "cfg",
            TypeRef::Map(Box::new(TypeRef::String), Box::new(TypeRef::String)),
        )]);
        let mut buf = 1i32.to_le_bytes().to_vec(); // count 1
        buf.extend_from_slice(&val_string("k"));
        // VAL_LIST tag + int32 length(8) + 8 bytes whose first i32 is negative
        buf.extend_from_slice(&11i32.to_le_bytes());
        buf.extend_from_slice(&8i32.to_le_bytes());
        buf.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4]);
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        let entry = &nodes[0].children[0];
        // negative count -> null array; cursor resynced past the block
        assert!(matches!(
            entry.children[1].value,
            DecodedValue::Array { null: true, .. }
        ));
        assert_eq!(nodes.len(), 1); // map fully consumed, no trailing Raw stop
    }

    #[test]
    fn map_value_is_nested_list() {
        let reg = Registry::empty();
        let m = method(vec![in_param(
            "cfg",
            TypeRef::Map(Box::new(TypeRef::String), Box::new(TypeRef::String)),
        )]);
        let mut buf = 1i32.to_le_bytes().to_vec(); // count 1
        buf.extend_from_slice(&val_string("k"));
        // value = VAL_LIST length-prefixed: int32 len, then [count 2, VAL_INTEGER 7, VAL_INTEGER 8]
        let mut list_body = 2i32.to_le_bytes().to_vec();
        list_body.extend_from_slice(&val_i32(1, 7));
        list_body.extend_from_slice(&val_i32(1, 8));
        buf.extend_from_slice(&11i32.to_le_bytes()); // VAL_LIST tag
        buf.extend_from_slice(&(list_body.len() as i32).to_le_bytes()); // length
        buf.extend_from_slice(&list_body);
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        let val = &nodes[0].children[0].children[1];
        assert!(matches!(val.value, DecodedValue::Array { len: 2, .. }));
        assert!(matches!(val.children[1].value, DecodedValue::I64(8)));
    }

    #[test]
    fn map_value_is_parcelable() {
        use crate::model::{Field, Parcelable};
        let mut o = OverlayLayer {
            source_path: "t".into(),
            interfaces: Default::default(),
            enums: Default::default(),
            parcelables: Default::default(),
            unions: Default::default(),
            typedefs: Default::default(),
        };
        o.parcelables.insert(
            "a.P".into(),
            Parcelable {
                fqn: "a.P".into(),
                fields: vec![Field {
                    name: "v".into(),
                    ty: TypeRef::Primitive(Prim::I32),
                }],
            },
        );
        let reg = Registry::from_parts(vec![o], None, std::collections::HashMap::new());
        let m = method(vec![in_param(
            "cfg",
            TypeRef::Map(Box::new(TypeRef::String), Box::new(TypeRef::String)),
        )]);
        let mut buf = 1i32.to_le_bytes().to_vec();
        buf.extend_from_slice(&val_string("k"));
        // value = VAL_PARCELABLE: length-prefixed [ String16 "a.P" (no tag), structured block ]
        // class name is a raw String16 (Parcel.writeString, no tag prefix)
        let mut pbody = string16("a.P");
        // structured parcelable block: int32 size(=8, incl itself) + int32 v(=5)
        pbody.extend_from_slice(&8i32.to_le_bytes());
        pbody.extend_from_slice(&5i32.to_le_bytes());
        buf.extend_from_slice(&4i32.to_le_bytes()); // VAL_PARCELABLE tag
        buf.extend_from_slice(&(pbody.len() as i32).to_le_bytes()); // length
        buf.extend_from_slice(&pbody);
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        let val = &nodes[0].children[0].children[1];
        assert!(matches!(&val.value, DecodedValue::Parcelable { fqn, .. } if fqn == "a.P"));
        assert!(matches!(val.children[0].value, DecodedValue::I64(5)));
    }

    #[test]
    fn map_value_is_nested_map() {
        let reg = Registry::empty();
        let m = method(vec![in_param(
            "cfg",
            TypeRef::Map(Box::new(TypeRef::String), Box::new(TypeRef::String)),
        )]);
        let mut buf = 1i32.to_le_bytes().to_vec();
        buf.extend_from_slice(&val_string("k"));
        // value = VAL_MAP: length-prefixed [ count 1, VAL_STRING "ik", VAL_INTEGER 9 ]
        let mut inner = 1i32.to_le_bytes().to_vec();
        inner.extend_from_slice(&val_string("ik"));
        inner.extend_from_slice(&val_i32(1, 9));
        buf.extend_from_slice(&2i32.to_le_bytes()); // VAL_MAP tag
        buf.extend_from_slice(&(inner.len() as i32).to_le_bytes());
        buf.extend_from_slice(&inner);
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        let val = &nodes[0].children[0].children[1];
        assert!(matches!(val.value, DecodedValue::Map { len: 1, .. }));
    }

    #[test]
    fn deeply_nested_map_does_not_overflow() {
        // 300 nested VAL_MAP values, each ~8 bytes/level; exceeds MAX_DECODE_DEPTH (128).
        // build inner-out so each layer wraps the previous.
        let reg = Registry::empty();
        // innermost value = VAL_INTEGER 0
        let mut inner = 1i32.to_le_bytes().to_vec();
        inner.extend_from_slice(&0i32.to_le_bytes());
        for _ in 0..300 {
            // a map entry: count=1, key=VAL_STRING "k", value=<inner>
            let mut body = 1i32.to_le_bytes().to_vec(); // count
            body.extend_from_slice(&val_string("k")); // key
            body.extend_from_slice(&inner); // value (prev layer)
                                            // wrap as VAL_MAP: tag 2 + int32 len + body
            let mut wrapped = 2i32.to_le_bytes().to_vec();
            wrapped.extend_from_slice(&(body.len() as i32).to_le_bytes());
            wrapped.extend_from_slice(&body);
            inner = wrapped;
        }
        // top-level param is a Map<String,String>; count=1, key=VAL_STRING "top", value=300-deep nest
        let m = method(vec![in_param(
            "cfg",
            TypeRef::Map(Box::new(TypeRef::String), Box::new(TypeRef::String)),
        )]);
        let mut buf = 1i32.to_le_bytes().to_vec(); // top count 1
        buf.extend_from_slice(&val_string("top")); // key
        buf.extend_from_slice(&inner); // value = deep nest
                                       // must not stack-overflow; returns without panic.
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(!nodes.is_empty());
    }

    #[test]
    fn reply_decodes_primitive_return() {
        let reg = Registry::empty();
        let mut m = method(vec![]);
        m.return_type = Some(TypeRef::Primitive(Prim::I32));
        let mut buf = 0i32.to_le_bytes().to_vec(); // status EX_NONE
        buf.extend_from_slice(&42i32.to_le_bytes()); // return = 42
        let nodes = decode_aidl_reply(&reg, 34, &m, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "return");
        assert!(matches!(nodes[0].value, DecodedValue::I64(42)));
    }

    #[test]
    fn reply_decodes_out_param_and_skips_in() {
        let reg = Registry::empty();
        let mut m = method(vec![
            in_param("x", TypeRef::Primitive(Prim::I32)),
            out_param("y", TypeRef::Primitive(Prim::I32)),
        ]);
        m.return_type = None;
        // reply carries only the out param y (in param x is request-only).
        let mut buf = 0i32.to_le_bytes().to_vec(); // status
        buf.extend_from_slice(&7i32.to_le_bytes()); // y = 7
        let nodes = decode_aidl_reply(&reg, 34, &m, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "y");
        assert!(matches!(nodes[0].value, DecodedValue::I64(7)));
    }

    #[test]
    fn reply_void_method_decodes_nothing() {
        let reg = Registry::empty();
        let mut m = method(vec![]);
        m.return_type = Some(TypeRef::UserDefined("void".into())); // void parses to this
        let buf = 0i32.to_le_bytes(); // status only
        let nodes = decode_aidl_reply(&reg, 34, &m, &buf, 0, &[]);
        assert!(nodes.is_empty());
    }

    #[test]
    fn reply_decodes_security_exception() {
        let reg = Registry::empty();
        let m = method(vec![]);
        let mut buf = (-1i32).to_le_bytes().to_vec(); // EX_SECURITY
        buf.extend_from_slice(&string16("denied"));
        buf.extend_from_slice(&0i32.to_le_bytes()); // remote stack-trace header size 0
        let nodes = decode_aidl_reply(&reg, 34, &m, &buf, 0, &[]);
        assert!(matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s == "EX_SECURITY"));
        assert_eq!(nodes[0].name, "exception");
        assert!(nodes.iter().any(|n| n.name == "exception.message"
            && matches!(&n.value, DecodedValue::Str(Some(s)) if s == "denied")));
    }

    #[test]
    fn reply_decodes_service_specific_exception() {
        let reg = Registry::empty();
        let m = method(vec![]);
        let mut buf = (-8i32).to_le_bytes().to_vec(); // EX_SERVICE_SPECIFIC
        buf.extend_from_slice(&string16("oops"));
        buf.extend_from_slice(&0i32.to_le_bytes()); // stack-trace header size 0
        buf.extend_from_slice(&42i32.to_le_bytes()); // service-specific code
        let nodes = decode_aidl_reply(&reg, 34, &m, &buf, 0, &[]);
        assert!(nodes
            .iter()
            .any(|n| n.name == "exception.serviceSpecific"
                && matches!(n.value, DecodedValue::I64(42))));
    }

    #[test]
    fn reply_skips_strictmode_reply_header() {
        let reg = Registry::empty();
        let mut m = method(vec![]);
        m.return_type = Some(TypeRef::Primitive(Prim::I32));
        // [-128][size=8][4 content bytes][status implied EX_NONE by -128][return=99]
        let mut buf = (-128i32).to_le_bytes().to_vec();
        buf.extend_from_slice(&8i32.to_le_bytes()); // header size (covers size int + 4 content)
        buf.extend_from_slice(&[1, 2, 3, 4]); // header content
        buf.extend_from_slice(&99i32.to_le_bytes()); // return value
        let nodes = decode_aidl_reply(&reg, 34, &m, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "return");
        assert!(matches!(nodes[0].value, DecodedValue::I64(99)));
    }

    #[test]
    fn reply_skips_appops_reply_header() {
        let reg = Registry::empty();
        let mut m = method(vec![]);
        m.return_type = Some(TypeRef::Primitive(Prim::I32));
        // [-127][size=8][4 content][status=0][return=5]
        let mut buf = (-127i32).to_le_bytes().to_vec();
        buf.extend_from_slice(&8i32.to_le_bytes());
        buf.extend_from_slice(&[0, 0, 0, 0]);
        buf.extend_from_slice(&0i32.to_le_bytes()); // re-read status = EX_NONE
        buf.extend_from_slice(&5i32.to_le_bytes()); // return
        let nodes = decode_aidl_reply(&reg, 34, &m, &buf, 0, &[]);
        assert_eq!(nodes[0].name, "return");
        assert!(matches!(nodes[0].value, DecodedValue::I64(5)));
    }

    #[test]
    fn reads_binder_handle_object() {
        // flat_binder_object: type=HANDLE, flags=0, handle=0x1f, cookie=0; offset entry [0].
        let mut data = binder_object::HANDLE.to_le_bytes().to_vec();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0x1fu64.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        let offsets = 0u64.to_le_bytes();
        let mut cur = ParcelCursor::new(&data, 0).with_offsets(&offsets);
        assert_eq!(cur.read_binder_object(), Some((0x1f, false)));
        assert_eq!(cur.pos, 24);
    }

    #[test]
    fn reads_local_binder_object_is_strong() {
        let mut data = binder_object::BINDER.to_le_bytes().to_vec();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0xdead_0000u64.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        let offsets = 0u64.to_le_bytes();
        let mut cur = ParcelCursor::new(&data, 0).with_offsets(&offsets);
        assert_eq!(cur.read_binder_object(), Some((0xdead_0000, true)));
    }

    #[test]
    fn read_binder_object_none_without_offsets() {
        let data = binder_object::HANDLE.to_le_bytes();
        let mut cur = ParcelCursor::new(&data, 0); // empty offsets
        assert_eq!(cur.read_binder_object(), None);
    }

    #[test]
    fn decodes_param_after_ibinder() {
        let reg = Registry::empty();
        let m = method(vec![
            in_param("display", TypeRef::IBinder),
            in_param("mode", TypeRef::Primitive(Prim::I32)),
        ]);
        // flat_binder_object (HANDLE, handle=2) then int32 mode=1; binder object at data offset 0.
        let mut buf = binder_object::HANDLE.to_le_bytes().to_vec();
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&2u64.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&1i32.to_le_bytes());
        let offsets = 0u64.to_le_bytes();
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &offsets);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "display");
        assert!(matches!(
            nodes[0].value,
            DecodedValue::Binder {
                handle: 2,
                strong: false
            }
        ));
        assert_eq!(nodes[1].name, "mode");
        assert!(matches!(nodes[1].value, DecodedValue::I64(1)));
    }

    #[test]
    fn ibinder_without_offsets_halts() {
        let reg = Registry::empty();
        let m = method(vec![
            in_param("display", TypeRef::IBinder),
            in_param("mode", TypeRef::Primitive(Prim::I32)),
        ]);
        let mut buf = vec![0u8; 24];
        buf.extend_from_slice(&1i32.to_le_bytes());
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]); // no offsets -> halt
        assert!(matches!(nodes[0].value, DecodedValue::RawTail { .. }));
    }

    // build a registry with a single interface fqn
    fn reg_with_interface(fqn: &str) -> Registry {
        use crate::model::OverlayLayer;
        let mut o = OverlayLayer {
            source_path: "t".into(),
            interfaces: Default::default(),
            enums: Default::default(),
            parcelables: Default::default(),
            unions: Default::default(),
            typedefs: Default::default(),
        };
        o.interfaces.insert(
            fqn.into(),
            crate::model::Interface {
                fqn: fqn.into(),
                flavor: crate::model::Flavor::Aidl,
                base_code: 1,
                methods: vec![],
                extends: None,
                imports: vec![],
            },
        );
        Registry::from_parts(vec![o], None, std::collections::HashMap::new())
    }

    #[test]
    fn interface_typed_param_decodes_as_ibinder() {
        // a method with `in android.view.IWindow window, in int x` where IWindow is a known
        // interface. the window param must decode as a Binder node and the following x also.
        let reg = reg_with_interface("android.view.IWindow");
        let m = method(vec![
            in_param(
                "window",
                TypeRef::UserDefined("android.view.IWindow".into()),
            ),
            in_param("x", TypeRef::Primitive(Prim::I32)),
        ]);
        // flat_binder_object (HANDLE, handle=7) at offset 0, then i32=42
        let mut buf = binder_object::HANDLE.to_le_bytes().to_vec();
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.extend_from_slice(&7u64.to_le_bytes()); // handle
        buf.extend_from_slice(&0u64.to_le_bytes()); // cookie
        buf.extend_from_slice(&42i32.to_le_bytes()); // x
        let offsets = 0u64.to_le_bytes();
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &offsets);
        assert_eq!(nodes.len(), 2, "expected two nodes, got {:?}", nodes);
        assert_eq!(nodes[0].name, "window");
        assert!(
            matches!(
                nodes[0].value,
                DecodedValue::Binder {
                    handle: 7,
                    strong: false
                }
            ),
            "expected Binder{{handle:7,strong:false}}, got {:?}",
            nodes[0].value
        );
        assert_eq!(nodes[1].name, "x");
        assert!(matches!(nodes[1].value, DecodedValue::I64(42)));
    }

    #[test]
    fn unknown_user_defined_type_still_halts_walk() {
        // a UserDefined fqn that is not an interface, enum, parcelable, or union → RawTail
        let reg = Registry::empty();
        let m = method(vec![
            in_param("obj", TypeRef::UserDefined("a.b.Mystery".into())),
            in_param("x", TypeRef::Primitive(Prim::I32)),
        ]);
        let mut buf = 1i32.to_le_bytes().to_vec();
        buf.extend_from_slice(&2i32.to_le_bytes());
        let nodes = decode_aidl_params(&reg, 34, &m, &buf, 0, &[]);
        assert!(
            matches!(&nodes[0].value, DecodedValue::RawTail { reason } if reason.contains("undecodable")),
            "got {:?}",
            nodes[0].value
        );
    }

    #[test]
    fn native_reply_decodes_out_params_no_status_header() {
        let reg = Registry::empty();
        // getCurrentPosition-style native reply: [int32 msec][int32 status], NO header.
        let mut m = method(vec![
            out_param("msec", TypeRef::Primitive(Prim::I32)),
            out_param("status", TypeRef::Primitive(Prim::I32)),
        ]);
        m.return_type = None;
        let mut buf = 42i32.to_le_bytes().to_vec();
        buf.extend_from_slice(&0i32.to_le_bytes());
        let nodes = decode_native_reply(&reg, 34, &m, &buf, 0, &[]);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "msec");
        assert!(matches!(nodes[0].value, DecodedValue::I64(42)));
        assert_eq!(nodes[1].name, "status");
        assert!(matches!(nodes[1].value, DecodedValue::I64(0)));
    }

    #[test]
    fn native_reply_skips_in_params() {
        let reg = Registry::empty();
        // a mixed method: `in` request fields are NOT in the reply; only `out` decode.
        let mut m = method(vec![
            in_param("left", TypeRef::Primitive(Prim::F32)),
            in_param("right", TypeRef::Primitive(Prim::F32)),
            out_param("status", TypeRef::Primitive(Prim::I32)),
        ]);
        m.return_type = None;
        let buf = 0i32.to_le_bytes().to_vec(); // reply = just the status
        let nodes = decode_native_reply(&reg, 34, &m, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "status");
        assert!(matches!(nodes[0].value, DecodedValue::I64(0)));
    }

    #[test]
    fn native_reply_string_out() {
        let reg = Registry::empty();
        let mut m = method(vec![out_param("driverPath", TypeRef::String)]);
        m.return_type = None;
        let buf = string16("/vendor/lib/egl"); // reply = bare String16, no header
        let nodes = decode_native_reply(&reg, 34, &m, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "driverPath");
        assert!(matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s == "/vendor/lib/egl"));
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
        let nodes = decode_aidl_params(&reg, sdk, &method, &buf, 0, &[]);
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

    #[test]
    fn native_struct_unknown_type_is_none() {
        let reg = Registry::empty();
        let mut cur = ParcelCursor::new(&[0u8; 4], 0);
        assert!(crate::native_struct::decode(&reg, 35, &mut cur, "a.b.NotAStruct", 0, 0).is_none());
    }

    // INTERFACE_TRANSACTION replies carry a bare String16 at offset 0 with no status header.
    // verify that read_string16 recovers the descriptor from the observed wire pattern.
    #[test]
    fn read_string16_interface_descriptor() {
        // "android.frameworks.stats.IStats" in UTF-16 LE: count=31, then 31+1=32 char16_t (64
        // bytes, pad_to_4 is already 0 mod 4), as seen in frame 100 of out.pcapng.
        let descriptor = "android.frameworks.stats.IStats";
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&(descriptor.len() as i32).to_le_bytes()); // count
        for ch in descriptor.encode_utf16() {
            buf.extend_from_slice(&ch.to_le_bytes());
        }
        // NUL terminator (u16)
        buf.extend_from_slice(&0u16.to_le_bytes());
        // padded to 4 bytes: (31+1)*2 = 64, already a multiple of 4 — no extra padding needed.
        let mut cur = ParcelCursor::new(&buf, 0);
        let result = cur.read_string16();
        assert_eq!(result, Some(Some(descriptor.to_string())));
        assert_eq!(cur.pos, buf.len()); // cursor consumed the whole buffer
    }
}
