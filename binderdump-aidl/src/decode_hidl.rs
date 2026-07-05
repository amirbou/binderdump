// HIDL wire decoder for a method's in-params. Primitive and enum args are
// inline at natural alignment (each type read at its own width, little-endian).
// Aggregate args (hidl_string, hidl_vec) are 40-byte binder_buffer_objects
// in the data stream; their content lives in child payloads from the scatter-gather tree.

use crate::binder_object;
use crate::decode::{depth_exceeded, node, raw_tail, DecodedNode, DecodedValue};
use crate::model::{Direction, Method};
use crate::model::{Field, Prim, TypeRef};
use crate::registry::Registry;

// cursor over a HIDL data buffer. returns None on overrun.
//
// two modes:
//   parcel_mode=false (default, struct fields): each read aligns the cursor to
//     the type's natural width before consuming — matches C struct layout inside
//     a flat binder_buffer_object payload.
//   parcel_mode=true (top-level Parcel args): no position re-alignment for
//     8-byte types; libhwbinder Parcel::write pads the written size to 4 bytes
//     but never realigns the write position (pad_size(8)=8 so u64/i64 still
//     advance by 8, but no gap is inserted before them).
struct HidlCursor<'a> {
    data: &'a [u8],
    pos: usize,
    parcel_mode: bool,
}

impl<'a> HidlCursor<'a> {
    fn new(data: &'a [u8], start: usize) -> Self {
        Self {
            data,
            pos: start,
            parcel_mode: false,
        }
    }

    // use for reading top-level Parcel args (hwbinder Parcel, not struct payload).
    fn new_parcel(data: &'a [u8], start: usize) -> Self {
        Self {
            data,
            pos: start,
            parcel_mode: true,
        }
    }

    // align pos up to the next multiple of `align` (must be a power of two).
    fn align_to(&mut self, align: usize) {
        self.pos = (self.pos + align - 1) & !(align - 1);
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let sl = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(sl)
    }

    fn read_u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Option<u16> {
        self.align_to(2);
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }

    fn read_u32(&mut self) -> Option<u32> {
        self.align_to(4);
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn read_i32(&mut self) -> Option<i32> {
        self.align_to(4);
        Some(i32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn read_u64(&mut self) -> Option<u64> {
        // in parcel mode: no 8-byte realignment; hwbinder Parcel::write advances
        // by pad_size(8)=8 but doesn't insert a gap before the write.
        if !self.parcel_mode {
            self.align_to(8);
        }
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn read_i64(&mut self) -> Option<i64> {
        if !self.parcel_mode {
            self.align_to(8);
        }
        Some(i64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn read_f32(&mut self) -> Option<f32> {
        self.align_to(4);
        Some(f32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn read_f64(&mut self) -> Option<f64> {
        if !self.parcel_mode {
            self.align_to(8);
        }
        Some(f64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
}

// read a primitive at HIDL natural alignment; returns (value, type_label) or None on overrun.
fn read_hidl_prim(cur: &mut HidlCursor, prim: Prim) -> Option<(DecodedValue, &'static str)> {
    let pair = match prim {
        Prim::Bool => (DecodedValue::Bool(cur.read_u8()? != 0), "bool"),
        Prim::I8 => (DecodedValue::I64(cur.read_u8()? as i8 as i64), "int8_t"),
        Prim::U8 => (DecodedValue::U64(cur.read_u8()? as u64), "uint8_t"),
        Prim::Char => (DecodedValue::U64(cur.read_u16()? as u64), "char16_t"),
        Prim::I16 => (DecodedValue::I64(cur.read_u16()? as i16 as i64), "int16_t"),
        Prim::U16 => (DecodedValue::U64(cur.read_u16()? as u64), "uint16_t"),
        Prim::I32 => (DecodedValue::I64(cur.read_i32()? as i64), "int32_t"),
        Prim::U32 => (DecodedValue::U64(cur.read_u32()? as u64), "uint32_t"),
        Prim::I64 => (DecodedValue::I64(cur.read_i64()?), "int64_t"),
        Prim::U64 => (DecodedValue::U64(cur.read_u64()?), "uint64_t"),
        Prim::F32 => (DecodedValue::F64(cur.read_f32()? as f64), "float"),
        Prim::F64 => (DecodedValue::F64(cur.read_f64()?), "double"),
    };
    Some(pair)
}

// read an enum's backing primitive as i64, at natural alignment.
fn read_hidl_backing(cur: &mut HidlCursor, backing: Prim) -> Option<i64> {
    match backing {
        Prim::Bool | Prim::I8 => Some(cur.read_u8()? as i8 as i64),
        Prim::U8 => Some(cur.read_u8()? as i64),
        Prim::I16 => Some(cur.read_u16()? as i16 as i64),
        Prim::Char | Prim::U16 => Some(cur.read_u16()? as i64),
        Prim::I32 => Some(cur.read_i32()? as i64),
        Prim::U32 => Some(cur.read_u32()? as i64),
        Prim::I64 | Prim::U64 => cur.read_i64(),
        Prim::F32 | Prim::F64 => None, // enums are never float-backed
    }
}

// --- scatter-gather helpers ---

// index (0-based in the offsets array) of the buffer_object at byte offset `pos` in data
fn find_obj_index(offsets: &[u8], pos: usize) -> Option<usize> {
    binder_object::offset_entries(offsets).position(|off| off == pos)
}

// payload bytes for the buffer_object at index `idx` in ptr_payloads
fn get_payload<'a>(ptr_payloads: &'a [(u32, Vec<u8>)], idx: usize) -> Option<&'a [u8]> {
    ptr_payloads
        .iter()
        .find(|(oi, _)| *oi as usize == idx)
        .map(|(_, b)| b.as_slice())
}

// index of a child buffer_object that has HAS_PARENT, parent == parent_idx,
// and parent_offset == parent_off. scans the full offsets/data.
fn find_child_obj(
    data: &[u8],
    offsets: &[u8],
    parent_idx: usize,
    parent_off: u64,
) -> Option<usize> {
    binder_object::offset_entries(offsets)
        .enumerate()
        .find_map(|(idx, off)| {
            let obj = binder_object::read_buffer_object(data, off)?;
            if obj.flags & binder_object::HAS_PARENT != 0
                && obj.parent as usize == parent_idx
                && obj.parent_offset == parent_off
            {
                Some(idx)
            } else {
                None
            }
        })
}

// advance cur past the buffer_object at offsets index k and all objects in the offsets
// array that are transitively descended from it (parent chain closure). for an empty vec
// (size=0, no descendants), this advances exactly +40 to the next object.
fn advance_past_descendants(cur: &mut HidlCursor, data: &[u8], offsets: &[u8], k: usize) {
    let obj_positions: Vec<usize> = binder_object::offset_entries(offsets).collect();
    let n = obj_positions.len();
    if k >= n {
        return;
    }

    // transitive closure: seed with k, expand by finding any j where obj_j.parent is in set
    let mut in_set = vec![false; n];
    in_set[k] = true;
    loop {
        let mut changed = false;
        for j in 0..n {
            if in_set[j] {
                continue;
            }
            let Some(obj) = binder_object::read_buffer_object(data, obj_positions[j]) else {
                continue;
            };
            if obj.flags & binder_object::HAS_PARENT != 0 {
                let p = obj.parent as usize;
                if p < n && in_set[p] {
                    in_set[j] = true;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }

    // max end position across all objects in the set
    let mut max_end = obj_positions[k].saturating_add(40);
    for j in 0..n {
        if in_set[j] {
            let end = obj_positions[j].saturating_add(40);
            if end > max_end {
                max_end = end;
            }
        }
    }

    // HIDL sometimes places unlisted placeholder bbos in the inline data (e.g. an
    // empty-vec elements buffer with HAS_PARENT that the kernel omits from the offsets
    // array). These occupy physical bytes but are absent from the offsets array, so
    // max_end may land between two listed offsets. Advance to the next listed offset
    // >= max_end so the next find_obj_index call succeeds.
    if !obj_positions.iter().any(|&p| p == max_end) {
        if let Some(&next) = obj_positions.iter().filter(|&&p| p >= max_end).min() {
            max_end = next;
        }
    }

    cur.pos = max_end;
}

// bytes of a NUL-terminated C string from `chars` — prefix before the first NUL,
// or the whole slice when no NUL is present.
fn str_from_nul(chars: &[u8]) -> &[u8] {
    match chars.iter().position(|&b| b == 0) {
        Some(nul) => &chars[..nul],
        None => chars,
    }
}

// --- native_handle decoder ---

// decode native_handle_t from its buffer payload.
// native_handle_t layout: { int version(4), int numFds(4), int numInts(4),
//                           int data[numFds + numInts] }
// the fd slots (data[0..numFds]) hold placeholder ints; the real fds are FDA objects.
// children: numFds, numInts, ints (the numInts values that follow the fd slots).
fn decode_hidl_handle(payload: &[u8], depth: u32) -> Option<DecodedNode> {
    if depth_exceeded(depth) {
        return None;
    }
    if payload.len() < 12 {
        return None;
    }
    let num_fds = u32::from_le_bytes(payload[4..8].try_into().ok()?);
    let num_ints = u32::from_le_bytes(payload[8..12].try_into().ok()?);

    // payload must contain the header + numFds fd slots + numInts int slots
    let total = 12usize
        .checked_add((num_fds as usize).checked_mul(4)?)?
        .checked_add((num_ints as usize).checked_mul(4)?)?;
    if payload.len() < total {
        return None;
    }

    let mut children = Vec::new();
    {
        let mut n = node(DecodedValue::U64(num_fds as u64), "uint32_t", 4, 4, vec![]);
        n.name = "numFds".to_string();
        children.push(n);
    }
    {
        let mut n = node(DecodedValue::U64(num_ints as u64), "uint32_t", 8, 4, vec![]);
        n.name = "numInts".to_string();
        children.push(n);
    }
    if num_ints > 0 {
        // fd slots precede the int slots; ints start at 12 + numFds*4
        let ints_base = 12 + num_fds as usize * 4;
        let mut int_elems = Vec::with_capacity(num_ints as usize);
        for i in 0..num_ints as usize {
            let off = ints_base + i * 4;
            let v = u32::from_le_bytes(payload[off..off + 4].try_into().ok()?);
            int_elems.push(node(DecodedValue::U64(v as u64), "int32_t", off, 4, vec![]));
        }
        let mut ints_node = node(
            DecodedValue::Array {
                len: num_ints as usize,
                null: false,
            },
            "ints",
            ints_base,
            num_ints as usize * 4,
            int_elems,
        );
        ints_node.name = "ints".to_string();
        children.push(ints_node);
    }

    Some(node(
        DecodedValue::Parcelable {
            fqn: "native_handle".to_string(),
            null: false,
        },
        "native_handle",
        0,
        payload.len(),
        children,
    ))
}

// decode a top-level handle arg. consumes the 40-byte buffer_object from cur,
// then reads native_handle_t from the payload.
fn decode_hidl_handle_bbo(
    cur: &mut HidlCursor,
    data: &[u8],
    offsets: &[u8],
    ptr_payloads: &[(u32, Vec<u8>)],
    depth: u32,
) -> Option<(DecodedNode, usize)> {
    if depth_exceeded(depth) {
        return None;
    }
    let start = cur.pos;
    let tag = u32::from_le_bytes(data.get(start..start + 4)?.try_into().ok()?);
    if tag != binder_object::PTR {
        return None;
    }
    let obj_idx = find_obj_index(offsets, start)?;
    cur.take(40)?;
    let payload = get_payload(ptr_payloads, obj_idx)?;
    let nh_node = decode_hidl_handle(payload, depth + 1)?;
    Some((nh_node, obj_idx))
}

// --- struct layout helpers ---

// (size_bytes, alignment) for a HIDL type embedded inline in a struct or fixed array.
// returns None for types whose wire size isn't known (hidl_vec, IBinder, etc.).
fn hidl_type_size_align(ty: &TypeRef, reg: &Registry, sdk: u32) -> Option<(usize, usize)> {
    match ty {
        TypeRef::Primitive(p) => Some(match p {
            Prim::Bool | Prim::I8 | Prim::U8 => (1, 1),
            Prim::Char | Prim::I16 | Prim::U16 => (2, 2),
            Prim::I32 | Prim::U32 | Prim::F32 => (4, 4),
            Prim::I64 | Prim::U64 | Prim::F64 => (8, 8),
        }),
        // hidl_string: ptr[8] + size[4] + owns[4] = 16 bytes, align 8
        TypeRef::String => Some((16, 8)),
        TypeRef::UserDefined(fqn) => {
            if let Some(e) = reg.enum_def(sdk, fqn) {
                hidl_type_size_align(&TypeRef::Primitive(e.backing), reg, sdk)
            } else if let Some(p) = reg.parcelable_def(sdk, fqn) {
                let fields = p.fields.clone();
                hidl_struct_size_align(&fields, reg, sdk)
            } else if let Some(resolved) = reg.typedef_def(sdk, fqn) {
                hidl_type_size_align(&resolved, reg, sdk)
            } else {
                None
            }
        }
        TypeRef::FixedArray(inner, n) => {
            let (elem_size, elem_align) = hidl_type_size_align(inner, reg, sdk)?;
            Some((elem_size.checked_mul(*n)?, elem_align))
        }
        // hidl_vec / IBinder / handle / memory / nullable: variable or complex wire form
        _ => None,
    }
}

// total (size, max_alignment) of a HIDL struct given its field list.
// accounts for natural-alignment padding between fields and end-padding.
fn hidl_struct_size_align(fields: &[Field], reg: &Registry, sdk: u32) -> Option<(usize, usize)> {
    let mut pos: usize = 0;
    let mut max_align: usize = 1;
    for field in fields {
        let (size, align) = hidl_type_size_align(&field.ty, reg, sdk)?;
        max_align = max_align.max(align);
        pos = (pos + align - 1) & !(align - 1); // pad to field alignment
        pos = pos.checked_add(size)?;
    }
    // end-pad so the struct is a multiple of its max-field alignment
    pos = (pos + max_align - 1) & !(max_align - 1);
    Some((pos, max_align))
}

// --- struct field decoder ---

// decode the fields of a HIDL struct from `struct_bytes`.
// containing_obj_idx: index of the buffer_object whose payload contains struct_bytes.
// struct_base_offset: byte offset of struct_bytes[0] within that payload.
// this is used to locate embedded hidl_string / hidl_vec children in the sg tree.
fn decode_hidl_struct_fields(
    reg: &Registry,
    sdk: u32,
    data: &[u8],
    offsets: &[u8],
    ptr_payloads: &[(u32, Vec<u8>)],
    struct_bytes: &[u8],
    containing_obj_idx: usize,
    struct_base_offset: u64,
    fields: &[Field],
    depth: u32,
) -> Option<Vec<DecodedNode>> {
    if depth_exceeded(depth) {
        return None;
    }
    let mut cur = HidlCursor::new(struct_bytes, 0);
    let mut children = Vec::new();
    for field in fields {
        let before = cur.pos;
        match &field.ty {
            TypeRef::Primitive(p) => {
                let (val, label) = read_hidl_prim(&mut cur, *p)?;
                let mut n = node(val, label, before, cur.pos - before, vec![]);
                n.name = field.name.clone();
                children.push(n);
            }
            TypeRef::String => {
                // hidl_string embedded in a struct: 16 bytes, align 8.
                // the chars child has parent == containing_obj_idx,
                // parent_offset == struct_base_offset + field_off.
                cur.align_to(8);
                let field_off = cur.pos;
                let chunk = struct_bytes.get(field_off..field_off + 12)?;
                let size = u32::from_le_bytes(chunk[8..12].try_into().ok()?) as usize;
                cur.take(16)?; // advance past the hidl_string struct
                let parent_off = struct_base_offset + field_off as u64;
                let val = if size == 0 {
                    DecodedValue::Str(Some(String::new()))
                } else {
                    let chars_idx = find_child_obj(data, offsets, containing_obj_idx, parent_off)?;
                    let chars = get_payload(ptr_payloads, chars_idx)?;
                    // use NUL terminator instead of mSize — embedded hidl_string structs
                    // inside a vec's elements buffer have corrupted mSize after the kernel's
                    // scatter-gather address translation; the char buffer itself is intact.
                    let s = String::from_utf8_lossy(str_from_nul(chars)).into_owned();
                    DecodedValue::Str(Some(s))
                };
                let mut n = node(val, "hidl_string", field_off, 16, vec![]);
                n.name = field.name.clone();
                children.push(n);
            }
            TypeRef::UserDefined(fqn) => {
                // resolve typedef chain first; enum/parcelable checks follow
                let typedef_resolved = reg.typedef_def(sdk, fqn);
                let effective_ty = typedef_resolved.as_ref().unwrap_or(&field.ty);
                let resolved_fqn = match effective_ty {
                    TypeRef::UserDefined(f) => f.as_str(),
                    TypeRef::Primitive(p) => {
                        // typedef to a primitive: read it inline and continue
                        let (val, label) = read_hidl_prim(&mut cur, *p)?;
                        let mut n = node(val, label, before, cur.pos - before, vec![]);
                        n.name = field.name.clone();
                        children.push(n);
                        continue;
                    }
                    _ => return None,
                };
                if let Some(e) = reg.enum_def(sdk, resolved_fqn) {
                    let backing = e.backing;
                    let efqn = e.fqn.clone();
                    let variants: Vec<(i64, String)> =
                        e.consts.iter().map(|(n, v)| (*v, n.clone())).collect();
                    let repr = read_hidl_backing(&mut cur, backing)?;
                    let mut n = node(
                        DecodedValue::Enum { repr, variants },
                        &efqn,
                        before,
                        cur.pos - before,
                        vec![],
                    );
                    n.name = field.name.clone();
                    children.push(n);
                } else if let Some(p) = reg.parcelable_def(sdk, resolved_fqn) {
                    // nested struct: align, slice, recurse
                    let nested_fields = p.fields.clone();
                    let pfqn = p.fqn.clone();
                    let (struct_size, struct_align) =
                        hidl_struct_size_align(&nested_fields, reg, sdk)?;
                    cur.align_to(struct_align);
                    let struct_off = cur.pos;
                    let nested_bytes = struct_bytes.get(struct_off..struct_off + struct_size)?;
                    let nested_base = struct_base_offset + struct_off as u64;
                    let nested_children = decode_hidl_struct_fields(
                        reg,
                        sdk,
                        data,
                        offsets,
                        ptr_payloads,
                        nested_bytes,
                        containing_obj_idx,
                        nested_base,
                        &nested_fields,
                        depth + 1,
                    )?;
                    cur.pos += struct_size;
                    let mut n = node(
                        DecodedValue::Parcelable {
                            fqn: pfqn.clone(),
                            null: false,
                        },
                        &pfqn,
                        struct_off,
                        struct_size,
                        nested_children,
                    );
                    n.name = field.name.clone();
                    children.push(n);
                } else {
                    return None; // unknown fqn inside struct
                }
            }
            _ => return None, // unsupported field type inside struct
        }
    }
    Some(children)
}

// --- aggregate decoders ---

// decode a top-level hidl_string arg. consumes the 40-byte buffer_object from cur,
// reads size from the 16-byte child payload (ptr[8]+size[4]+owns[4]), then fetches
// the chars from the grandchild whose parent_offset == 0.
fn decode_hidl_string(
    cur: &mut HidlCursor,
    data: &[u8],
    offsets: &[u8],
    ptr_payloads: &[(u32, Vec<u8>)],
) -> Option<(DecodedValue, usize)> {
    let pos = cur.pos;
    let obj_idx = find_obj_index(offsets, pos)?;
    // require PTR type tag — other object types are not buffer pointers
    let tag = u32::from_le_bytes(data.get(pos..pos + 4)?.try_into().ok()?);
    if tag != binder_object::PTR {
        return None;
    }
    cur.take(40)?; // advance past the buffer_object
    let payload = get_payload(ptr_payloads, obj_idx)?;
    if payload.len() < 12 {
        return None;
    }
    let size = u32::from_le_bytes(payload[8..12].try_into().ok()?) as usize;
    if size == 0 {
        return Some((DecodedValue::Str(Some(String::new())), obj_idx));
    }
    // chars child: parent == obj_idx, parent_offset == 0 (the ptr field in hidl_string)
    let chars_idx = find_child_obj(data, offsets, obj_idx, 0)?;
    let chars = get_payload(ptr_payloads, chars_idx)?;
    // use NUL terminator instead of mSize for the same resilience as the struct-embedded path
    let s = String::from_utf8_lossy(str_from_nul(chars)).into_owned();
    Some((DecodedValue::Str(Some(s)), obj_idx))
}

// decode a top-level HIDL struct arg. consumes the 40-byte buffer_object from cur,
// then decodes the struct fields from the payload.
fn decode_hidl_struct(
    cur: &mut HidlCursor,
    data: &[u8],
    offsets: &[u8],
    ptr_payloads: &[(u32, Vec<u8>)],
    reg: &Registry,
    sdk: u32,
    fqn: &str,
    depth: u32,
) -> Option<(DecodedNode, usize)> {
    if depth_exceeded(depth) {
        return None;
    }
    let start = cur.pos;
    let tag = u32::from_le_bytes(data.get(start..start + 4)?.try_into().ok()?);
    if tag != binder_object::PTR {
        return None;
    }
    let obj_idx = find_obj_index(offsets, start)?;
    cur.take(40)?;
    let struct_bytes = get_payload(ptr_payloads, obj_idx)?;
    let p = reg.parcelable_def(sdk, fqn)?;
    let pfqn = p.fqn.clone();
    let fields = p.fields.clone();
    let children = decode_hidl_struct_fields(
        reg,
        sdk,
        data,
        offsets,
        ptr_payloads,
        struct_bytes,
        obj_idx,
        0, // struct starts at offset 0 within its own payload
        &fields,
        depth + 1,
    )?;
    Some((
        node(
            DecodedValue::Parcelable {
                fqn: pfqn,
                null: false,
            },
            fqn,
            start,
            cur.pos - start,
            children,
        ),
        obj_idx,
    ))
}

// decode `count` elements of type `inner` from the flat elements buffer `elems`.
// for string elements, char children are found by parent == elems_obj_idx and
// parent_offset == byte offset of the hidl_string struct within elems.
// for struct elements, children are found relative to each element's base offset.
fn decode_hidl_vec_elems(
    reg: &Registry,
    sdk: u32,
    data: &[u8],
    offsets: &[u8],
    ptr_payloads: &[(u32, Vec<u8>)],
    elems: &[u8],
    elems_obj_idx: usize,
    count: usize,
    inner: &TypeRef,
    depth: u32,
) -> Option<Vec<DecodedNode>> {
    if depth_exceeded(depth) {
        return None;
    }
    // each element is at least 1 byte; a count larger than the buffer is impossible
    if count > elems.len() {
        return None;
    }
    let mut children = Vec::with_capacity(count.min(1024));
    match inner {
        TypeRef::Primitive(p) => {
            let mut ec = HidlCursor::new(elems, 0);
            for _ in 0..count {
                let elem_start = ec.pos;
                let (val, label) = read_hidl_prim(&mut ec, *p)?;
                children.push(node(val, label, elem_start, ec.pos - elem_start, vec![]));
            }
        }
        TypeRef::String => {
            // each element is a 16-byte hidl_string at byte offset i*16 in elems.
            // chars child: parent == elems_obj_idx, parent_offset == i*16.
            for i in 0..count {
                let elem_off = i * 16;
                let chunk = elems.get(elem_off..elem_off + 12)?;
                let size = u32::from_le_bytes(chunk[8..12].try_into().ok()?) as usize;
                let val = if size == 0 {
                    DecodedValue::Str(Some(String::new()))
                } else {
                    let chars_idx = find_child_obj(data, offsets, elems_obj_idx, elem_off as u64)?;
                    let chars = get_payload(ptr_payloads, chars_idx)?;
                    // use NUL terminator instead of mSize — mSize in embedded hidl_string
                    // structs is corrupted by the kernel's scatter-gather address translation;
                    // the char buffer is intact and NUL-terminated.
                    let s = String::from_utf8_lossy(str_from_nul(chars)).into_owned();
                    DecodedValue::Str(Some(s))
                };
                children.push(node(val, "hidl_string", elem_off, 16, vec![]));
            }
        }
        TypeRef::UserDefined(fqn) => {
            // resolve typedef chain; if resolved to a non-UserDefined type, recurse
            let typedef_resolved = reg.typedef_def(sdk, fqn);
            let effective_inner = typedef_resolved.as_ref().unwrap_or(inner);
            let resolved_fqn = match effective_inner {
                TypeRef::UserDefined(f) => f.as_str(),
                // typedef to a primitive: decode count elements inline
                TypeRef::Primitive(_) | TypeRef::String => {
                    return decode_hidl_vec_elems(
                        reg,
                        sdk,
                        data,
                        offsets,
                        ptr_payloads,
                        elems,
                        elems_obj_idx,
                        count,
                        effective_inner,
                        depth + 1,
                    );
                }
                _ => return None,
            };
            if let Some(e) = reg.enum_def(sdk, resolved_fqn) {
                // array of enums: each element is the backing type inline
                let backing = e.backing;
                let efqn = e.fqn.clone();
                let variants: Vec<(i64, String)> =
                    e.consts.iter().map(|(n, v)| (*v, n.clone())).collect();
                let mut ec = HidlCursor::new(elems, 0);
                for _ in 0..count {
                    let elem_start = ec.pos;
                    let repr = read_hidl_backing(&mut ec, backing)?;
                    children.push(node(
                        DecodedValue::Enum {
                            repr,
                            variants: variants.clone(),
                        },
                        &efqn,
                        elem_start,
                        ec.pos - elem_start,
                        vec![],
                    ));
                }
            } else if let Some(p) = reg.parcelable_def(sdk, resolved_fqn) {
                // array of structs: elements are packed inline at struct alignment
                let fields = p.fields.clone();
                let pfqn = p.fqn.clone();
                let (elem_size, _) = hidl_struct_size_align(&fields, reg, sdk)?;
                if elem_size == 0 {
                    return None;
                }
                // tighter bounds check: count * elem_size must fit in elems
                if count
                    .checked_mul(elem_size)
                    .map(|s| s > elems.len())
                    .unwrap_or(true)
                {
                    return None;
                }
                for i in 0..count {
                    let struct_off = i * elem_size;
                    let struct_bytes = elems.get(struct_off..struct_off + elem_size)?;
                    let elem_children = decode_hidl_struct_fields(
                        reg,
                        sdk,
                        data,
                        offsets,
                        ptr_payloads,
                        struct_bytes,
                        elems_obj_idx,
                        struct_off as u64,
                        &fields,
                        depth + 1,
                    )?;
                    children.push(node(
                        DecodedValue::Parcelable {
                            fqn: pfqn.clone(),
                            null: false,
                        },
                        &pfqn,
                        struct_off,
                        elem_size,
                        elem_children,
                    ));
                }
            } else {
                return None; // unresolved fqn
            }
        }
        TypeRef::HidlHandle => {
            // vec<handle>: each 16-byte element in the elements buffer is
            // { native_handle* (8), pad (8) }. the actual native_handle is a
            // child bbo with parent == elems_obj_idx and parent_offset == i*16.
            if count
                .checked_mul(16)
                .map(|s| s > elems.len())
                .unwrap_or(true)
            {
                return None;
            }
            for i in 0..count {
                let nh_idx = find_child_obj(data, offsets, elems_obj_idx, (i as u64) * 16)?;
                let payload = get_payload(ptr_payloads, nh_idx)?;
                let nh_node = decode_hidl_handle(payload, depth + 1)?;
                children.push(nh_node);
            }
        }
        _ => return None,
    }
    Some(children)
}

// decode a top-level hidl_vec<T> arg. consumes the 40-byte buffer_object from cur,
// reads count from the 16-byte child payload, then decodes count elements from the
// elements child buffer.
fn decode_hidl_vec(
    cur: &mut HidlCursor,
    data: &[u8],
    offsets: &[u8],
    ptr_payloads: &[(u32, Vec<u8>)],
    reg: &Registry,
    sdk: u32,
    inner: &TypeRef,
    depth: u32,
) -> Option<(DecodedNode, usize)> {
    if depth_exceeded(depth) {
        return None;
    }
    let start = cur.pos;
    let obj_idx = find_obj_index(offsets, start)?;
    // require PTR type tag — other object types are not buffer pointers
    let tag = u32::from_le_bytes(data.get(start..start + 4)?.try_into().ok()?);
    if tag != binder_object::PTR {
        return None;
    }
    cur.take(40)?;
    let payload = get_payload(ptr_payloads, obj_idx)?;
    if payload.len() < 12 {
        return None;
    }
    let count = u32::from_le_bytes(payload[8..12].try_into().ok()?) as usize;
    if count == 0 {
        return Some((
            node(
                DecodedValue::Array {
                    len: 0,
                    null: false,
                },
                "hidl_vec",
                start,
                cur.pos - start,
                vec![],
            ),
            obj_idx,
        ));
    }
    // elements child: parent == obj_idx, parent_offset == 0 (the buffer ptr in hidl_vec)
    let elems_idx = find_child_obj(data, offsets, obj_idx, 0)?;
    let elems = get_payload(ptr_payloads, elems_idx)?;
    let children = decode_hidl_vec_elems(
        reg,
        sdk,
        data,
        offsets,
        ptr_payloads,
        elems,
        elems_idx,
        count,
        inner,
        depth + 1,
    )?;
    Some((
        node(
            DecodedValue::Array {
                len: count,
                null: false,
            },
            "hidl_vec",
            start,
            cur.pos - start,
            children,
        ),
        obj_idx,
    ))
}

// shared walker used by decode_hidl_params (request) and decode_hidl_reply (reply).
// walks all params except those whose direction == skip_dir, using the scatter-gather buffer model.
// candidate_pkgs: ordered list of package fqns to try when resolving a bare (no '@') type name;
// the current package comes first, then any explicitly imported packages.
// iface_fqn: if Some, bare names that don't resolve via candidate_pkgs are also tried as
// nested types of that interface (e.g. "PowerMode" → "pkg@ver::IFace.PowerMode").
// cur is advanced in-place so the caller can inspect remaining bytes after the walk.
fn walk_params_skip(
    reg: &Registry,
    sdk: u32,
    method: &Method,
    data: &[u8],
    cur: &mut HidlCursor<'_>,
    offsets: &[u8],
    ptr_payloads: &[(u32, Vec<u8>)],
    skip_dir: Direction,
    candidate_pkgs: &[String],
    iface_fqn: Option<&str>,
) -> Vec<DecodedNode> {
    let mut nodes = Vec::new();

    for param in &method.params {
        if param.direction == skip_dir {
            continue;
        }
        let before = cur.pos;
        // resolve any typedef chain before dispatch; bare names like "Display" or "VsyncPeriodNanos"
        // are qualified against candidate_pkgs (current package first, then imports). if that
        // fails and iface_fqn is set, also try the interface's nested-type scope (e.g.
        // "PowerMode" inside IComposerClient → "pkg@ver::IComposerClient.PowerMode").
        let typedef_resolved = match &param.ty {
            TypeRef::UserDefined(fqn)
                if !fqn.contains('@') && (!candidate_pkgs.is_empty() || iface_fqn.is_some()) =>
            {
                let via_pkgs = if !candidate_pkgs.is_empty() {
                    reg.resolve_user_type(sdk, fqn, candidate_pkgs)
                } else {
                    None
                };
                via_pkgs.or_else(|| {
                    let iface = iface_fqn?;
                    let nested = format!("{}.{}", iface, fqn);
                    if reg.enum_def(sdk, &nested).is_some() {
                        return Some(TypeRef::UserDefined(nested));
                    }
                    if reg.parcelable_def(sdk, &nested).is_some() {
                        return Some(TypeRef::UserDefined(nested));
                    }
                    None
                })
            }
            TypeRef::UserDefined(fqn) => reg.typedef_def(sdk, fqn),
            _ => None,
        };
        let effective_ty = typedef_resolved.as_ref().unwrap_or(&param.ty);
        match effective_ty {
            TypeRef::Primitive(p) => match read_hidl_prim(cur, *p) {
                Some((val, label)) => {
                    let mut n = node(val, label, before, cur.pos - before, vec![]);
                    n.name = param.name.clone();
                    nodes.push(n);
                }
                None => {
                    nodes.push(raw_tail(
                        param.name.clone(),
                        before,
                        data.len(),
                        "buffer overrun".to_string(),
                    ));
                    return nodes;
                }
            },
            TypeRef::UserDefined(fqn) => {
                if let Some(e) = reg.enum_def(sdk, fqn) {
                    let backing = e.backing;
                    let efqn = e.fqn.clone();
                    let variants: Vec<(i64, String)> =
                        e.consts.iter().map(|(n, v)| (*v, n.clone())).collect();
                    match read_hidl_backing(cur, backing) {
                        Some(repr) => {
                            let mut n = node(
                                DecodedValue::Enum { repr, variants },
                                &efqn,
                                before,
                                cur.pos - before,
                                vec![],
                            );
                            n.name = param.name.clone();
                            nodes.push(n);
                        }
                        None => {
                            nodes.push(raw_tail(
                                param.name.clone(),
                                before,
                                data.len(),
                                "buffer overrun".to_string(),
                            ));
                            return nodes;
                        }
                    }
                } else if reg.parcelable_def(sdk, fqn).is_some() {
                    match decode_hidl_struct(cur, data, offsets, ptr_payloads, reg, sdk, fqn, 0) {
                        Some((mut n, obj_idx)) => {
                            n.name = param.name.clone();
                            nodes.push(n);
                            advance_past_descendants(cur, data, offsets, obj_idx);
                        }
                        None => {
                            nodes.push(raw_tail(
                                param.name.clone(),
                                before,
                                data.len(),
                                "hidl struct decode failed".to_string(),
                            ));
                            return nodes;
                        }
                    }
                } else {
                    // unresolved fqn or aggregate (interface/union)
                    nodes.push(raw_tail(
                        param.name.clone(),
                        before,
                        data.len(),
                        "hidl aggregate not yet supported".to_string(),
                    ));
                    return nodes;
                }
            }
            TypeRef::String => match decode_hidl_string(cur, data, offsets, ptr_payloads) {
                Some((val, obj_idx)) => {
                    let mut n = node(val, "hidl_string", before, cur.pos - before, vec![]);
                    n.name = param.name.clone();
                    nodes.push(n);
                    advance_past_descendants(cur, data, offsets, obj_idx);
                }
                None => {
                    nodes.push(raw_tail(
                        param.name.clone(),
                        before,
                        data.len(),
                        "hidl_string decode failed".to_string(),
                    ));
                    return nodes;
                }
            },
            TypeRef::List(inner) => {
                // resolve bare inner type name (e.g. "ParameterValue") through
                // candidate_pkgs so the element lookup finds the FQN in the registry.
                let resolved_inner = if let TypeRef::UserDefined(fqn) = inner.as_ref() {
                    if !fqn.contains('@') && !candidate_pkgs.is_empty() {
                        reg.resolve_user_type(sdk, fqn, candidate_pkgs)
                    } else {
                        reg.typedef_def(sdk, fqn)
                    }
                } else {
                    None
                };
                let effective_inner = resolved_inner.as_ref().unwrap_or(inner.as_ref());
                match decode_hidl_vec(
                    cur,
                    data,
                    offsets,
                    ptr_payloads,
                    reg,
                    sdk,
                    effective_inner,
                    0,
                ) {
                    Some((mut n, obj_idx)) => {
                        n.name = param.name.clone();
                        nodes.push(n);
                        advance_past_descendants(cur, data, offsets, obj_idx);
                    }
                    None => {
                        nodes.push(raw_tail(
                            param.name.clone(),
                            before,
                            data.len(),
                            "hidl_vec decode failed".to_string(),
                        ));
                        return nodes;
                    }
                }
            }
            TypeRef::FixedArray(inner, n) => {
                // N inline elements at natural alignment, no size/count prefix
                let mut fc = Vec::with_capacity(*n);
                let mut failed = false;
                for _ in 0..*n {
                    let s = cur.pos;
                    match inner.as_ref() {
                        TypeRef::Primitive(p) => match read_hidl_prim(cur, *p) {
                            Some((val, label)) => fc.push(node(val, label, s, cur.pos - s, vec![])),
                            None => {
                                failed = true;
                                break;
                            }
                        },
                        _ => {
                            failed = true;
                            break;
                        }
                    }
                }
                if failed {
                    nodes.push(raw_tail(
                        param.name.clone(),
                        before,
                        data.len(),
                        "fixed array decode failed".to_string(),
                    ));
                    return nodes;
                }
                let mut nn = node(
                    DecodedValue::Array {
                        len: *n,
                        null: false,
                    },
                    "fixed_array",
                    before,
                    cur.pos - before,
                    fc,
                );
                nn.name = param.name.clone();
                nodes.push(nn);
            }
            TypeRef::HidlHandle => {
                match decode_hidl_handle_bbo(cur, data, offsets, ptr_payloads, 0) {
                    Some((mut n, obj_idx)) => {
                        n.name = param.name.clone();
                        nodes.push(n);
                        advance_past_descendants(cur, data, offsets, obj_idx);
                    }
                    None => {
                        nodes.push(raw_tail(
                            param.name.clone(),
                            before,
                            data.len(),
                            "hidl_handle decode failed".to_string(),
                        ));
                        return nodes;
                    }
                }
            }
            TypeRef::HidlMemory => {
                // hidl_memory is shared memory, not in-transaction
                nodes.push(raw_tail(
                    param.name.clone(),
                    before,
                    data.len(),
                    "hidl handle/memory (opaque)".to_string(),
                ));
                return nodes;
            }
            // IBinder, Array, Map, Nullable — not yet handled in HIDL
            _ => {
                nodes.push(raw_tail(
                    param.name.clone(),
                    before,
                    data.len(),
                    "hidl aggregate not yet supported".to_string(),
                ));
                return nodes;
            }
        }
    }
    nodes
}

// decode a HIDL method's in-params from `data` starting at `start`, using the
// offsets array and the captured child payloads.
// candidate_pkgs: ordered package fqns for resolving bare type names (current pkg first).
// iface_fqn: if Some, bare names unresolvable via candidate_pkgs are also tried as
// nested types of that interface (e.g. pkg@ver::IFoo.TypeName).
pub fn decode_hidl_params(
    reg: &Registry,
    sdk: u32,
    method: &Method,
    data: &[u8],
    start: usize,
    offsets: &[u8],
    ptr_payloads: &[(u32, Vec<u8>)],
    candidate_pkgs: &[String],
    iface_fqn: Option<&str>,
) -> Vec<DecodedNode> {
    // parcel_mode: top-level args written by hwbinder Parcel::write (pad to 4,
    // no 8-byte realignment before u64/i64).
    let mut cur = HidlCursor::new_parcel(data, start);
    walk_params_skip(
        reg,
        sdk,
        method,
        data,
        &mut cur,
        offsets,
        ptr_payloads,
        Direction::Out,
        candidate_pkgs,
        iface_fqn,
    )
}

// decode a HIDL method's reply: the generates() out-params (Direction::Out).
// start is 0 — replies carry no interface token.
// candidate_pkgs: ordered package fqns for resolving bare type names (current pkg first).
// iface_fqn: if Some, bare names unresolvable via candidate_pkgs are also tried as
// nested types of that interface (e.g. pkg@ver::IFoo.TypeName).
pub fn decode_hidl_reply(
    reg: &Registry,
    sdk: u32,
    method: &Method,
    data: &[u8],
    start: usize,
    offsets: &[u8],
    ptr_payloads: &[(u32, Vec<u8>)],
    candidate_pkgs: &[String],
    iface_fqn: Option<&str>,
) -> Vec<DecodedNode> {
    let mut cur = HidlCursor::new_parcel(data, start);
    let mut nodes = walk_params_skip(
        reg,
        sdk,
        method,
        data,
        &mut cur,
        offsets,
        ptr_payloads,
        Direction::In,
        candidate_pkgs,
        iface_fqn,
    );

    // TODO - _hidl_status framing is unverified; no real reply frame available to confirm
    // its position relative to the out-params. attempt to surface a trailing int32 only when
    // exactly 4 bytes remain at a 4-aligned cursor; prefer leaving remainder alone over fabricating.
    let aligned = (cur.pos + 3) & !3;
    if data.len().saturating_sub(aligned) == 4 {
        cur.pos = aligned;
        if let Some(status) = cur.read_i32() {
            let before = cur.pos - 4;
            let mut n = node(
                DecodedValue::I64(status as i64),
                "int32_t",
                before,
                4,
                vec![],
            );
            n.name = "_hidl_status".to_string();
            nodes.push(n);
        }
    }

    nodes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binder_object;
    use crate::model::{
        Direction, EnumDef, Field, Method, OverlayLayer, Parameter, Parcelable, Prim, TypeRef,
    };
    use crate::registry::Registry;
    use std::collections::HashMap;

    fn empty_reg() -> Registry {
        Registry::empty()
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

    fn reg_with_parcelable(fqn: &str, fields: Vec<(&str, TypeRef)>) -> Registry {
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

    // build a 40-byte binder_buffer_object with PTR type tag.
    // buffer ptr is left as zero (decoder ignores it).
    fn buf_obj(flags: u32, length: u64, parent: u64, parent_offset: u64) -> [u8; 40] {
        let mut b = [0u8; 40];
        b[0..4].copy_from_slice(&binder_object::PTR.to_le_bytes());
        b[4..8].copy_from_slice(&flags.to_le_bytes());
        b[16..24].copy_from_slice(&length.to_le_bytes());
        b[24..32].copy_from_slice(&parent.to_le_bytes());
        b[32..40].copy_from_slice(&parent_offset.to_le_bytes());
        b
    }

    // encode offsets array: slice of u64 byte-positions into data.
    fn offsets_buf(positions: &[u64]) -> Vec<u8> {
        let mut v = Vec::new();
        for &p in positions {
            v.extend_from_slice(&p.to_le_bytes());
        }
        v
    }

    // 16-byte hidl_string/hidl_vec struct payload: ptr(8) + count_or_size(4) + owns+pad(4).
    fn sg_payload(count_or_size: u32) -> Vec<u8> {
        let mut v = vec![0u8; 8]; // ptr = 0
        v.extend_from_slice(&count_or_size.to_le_bytes());
        v.extend_from_slice(&[0u8; 4]); // owns + pad
        v
    }

    // build a 16-byte hidl_string inline struct: ptr[8]=0 + size[4] + owns[4]=0
    fn hidl_string_inline(size: u32) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[8..12].copy_from_slice(&size.to_le_bytes());
        b
    }

    #[test]
    fn decodes_two_inline_primitives() {
        // setPowerMode_2_2(Display display /*uint64_t*/, PowerMode mode /*int32_t*/)
        // u64 at offset 0 (8-aligned), i32 at offset 8 (4-aligned, no padding needed).
        let reg = empty_reg();
        let m = method(vec![
            in_param("display", TypeRef::Primitive(Prim::U64)),
            in_param("mode", TypeRef::Primitive(Prim::I32)),
        ]);
        let display_val: u64 = 0xDEAD_BEEF_CAFE_BABEu64;
        let mode_val: i32 = 42;
        let mut buf = Vec::new();
        buf.extend_from_slice(&display_val.to_le_bytes()); // 8 bytes at offset 0
        buf.extend_from_slice(&mode_val.to_le_bytes()); // 4 bytes at offset 8

        let nodes = decode_hidl_params(&reg, 34, &m, &buf, 0, &[], &[], &[], None);

        assert_eq!(nodes.len(), 2, "expected two decoded nodes");
        assert_eq!(nodes[0].name, "display");
        assert!(
            matches!(nodes[0].value, DecodedValue::U64(v) if v == display_val),
            "expected U64({:#x}), got {:?}",
            display_val,
            nodes[0].value
        );
        assert_eq!(nodes[1].name, "mode");
        assert!(
            matches!(nodes[1].value, DecodedValue::I64(v) if v == mode_val as i64),
            "expected I64({}), got {:?}",
            mode_val,
            nodes[1].value
        );
    }

    #[test]
    fn parcel_mode_no_8byte_realign_for_u64() {
        // in parcel mode (top-level Parcel args), u64 is NOT realigned to the next
        // 8-byte boundary before reading. after reading the u8 at pos 0 (cursor moves
        // to 1), u64 is read directly from [1..9] with no gap.
        // this matches libhwbinder Parcel::write which pads the written SIZE to 4 bytes
        // but never realigns the write POSITION.
        let reg = empty_reg();
        let m = method(vec![
            in_param("flags", TypeRef::Primitive(Prim::U8)),
            in_param("handle", TypeRef::Primitive(Prim::U64)),
        ]);
        let mut buf = vec![0u8; 9];
        buf[0] = 0x05; // flags = 5 (1 byte), cursor advances to 1
        let handle_val: u64 = 0x1234_5678_9ABC_DEF0;
        buf[1..9].copy_from_slice(&handle_val.to_le_bytes()); // u64 at pos 1, no gap

        let nodes = decode_hidl_params(&reg, 34, &m, &buf, 0, &[], &[], &[], None);

        assert_eq!(nodes.len(), 2);
        assert!(matches!(nodes[0].value, DecodedValue::U64(5)));
        assert!(matches!(nodes[1].value, DecodedValue::U64(v) if v == handle_val));
    }

    #[test]
    fn out_param_is_skipped() {
        let reg = empty_reg();
        let m = method(vec![
            in_param("x", TypeRef::Primitive(Prim::I32)),
            out_param("result", TypeRef::Primitive(Prim::I32)),
        ]);
        let buf = 7i32.to_le_bytes();
        let nodes = decode_hidl_params(&reg, 34, &m, &buf, 0, &[], &[], &[], None);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "x");
        assert!(matches!(nodes[0].value, DecodedValue::I64(7)));
    }

    #[test]
    fn decodes_enum_param() {
        // PowerMode enum backed by int32_t
        let reg = reg_with_enum(
            "android.hardware.graphics.composer.hal.PowerMode",
            Prim::I32,
            vec![("OFF", 0), ("ON", 2), ("DOZE", 3)],
        );
        let m = method(vec![in_param(
            "mode",
            TypeRef::UserDefined("android.hardware.graphics.composer.hal.PowerMode".into()),
        )]);
        let buf = 2i32.to_le_bytes(); // ON = 2
        let nodes = decode_hidl_params(&reg, 34, &m, &buf, 0, &[], &[], &[], None);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "mode");
        match &nodes[0].value {
            DecodedValue::Enum { repr, variants } => {
                assert_eq!(*repr, 2);
                assert!(variants.contains(&(2, "ON".to_string())));
            }
            v => panic!("expected enum, got {:?}", v),
        }
    }

    #[test]
    fn aggregate_type_yields_raw_tail_and_stops() {
        // a String param stops the walk after the decoded primitives before it.
        // with no offsets provided the hidl_string decode fails immediately.
        let reg = empty_reg();
        let m = method(vec![
            in_param("id", TypeRef::Primitive(Prim::I32)),
            in_param("name", TypeRef::String),
            in_param("after", TypeRef::Primitive(Prim::I32)),
        ]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&99i32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 16]);

        let nodes = decode_hidl_params(&reg, 34, &m, &buf, 0, &[], &[], &[], None);

        // id decoded, then a RawTail at "name"; "after" never reached
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "id");
        assert_eq!(nodes[1].name, "name");
        assert!(matches!(
            &nodes[1].value,
            DecodedValue::RawTail { reason } if reason == "hidl_string decode failed"
        ));
    }

    #[test]
    fn overrun_yields_raw_tail() {
        let reg = empty_reg();
        let m = method(vec![in_param("x", TypeRef::Primitive(Prim::U64))]);
        let buf = [0u8; 4]; // too short for a u64

        let nodes = decode_hidl_params(&reg, 34, &m, &buf, 0, &[], &[], &[], None);

        assert_eq!(nodes.len(), 1);
        assert!(matches!(
            &nodes[0].value,
            DecodedValue::RawTail { reason } if reason == "buffer overrun"
        ));
    }

    #[test]
    fn unresolved_user_defined_yields_raw_tail() {
        let reg = empty_reg();
        let m = method(vec![in_param(
            "p",
            TypeRef::UserDefined("android.hardware.foo.IFoo".into()),
        )]);
        let buf = [0u8; 32];

        let nodes = decode_hidl_params(&reg, 34, &m, &buf, 0, &[], &[], &[], None);

        assert_eq!(nodes.len(), 1);
        assert!(matches!(
            &nodes[0].value,
            DecodedValue::RawTail { reason } if reason == "hidl aggregate not yet supported"
        ));
    }

    // --- scatter-gather tests ---

    #[test]
    fn decodes_top_level_string() {
        let reg = empty_reg();
        let m = method(vec![in_param("name", TypeRef::String)]);

        // data: obj0 (top-level string, no HAS_PARENT) + obj1 (chars child, HAS_PARENT)
        let mut data = Vec::new();
        data.extend_from_slice(&buf_obj(0, 16, 0, 0)); // obj0 at data[0]
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 6, 0, 0)); // obj1 at data[40], parent=obj0

        let offs = offsets_buf(&[0, 40]);

        let payloads: Vec<(u32, Vec<u8>)> = vec![
            (0, sg_payload(5)),       // hidl_string: size=5
            (1, b"hello\0".to_vec()), // chars: "hello" + NUL
        ];

        let nodes = decode_hidl_params(&reg, 34, &m, &data, 0, &offs, &payloads, &[], None);

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "name");
        assert!(
            matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s == "hello"),
            "expected Str(Some(\"hello\")), got {:?}",
            nodes[0].value
        );
    }

    #[test]
    fn decodes_top_level_empty_string() {
        let reg = empty_reg();
        let m = method(vec![in_param("s", TypeRef::String)]);

        // obj0 only; no chars child needed when size==0
        let mut data = buf_obj(0, 16, 0, 0).to_vec();
        data.extend_from_slice(&[0u8; 40]); // padding (no child obj needed)

        let offs = offsets_buf(&[0]);
        let payloads: Vec<(u32, Vec<u8>)> = vec![(0, sg_payload(0))]; // size=0

        let nodes = decode_hidl_params(&reg, 34, &m, &data, 0, &offs, &payloads, &[], None);

        assert_eq!(nodes.len(), 1);
        assert!(
            matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s.is_empty()),
            "expected empty string, got {:?}",
            nodes[0].value
        );
    }

    #[test]
    fn decodes_vec_of_uint32() {
        let reg = empty_reg();
        let m = method(vec![in_param(
            "values",
            TypeRef::List(Box::new(TypeRef::Primitive(Prim::U32))),
        )]);

        // obj0: top-level vec buffer_object at data[0]
        // obj1: elements child at data[40], parent=0, parent_offset=0
        let mut data = Vec::new();
        data.extend_from_slice(&buf_obj(0, 16, 0, 0));
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 12, 0, 0)); // 3×4 bytes

        let offs = offsets_buf(&[0, 40]);

        // elements: [10, 20, 30] as u32 LE
        let mut elems = Vec::new();
        elems.extend_from_slice(&10u32.to_le_bytes());
        elems.extend_from_slice(&20u32.to_le_bytes());
        elems.extend_from_slice(&30u32.to_le_bytes());

        let payloads: Vec<(u32, Vec<u8>)> = vec![
            (0, sg_payload(3)), // hidl_vec: count=3
            (1, elems),
        ];

        let nodes = decode_hidl_params(&reg, 34, &m, &data, 0, &offs, &payloads, &[], None);

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "values");
        assert!(
            matches!(
                &nodes[0].value,
                DecodedValue::Array {
                    len: 3,
                    null: false
                }
            ),
            "expected Array {{ len: 3 }}, got {:?}",
            nodes[0].value
        );
        assert_eq!(nodes[0].children.len(), 3);
        assert!(matches!(nodes[0].children[0].value, DecodedValue::U64(10)));
        assert!(matches!(nodes[0].children[1].value, DecodedValue::U64(20)));
        assert!(matches!(nodes[0].children[2].value, DecodedValue::U64(30)));
    }

    #[test]
    fn non_ptr_type_tag_yields_raw_tail() {
        // buffer_object at cursor has BINDER type tag (not PTR); decode must reject it
        // and return a raw_tail rather than wrongly treating it as a hidl_string.
        let reg = empty_reg();
        let m = method(vec![in_param("name", TypeRef::String)]);

        // obj0: BINDER-tagged at data[0] — overwrite the PTR tag from buf_obj
        let mut data = Vec::new();
        let mut obj0 = buf_obj(0, 16, 0, 0);
        obj0[0..4].copy_from_slice(&binder_object::BINDER.to_le_bytes());
        data.extend_from_slice(&obj0);
        // obj1: chars child at data[40], parent=0, parent_offset=0
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 6, 0, 0));

        let offs = offsets_buf(&[0, 40]);
        let payloads: Vec<(u32, Vec<u8>)> = vec![
            (0, sg_payload(5)),       // hidl_string: size=5
            (1, b"hello\0".to_vec()), // chars: "hello" + NUL
        ];

        let nodes = decode_hidl_params(&reg, 34, &m, &data, 0, &offs, &payloads, &[], None);

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "name");
        assert!(
            matches!(
                &nodes[0].value,
                DecodedValue::RawTail { reason } if reason == "hidl_string decode failed"
            ),
            "expected RawTail(hidl_string decode failed), got {:?}",
            nodes[0].value
        );
    }

    #[test]
    fn vec_count_exceeding_elems_len_yields_raw_tail() {
        // count (100) > elements payload len (12 bytes) — must be rejected before the element loop
        let reg = empty_reg();
        let m = method(vec![in_param(
            "values",
            TypeRef::List(Box::new(TypeRef::Primitive(Prim::U32))),
        )]);

        let mut data = Vec::new();
        data.extend_from_slice(&buf_obj(0, 16, 0, 0));
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 12, 0, 0));

        let offs = offsets_buf(&[0, 40]);

        let mut elems = Vec::new();
        elems.extend_from_slice(&1u32.to_le_bytes());
        elems.extend_from_slice(&2u32.to_le_bytes());
        elems.extend_from_slice(&3u32.to_le_bytes());

        let payloads: Vec<(u32, Vec<u8>)> = vec![
            (0, sg_payload(100)), // count=100, but elems is only 12 bytes
            (1, elems),
        ];

        let nodes = decode_hidl_params(&reg, 34, &m, &data, 0, &offs, &payloads, &[], None);

        assert_eq!(nodes.len(), 1);
        assert!(
            matches!(&nodes[0].value, DecodedValue::RawTail { .. }),
            "expected RawTail, got {:?}",
            nodes[0].value
        );
    }

    #[test]
    fn decodes_vec_of_strings() {
        // vec<hidl_string> with 2 elements: ["foo", "bar"]
        // elements buffer contains 2 × 16-byte hidl_string structs.
        // chars children: parent=elems_obj_idx=1, parent_offset=0 (elem 0) and 16 (elem 1).
        let reg = empty_reg();
        let m = method(vec![in_param(
            "keys",
            TypeRef::List(Box::new(TypeRef::String)),
        )]);

        // data:
        //   obj0 at 0:  top-level vec (no HAS_PARENT)
        //   obj1 at 40: elements child (HAS_PARENT, parent=0, parent_offset=0)
        //   obj2 at 80: chars for elem0 (HAS_PARENT, parent=1, parent_offset=0)
        //   obj3 at 120: chars for elem1 (HAS_PARENT, parent=1, parent_offset=16)
        let mut data = Vec::new();
        data.extend_from_slice(&buf_obj(0, 16, 0, 0)); // obj0
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 32, 0, 0)); // obj1: parent=0
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 4, 1, 0)); // obj2: parent=1, parent_off=0
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 4, 1, 16)); // obj3: parent=1, parent_off=16

        let offs = offsets_buf(&[0, 40, 80, 120]);

        // elements buffer: two hidl_string structs (32 bytes)
        //   elem0 at offset 0:  ptr(8) + size=3(4) + pad(4)
        //   elem1 at offset 16: ptr(8) + size=3(4) + pad(4)
        let mut elems = Vec::new();
        elems.extend_from_slice(&[0u8; 8]); // ptr
        elems.extend_from_slice(&3u32.to_le_bytes()); // size=3 ("foo")
        elems.extend_from_slice(&[0u8; 4]); // owns+pad
        elems.extend_from_slice(&[0u8; 8]); // ptr
        elems.extend_from_slice(&3u32.to_le_bytes()); // size=3 ("bar")
        elems.extend_from_slice(&[0u8; 4]);

        let payloads: Vec<(u32, Vec<u8>)> = vec![
            (0, sg_payload(2)),     // hidl_vec: count=2
            (1, elems),             // elements: two hidl_string structs
            (2, b"foo\0".to_vec()), // chars for elem0
            (3, b"bar\0".to_vec()), // chars for elem1
        ];

        let nodes = decode_hidl_params(&reg, 34, &m, &data, 0, &offs, &payloads, &[], None);

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "keys");
        assert!(
            matches!(
                &nodes[0].value,
                DecodedValue::Array {
                    len: 2,
                    null: false
                }
            ),
            "got {:?}",
            nodes[0].value
        );
        assert_eq!(nodes[0].children.len(), 2);
        assert!(
            matches!(&nodes[0].children[0].value, DecodedValue::Str(Some(s)) if s == "foo"),
            "elem0 = {:?}",
            nodes[0].children[0].value
        );
        assert!(
            matches!(&nodes[0].children[1].value, DecodedValue::Str(Some(s)) if s == "bar"),
            "elem1 = {:?}",
            nodes[0].children[1].value
        );
    }

    // corrupted mSize in embedded hidl_string (frame-321 "en_state" regression).
    // in a vec<string>, the kernel's sg address translation corrupts the mSize field
    // of hidl_string structs inside the elements buffer. the char buffer itself is intact
    // and NUL-terminated. mSize=1 must not truncate "en_state" to "e".
    #[test]
    fn vec_of_strings_corrupted_msize_reads_to_nul() {
        let reg = empty_reg();
        let m = method(vec![in_param(
            "keys",
            TypeRef::List(Box::new(TypeRef::String)),
        )]);

        // sg tree:
        //   obj0 at 0:  top-level vec
        //   obj1 at 40: elements buffer (parent=0, parent_off=0); 1 hidl_string = 16 bytes
        //   obj2 at 80: chars for elem0 (parent=1, parent_off=0)
        let mut data = Vec::new();
        data.extend_from_slice(&buf_obj(0, 16, 0, 0)); // obj0
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 16, 0, 0)); // obj1
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 13, 1, 0)); // obj2

        let offs = offsets_buf(&[0, 40, 80]);

        // elements: 1 hidl_string with mSize=1 (corrupted; real string is "en_state")
        let elems = hidl_string_inline(1).to_vec();

        // char buffer matches the real frame-321 payload: "en_state\0\0\0\0\xb0"
        let chars: Vec<u8> = vec![
            b'e', b'n', b'_', b's', b't', b'a', b't', b'e', 0, 0, 0, 0, 0xb0,
        ];

        let payloads: Vec<(u32, Vec<u8>)> = vec![
            (0, sg_payload(1)), // vec: count=1
            (1, elems),         // elements: 1 hidl_string struct with mSize=1
            (2, chars),         // chars: "en_state\0..."
        ];

        let nodes = decode_hidl_params(&reg, 34, &m, &data, 0, &offs, &payloads, &[], None);

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "keys");
        assert_eq!(
            nodes[0].children.len(),
            1,
            "expected 1 element, got {nodes:?}"
        );
        assert!(
            matches!(&nodes[0].children[0].value, DecodedValue::Str(Some(s)) if s == "en_state"),
            "expected \"en_state\" (NUL-terminated, ignoring corrupted mSize=1), got {:?}",
            nodes[0].children[0].value
        );
    }

    // --- struct tests ---

    // vec<ParameterValue> where ParameterValue = { string key; string value; }
    // this is the frame-695 shape: 2 elements, each with 2 embedded hidl_strings.
    // the strings resolve via parent_offset == i*32 (struct base) + 0 or 16 (field offset).
    #[test]
    fn decodes_vec_of_struct_with_two_strings() {
        let reg = reg_with_parcelable(
            "a.PV",
            vec![("key", TypeRef::String), ("value", TypeRef::String)],
        );
        let m = method(vec![in_param(
            "params",
            TypeRef::List(Box::new(TypeRef::UserDefined("a.PV".into()))),
        )]);

        // sg tree:
        //   obj0 at 0:    top-level vec
        //   obj1 at 40:   elements buffer (parent=0, parent_off=0)
        //   obj2 at 80:   chars elem0.key  (parent=1, parent_off=0)
        //   obj3 at 120:  chars elem0.value (parent=1, parent_off=16)
        //   obj4 at 160:  chars elem1.key  (parent=1, parent_off=32)
        //   obj5 at 200:  chars elem1.value (parent=1, parent_off=48)
        let mut data = Vec::new();
        data.extend_from_slice(&buf_obj(0, 16, 0, 0)); // obj0
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 64, 0, 0)); // obj1
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 4, 1, 0)); // obj2
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 6, 1, 16)); // obj3
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 5, 1, 32)); // obj4
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 7, 1, 48)); // obj5

        let offs = offsets_buf(&[0, 40, 80, 120, 160, 200]);

        // elements buffer: 2 × 32-byte structs
        // struct PV = { hidl_string key[16]; hidl_string value[16]; } = 32 bytes
        let mut elems = Vec::new();
        elems.extend_from_slice(&hidl_string_inline(3)); // elem0.key: size=3
        elems.extend_from_slice(&hidl_string_inline(5)); // elem0.value: size=5
        elems.extend_from_slice(&hidl_string_inline(4)); // elem1.key: size=4
        elems.extend_from_slice(&hidl_string_inline(6)); // elem1.value: size=6

        let payloads: Vec<(u32, Vec<u8>)> = vec![
            (0, sg_payload(2)),        // vec: count=2
            (1, elems),                // 64-byte elements buffer
            (2, b"key\0".to_vec()),    // elem0.key
            (3, b"value\0".to_vec()),  // elem0.value
            (4, b"key1\0".to_vec()),   // elem1.key
            (5, b"value1\0".to_vec()), // elem1.value
        ];

        let nodes = decode_hidl_params(&reg, 34, &m, &data, 0, &offs, &payloads, &[], None);

        assert_eq!(nodes.len(), 1, "expected 1 vec node, got {nodes:?}");
        assert_eq!(nodes[0].name, "params");
        assert!(
            matches!(
                &nodes[0].value,
                DecodedValue::Array {
                    len: 2,
                    null: false
                }
            ),
            "got {:?}",
            nodes[0].value
        );
        assert_eq!(nodes[0].children.len(), 2, "expected 2 struct elements");

        // elem0
        let e0 = &nodes[0].children[0];
        assert!(matches!(&e0.value, DecodedValue::Parcelable { fqn, .. } if fqn == "a.PV"));
        assert_eq!(e0.children.len(), 2);
        assert_eq!(e0.children[0].name, "key");
        assert!(
            matches!(&e0.children[0].value, DecodedValue::Str(Some(s)) if s == "key"),
            "elem0.key = {:?}",
            e0.children[0].value
        );
        assert_eq!(e0.children[1].name, "value");
        assert!(
            matches!(&e0.children[1].value, DecodedValue::Str(Some(s)) if s == "value"),
            "elem0.value = {:?}",
            e0.children[1].value
        );

        // elem1
        let e1 = &nodes[0].children[1];
        assert!(matches!(&e1.value, DecodedValue::Parcelable { fqn, .. } if fqn == "a.PV"));
        assert_eq!(e1.children.len(), 2);
        assert!(
            matches!(&e1.children[0].value, DecodedValue::Str(Some(s)) if s == "key1"),
            "elem1.key = {:?}",
            e1.children[0].value
        );
        assert!(
            matches!(&e1.children[1].value, DecodedValue::Str(Some(s)) if s == "value1"),
            "elem1.value = {:?}",
            e1.children[1].value
        );
    }

    // top-level struct arg: { uint32_t x; string label; }
    // the struct is wrapped in a 40-byte buffer_object; the string field resolves
    // via a chars child whose parent_offset == 8 (after u32 x + 4 bytes alignment pad).
    #[test]
    fn decodes_top_level_struct_with_primitive_and_string() {
        let reg = reg_with_parcelable(
            "a.Point",
            vec![
                ("x", TypeRef::Primitive(Prim::U32)),
                ("label", TypeRef::String),
            ],
        );
        let m = method(vec![in_param("p", TypeRef::UserDefined("a.Point".into()))]);

        // sg tree:
        //   obj0 at 0:  struct buffer_object (top-level, no parent)
        //   obj1 at 40: chars for struct.label (parent=0, parent_off=8)
        //               — hidl_string is at byte offset 8 in the struct payload
        //                 (u32 x[4] + 4-byte pad to align-8 → string at 8)
        let mut data = Vec::new();
        data.extend_from_slice(&buf_obj(0, 24, 0, 0)); // obj0: struct payload is 24 bytes
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 7, 0, 8)); // obj1

        let offs = offsets_buf(&[0, 40]);

        // struct payload: x=42(4) + pad(4) + hidl_string{size=6}(16) = 24 bytes
        let mut struct_bytes: Vec<u8> = Vec::new();
        struct_bytes.extend_from_slice(&42u32.to_le_bytes()); // x
        struct_bytes.extend_from_slice(&[0u8; 4]); // alignment padding
        struct_bytes.extend_from_slice(&hidl_string_inline(6)); // label: size=6

        let payloads: Vec<(u32, Vec<u8>)> = vec![
            (0, struct_bytes),         // the struct's bytes
            (1, b"foobar\0".to_vec()), // chars for label
        ];

        let nodes = decode_hidl_params(&reg, 34, &m, &data, 0, &offs, &payloads, &[], None);

        assert_eq!(nodes.len(), 1, "got {nodes:?}");
        assert_eq!(nodes[0].name, "p");
        assert!(
            matches!(&nodes[0].value, DecodedValue::Parcelable { fqn, null: false } if fqn == "a.Point"),
            "got {:?}",
            nodes[0].value
        );
        assert_eq!(nodes[0].children.len(), 2);
        assert_eq!(nodes[0].children[0].name, "x");
        assert!(matches!(nodes[0].children[0].value, DecodedValue::U64(42)));
        assert_eq!(nodes[0].children[1].name, "label");
        assert!(
            matches!(&nodes[0].children[1].value, DecodedValue::Str(Some(s)) if s == "foobar"),
            "label = {:?}",
            nodes[0].children[1].value
        );
    }

    // fixed array: uint32_t[4] — 4 inline u32 values, no size prefix.
    #[test]
    fn decodes_fixed_array_of_uint32() {
        let reg = empty_reg();
        let m = method(vec![in_param(
            "m",
            TypeRef::FixedArray(Box::new(TypeRef::Primitive(Prim::U32)), 4),
        )]);

        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&3u32.to_le_bytes());
        buf.extend_from_slice(&4u32.to_le_bytes());

        let nodes = decode_hidl_params(&reg, 34, &m, &buf, 0, &[], &[], &[], None);

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "m");
        assert!(
            matches!(
                &nodes[0].value,
                DecodedValue::Array {
                    len: 4,
                    null: false
                }
            ),
            "got {:?}",
            nodes[0].value
        );
        assert_eq!(nodes[0].children.len(), 4);
        assert!(matches!(nodes[0].children[0].value, DecodedValue::U64(1)));
        assert!(matches!(nodes[0].children[1].value, DecodedValue::U64(2)));
        assert!(matches!(nodes[0].children[2].value, DecodedValue::U64(3)));
        assert!(matches!(nodes[0].children[3].value, DecodedValue::U64(4)));
    }

    // handle with no valid PTR buffer_object: yields raw_tail and stops
    #[test]
    fn hidl_handle_no_ptr_obj_yields_raw_tail() {
        let reg = empty_reg();
        let m = method(vec![
            in_param("id", TypeRef::Primitive(Prim::I32)),
            in_param("h", TypeRef::HidlHandle),
            in_param("after", TypeRef::Primitive(Prim::I32)),
        ]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&5i32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 32]); // no valid PTR bbo here

        let nodes = decode_hidl_params(&reg, 34, &m, &buf, 0, &[], &[], &[], None);

        // id decoded, h → raw_tail (no PTR obj at cursor), after not reached
        assert_eq!(nodes.len(), 2);
        assert!(matches!(nodes[0].value, DecodedValue::I64(5)));
        assert!(
            matches!(
                &nodes[1].value,
                DecodedValue::RawTail { reason } if reason == "hidl_handle decode failed"
            ),
            "got {:?}",
            nodes[1].value
        );
    }

    // hidl_struct_size_align: struct with u32 + hidl_string = 24 bytes (with end-pad)
    #[test]
    fn struct_size_align_with_prim_and_string() {
        let reg = empty_reg();
        let fields = vec![
            Field {
                name: "x".into(),
                ty: TypeRef::Primitive(Prim::U32),
            },
            Field {
                name: "s".into(),
                ty: TypeRef::String,
            },
        ];
        // x: 4 bytes at align 4 (offset 0..4)
        // s: 16 bytes at align 8 (offset 8..24, after 4 bytes pad)
        // end-pad to align 8: 24 is already a multiple of 8
        let (size, align) = hidl_struct_size_align(&fields, &reg, 34).unwrap();
        assert_eq!(size, 24, "expected 24 bytes for {{u32, hidl_string}}");
        assert_eq!(align, 8);
    }

    // hidl_struct_size_align: two hidl_strings = 32 bytes
    #[test]
    fn struct_size_align_two_strings() {
        let reg = empty_reg();
        let fields = vec![
            Field {
                name: "key".into(),
                ty: TypeRef::String,
            },
            Field {
                name: "value".into(),
                ty: TypeRef::String,
            },
        ];
        // each hidl_string: 16 bytes, align 8 → total 32 bytes, align 8
        let (size, align) = hidl_struct_size_align(&fields, &reg, 34).unwrap();
        assert_eq!(size, 32, "expected 32 bytes for two hidl_strings");
        assert_eq!(align, 8);
    }

    // --- decode_hidl_reply tests ---

    #[test]
    fn reply_decodes_inline_primitive_out_param() {
        // generates(int32_t result) — out-param is a plain i32, inline at start=0
        let reg = empty_reg();
        let m = method(vec![out_param("result", TypeRef::Primitive(Prim::I32))]);
        let data = 42i32.to_le_bytes();

        let nodes = decode_hidl_reply(&reg, 34, &m, &data, 0, &[], &[], &[], None);

        assert_eq!(nodes.len(), 1, "expected one node, got {nodes:?}");
        assert_eq!(nodes[0].name, "result");
        assert!(
            matches!(nodes[0].value, DecodedValue::I64(42)),
            "expected I64(42), got {:?}",
            nodes[0].value
        );
    }

    #[test]
    fn reply_decodes_string_out_param() {
        // generates(string s) — out-param is a hidl_string via buffer model
        let reg = empty_reg();
        let m = method(vec![out_param("s", TypeRef::String)]);

        // obj0: top-level string buffer_object (no parent)
        // obj1: chars child (HAS_PARENT, parent=0, parent_offset=0)
        let mut data = Vec::new();
        data.extend_from_slice(&buf_obj(0, 16, 0, 0));
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 6, 0, 0));

        let offs = offsets_buf(&[0, 40]);
        let payloads: Vec<(u32, Vec<u8>)> = vec![
            (0, sg_payload(5)),       // hidl_string: size=5
            (1, b"hello\0".to_vec()), // chars
        ];

        let nodes = decode_hidl_reply(&reg, 34, &m, &data, 0, &offs, &payloads, &[], None);

        assert_eq!(nodes.len(), 1, "expected one node, got {nodes:?}");
        assert_eq!(nodes[0].name, "s");
        assert!(
            matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s == "hello"),
            "expected Str(Some(\"hello\")), got {:?}",
            nodes[0].value
        );
    }

    #[test]
    fn empty_vec_in_offsets_does_not_block_next_vec() {
        // foo(vec<uint32_t> a, vec<uint32_t> b) where a is empty.
        // a's buffer_object IS in the offsets array (the real HIDL wire format —
        // confirmed on frame 695: the kernel always registers buffer_objects in offsets).
        // advance_past_descendants on a has an empty closure and advances exactly +40,
        // landing the cursor on obj1 (b's header) at data[40].
        let reg = empty_reg();
        let m = method(vec![
            in_param("a", TypeRef::List(Box::new(TypeRef::Primitive(Prim::U32)))),
            in_param("b", TypeRef::List(Box::new(TypeRef::Primitive(Prim::U32)))),
        ]);

        // data:
        //   obj0 at 0:   a's vec header (flags=0, no parent) — in offsets[0]
        //   obj1 at 40:  b's vec header (flags=0, no parent) — in offsets[1]
        //   obj2 at 80:  b's elements (HAS_PARENT, parent=1) — in offsets[2]
        let mut data = Vec::new();
        data.extend_from_slice(&buf_obj(0, 16, 0, 0));
        data.extend_from_slice(&buf_obj(0, 16, 0, 0));
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 8, 1, 0));

        let offs = offsets_buf(&[0, 40, 80]);

        let mut elems = Vec::new();
        elems.extend_from_slice(&7u32.to_le_bytes());
        elems.extend_from_slice(&11u32.to_le_bytes());

        let payloads: Vec<(u32, Vec<u8>)> = vec![
            (0, sg_payload(0)), // a: count=0
            (1, sg_payload(2)), // b: count=2
            (2, elems),         // b's elements: [7, 11]
        ];

        let nodes = decode_hidl_params(&reg, 34, &m, &data, 0, &offs, &payloads, &[], None);

        assert_eq!(
            nodes.len(),
            2,
            "expected both params decoded, got {nodes:?}"
        );
        assert_eq!(nodes[0].name, "a");
        assert!(
            matches!(
                &nodes[0].value,
                DecodedValue::Array {
                    len: 0,
                    null: false
                }
            ),
            "expected empty array for a, got {:?}",
            nodes[0].value
        );
        assert_eq!(nodes[1].name, "b");
        assert!(
            matches!(
                &nodes[1].value,
                DecodedValue::Array {
                    len: 2,
                    null: false
                }
            ),
            "expected array of 2 for b, got {:?}",
            nodes[1].value
        );
        assert_eq!(nodes[1].children.len(), 2, "b should have 2 elements");
        assert!(matches!(nodes[1].children[0].value, DecodedValue::U64(7)));
        assert!(matches!(nodes[1].children[1].value, DecodedValue::U64(11)));
    }

    #[test]
    fn reply_skips_in_params() {
        // method with one in-param and one out-param; reply should only decode the out-param
        let reg = empty_reg();
        let m = method(vec![
            in_param("request", TypeRef::Primitive(Prim::I32)),
            out_param("result", TypeRef::Primitive(Prim::I32)),
        ]);
        // reply carries only the out-param value (start=0, no token)
        let data = 99i32.to_le_bytes();

        let nodes = decode_hidl_reply(&reg, 34, &m, &data, 0, &[], &[], &[], None);

        assert_eq!(nodes.len(), 1, "expected one node, got {nodes:?}");
        assert_eq!(nodes[0].name, "result");
        assert!(
            matches!(nodes[0].value, DecodedValue::I64(99)),
            "expected I64(99), got {:?}",
            nodes[0].value
        );
    }

    // --- cursor-advance tests (C1 correctness) ---

    #[test]
    fn vec_nonempty_followed_by_primitive() {
        // foo(vec<uint32_t> a, uint32_t b) — a is non-empty (has an elements child at data[40]).
        // after decoding a, the cursor must skip past a's elements child so b reads from data[80].
        // bug: +40-only advance leaves cursor at 40; b reads the PTR type tag (0x70742a85) instead.
        let reg = empty_reg();
        let m = method(vec![
            in_param("a", TypeRef::List(Box::new(TypeRef::Primitive(Prim::U32)))),
            in_param("b", TypeRef::Primitive(Prim::U32)),
        ]);

        // data:
        //   obj0 at 0:  a's vec header (in offsets[0])
        //   obj1 at 40: a's elements (HAS_PARENT, parent=0, in offsets[1])
        //   b at 80:    0xCAFE_BABEu32 inline
        let mut data = Vec::new();
        data.extend_from_slice(&buf_obj(0, 16, 0, 0));
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 12, 0, 0));
        data.extend_from_slice(&0xCAFE_BABEu32.to_le_bytes());

        let offs = offsets_buf(&[0, 40]);

        let mut elems = Vec::new();
        elems.extend_from_slice(&1u32.to_le_bytes());
        elems.extend_from_slice(&2u32.to_le_bytes());
        elems.extend_from_slice(&3u32.to_le_bytes());

        let payloads: Vec<(u32, Vec<u8>)> = vec![(0, sg_payload(3)), (1, elems)];

        let nodes = decode_hidl_params(&reg, 34, &m, &data, 0, &offs, &payloads, &[], None);

        assert_eq!(
            nodes.len(),
            2,
            "expected both params decoded, got {nodes:?}"
        );
        assert_eq!(nodes[0].name, "a");
        assert!(
            matches!(
                &nodes[0].value,
                DecodedValue::Array {
                    len: 3,
                    null: false
                }
            ),
            "expected Array{{len:3}}, got {:?}",
            nodes[0].value
        );
        assert_eq!(nodes[1].name, "b");
        assert!(
            matches!(nodes[1].value, DecodedValue::U64(0xCAFE_BABE)),
            "expected U64(0xCAFEBABE), got {:?}",
            nodes[1].value
        );
    }

    #[test]
    fn two_nonempty_vecs_both_decoded() {
        // foo(vec<uint32_t> a, vec<uint32_t> c) — both non-empty.
        // after decoding a, the cursor must skip past a's elements child (obj1) so
        // c's find_obj_index lands on obj2, not obj1.
        let reg = empty_reg();
        let m = method(vec![
            in_param("a", TypeRef::List(Box::new(TypeRef::Primitive(Prim::U32)))),
            in_param("c", TypeRef::List(Box::new(TypeRef::Primitive(Prim::U32)))),
        ]);

        // data:
        //   obj0 at 0:   a's vec header (in offsets[0])
        //   obj1 at 40:  a's elements (HAS_PARENT, parent=0, in offsets[1])
        //   obj2 at 80:  c's vec header (in offsets[2])
        //   obj3 at 120: c's elements (HAS_PARENT, parent=2, in offsets[3])
        let mut data = Vec::new();
        data.extend_from_slice(&buf_obj(0, 16, 0, 0));
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 8, 0, 0));
        data.extend_from_slice(&buf_obj(0, 16, 0, 0));
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 8, 2, 0));

        let offs = offsets_buf(&[0, 40, 80, 120]);

        let mut a_elems = Vec::new();
        a_elems.extend_from_slice(&10u32.to_le_bytes());
        a_elems.extend_from_slice(&20u32.to_le_bytes());

        let mut c_elems = Vec::new();
        c_elems.extend_from_slice(&30u32.to_le_bytes());
        c_elems.extend_from_slice(&40u32.to_le_bytes());

        let payloads: Vec<(u32, Vec<u8>)> = vec![
            (0, sg_payload(2)),
            (1, a_elems),
            (2, sg_payload(2)),
            (3, c_elems),
        ];

        let nodes = decode_hidl_params(&reg, 34, &m, &data, 0, &offs, &payloads, &[], None);

        assert_eq!(
            nodes.len(),
            2,
            "expected both params decoded, got {nodes:?}"
        );

        assert_eq!(nodes[0].name, "a");
        assert!(
            matches!(
                &nodes[0].value,
                DecodedValue::Array {
                    len: 2,
                    null: false
                }
            ),
            "expected Array{{len:2}} for a, got {:?}",
            nodes[0].value
        );
        assert_eq!(nodes[0].children.len(), 2);
        assert!(matches!(nodes[0].children[0].value, DecodedValue::U64(10)));
        assert!(matches!(nodes[0].children[1].value, DecodedValue::U64(20)));

        assert_eq!(nodes[1].name, "c");
        assert!(
            matches!(
                &nodes[1].value,
                DecodedValue::Array {
                    len: 2,
                    null: false
                }
            ),
            "expected Array{{len:2}} for c, got {:?}",
            nodes[1].value
        );
        assert_eq!(nodes[1].children.len(), 2);
        assert!(matches!(nodes[1].children[0].value, DecodedValue::U64(30)));
        assert!(matches!(nodes[1].children[1].value, DecodedValue::U64(40)));
    }

    // --- typedef tests ---

    fn reg_with_typedef(typedef_fqn: &str, target: TypeRef) -> Registry {
        let mut o = OverlayLayer {
            source_path: "t".into(),
            interfaces: Default::default(),
            enums: Default::default(),
            parcelables: Default::default(),
            unions: Default::default(),
            typedefs: Default::default(),
        };
        o.typedefs.insert(typedef_fqn.into(), target);
        Registry::from_parts(vec![o], None, HashMap::new())
    }

    #[test]
    fn typedef_of_primitive_decodes_as_underlying_type() {
        // typedef uint64_t Display; — Display param decodes as uint64_t
        let reg = reg_with_typedef("a@1.0::Display", TypeRef::Primitive(Prim::U64));
        let m = method(vec![in_param(
            "display",
            TypeRef::UserDefined("a@1.0::Display".into()),
        )]);
        let val: u64 = 0xDEAD_BEEF;
        let buf = val.to_le_bytes().to_vec();
        let nodes = decode_hidl_params(&reg, 34, &m, &buf, 0, &[], &[], &[], None);
        assert_eq!(nodes.len(), 1, "expected one node, got {nodes:?}");
        assert_eq!(nodes[0].name, "display");
        assert!(
            matches!(nodes[0].value, DecodedValue::U64(v) if v == val),
            "expected U64({val:#x}), got {:?}",
            nodes[0].value
        );
    }

    #[test]
    fn typedef_of_int32_decodes_correctly() {
        // typedef int32_t Config;
        let reg = reg_with_typedef("a@1.0::Config", TypeRef::Primitive(Prim::I32));
        let m = method(vec![in_param(
            "config",
            TypeRef::UserDefined("a@1.0::Config".into()),
        )]);
        let val: i32 = -7;
        let buf = val.to_le_bytes().to_vec();
        let nodes = decode_hidl_params(&reg, 34, &m, &buf, 0, &[], &[], &[], None);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "config");
        assert!(
            matches!(nodes[0].value, DecodedValue::I64(v) if v == val as i64),
            "expected I64({}), got {:?}",
            val,
            nodes[0].value
        );
    }

    #[test]
    fn typedef_unknown_keeps_raw_tail() {
        // a UserDefined that is not a typedef, enum, or parcelable → raw tail
        let reg = empty_reg();
        let m = method(vec![in_param(
            "x",
            TypeRef::UserDefined("a@1.0::Unknown".into()),
        )]);
        let buf = [0u8; 8];
        let nodes = decode_hidl_params(&reg, 34, &m, &buf, 0, &[], &[], &[], None);
        assert_eq!(nodes.len(), 1);
        assert!(
            matches!(
                &nodes[0].value,
                DecodedValue::RawTail { reason } if reason == "hidl aggregate not yet supported"
            ),
            "expected RawTail, got {:?}",
            nodes[0].value
        );
    }

    #[test]
    fn two_typedef_params_both_decoded() {
        // onVsync_2_4(Display display, int64_t timestamp, VsyncPeriodNanos vsyncPeriodNanos)
        // Display = uint64_t, VsyncPeriodNanos = int64_t
        let mut o = OverlayLayer {
            source_path: "t".into(),
            interfaces: Default::default(),
            enums: Default::default(),
            parcelables: Default::default(),
            unions: Default::default(),
            typedefs: Default::default(),
        };
        o.typedefs
            .insert("a@1.0::Display".into(), TypeRef::Primitive(Prim::U64));
        o.typedefs.insert(
            "a@1.0::VsyncPeriodNanos".into(),
            TypeRef::Primitive(Prim::I64),
        );
        let reg = Registry::from_parts(vec![o], None, HashMap::new());

        let m = method(vec![
            in_param("display", TypeRef::UserDefined("a@1.0::Display".into())),
            in_param("timestamp", TypeRef::Primitive(Prim::I64)),
            in_param(
                "vsyncPeriodNanos",
                TypeRef::UserDefined("a@1.0::VsyncPeriodNanos".into()),
            ),
        ]);

        let display_val: u64 = 1;
        let timestamp_val: i64 = 123_456_789;
        let vsync_val: i64 = 16_666_666;
        let mut buf = Vec::new();
        buf.extend_from_slice(&display_val.to_le_bytes());
        buf.extend_from_slice(&timestamp_val.to_le_bytes());
        buf.extend_from_slice(&vsync_val.to_le_bytes());

        let nodes = decode_hidl_params(&reg, 34, &m, &buf, 0, &[], &[], &[], None);
        assert_eq!(nodes.len(), 3, "expected 3 nodes, got {nodes:?}");
        assert_eq!(nodes[0].name, "display");
        assert!(matches!(nodes[0].value, DecodedValue::U64(1)));
        assert_eq!(nodes[1].name, "timestamp");
        assert!(matches!(nodes[1].value, DecodedValue::I64(123_456_789)));
        assert_eq!(nodes[2].name, "vsyncPeriodNanos");
        assert!(matches!(nodes[2].value, DecodedValue::I64(16_666_666)));
    }

    #[test]
    fn onvsync_2_4_bare_types_resolve_via_candidate_pkgs() {
        // onVsync_2_4(Display display, int64_t timestamp, VsyncPeriodNanos vsyncPeriodNanos)
        // Display   = uint64_t in composer@2.1::types (cross-package)
        // timestamp = int64_t  (primitive, no resolution needed)
        // VsyncPeriodNanos = uint32_t in composer@2.4::types (same package)
        // bare TypeRef::UserDefined names are resolved by candidate_pkgs.
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let reg = Registry::with_aosp_dir(repo_root.join("data/aosp"));

        let m = method(vec![
            in_param("display", TypeRef::UserDefined("Display".into())),
            in_param("timestamp", TypeRef::Primitive(Prim::I64)),
            in_param(
                "vsyncPeriodNanos",
                TypeRef::UserDefined("VsyncPeriodNanos".into()),
            ),
        ]);

        let candidate_pkgs = vec![
            "android.hardware.graphics.composer@2.4".to_string(),
            "android.hardware.graphics.composer@2.1".to_string(),
        ];

        let display_val: u64 = 0x0000_0000_0000_0001;
        let timestamp_val: i64 = 123_456_789_000;
        let vsync_val: u32 = 16_666_666;

        let mut buf = Vec::new();
        buf.extend_from_slice(&display_val.to_le_bytes()); // 8 bytes
        buf.extend_from_slice(&timestamp_val.to_le_bytes()); // 8 bytes
        buf.extend_from_slice(&vsync_val.to_le_bytes()); // 4 bytes

        let nodes = decode_hidl_params(&reg, 35, &m, &buf, 0, &[], &[], &candidate_pkgs, None);
        assert_eq!(nodes.len(), 3, "expected 3 decoded nodes, got {nodes:?}");
        assert_eq!(nodes[0].name, "display");
        assert!(
            matches!(nodes[0].value, DecodedValue::U64(v) if v == display_val),
            "expected U64({display_val}), got {:?}",
            nodes[0].value,
        );
        assert_eq!(nodes[1].name, "timestamp");
        assert!(
            matches!(nodes[1].value, DecodedValue::I64(v) if v == timestamp_val),
            "expected I64({timestamp_val}), got {:?}",
            nodes[1].value,
        );
        assert_eq!(nodes[2].name, "vsyncPeriodNanos");
        assert!(
            matches!(nodes[2].value, DecodedValue::U64(v) if v == vsync_val as u64),
            "expected U64({vsync_val}), got {:?}",
            nodes[2].value,
        );
    }

    // Bug B: frame-17668 onVsync_2_4 real layout.
    // token = "android.hardware.graphics.composer@2.4::IComposerCallback" (57 chars),
    // pad_to_4(58) = 60. args follow at offset 60 with NO 8-byte realignment:
    //   display (u64)           @ [60..68] = 0x0000000000000000
    //   timestamp (i64)         @ [68..76]
    //   vsyncPeriodNanos (u32)  @ [76..80] = 11111111 (≈90Hz)
    // total: 80 bytes. old code realigned display to offset 64, putting vsync at 80 = overrun.
    #[test]
    fn frame_17668_onvsync_2_4_no_overrun() {
        use crate::token::hidl_params_start;

        let reg = reg_with_typedef(
            "android.hardware.graphics.composer@2.1::Display",
            TypeRef::Primitive(Prim::U64),
        );
        let m = method(vec![
            in_param(
                "display",
                TypeRef::UserDefined("android.hardware.graphics.composer@2.1::Display".into()),
            ),
            in_param("timestamp", TypeRef::Primitive(Prim::I64)),
            in_param("vsyncPeriodNanos", TypeRef::Primitive(Prim::U32)),
        ]);

        // build the 80-byte buffer: token + display + timestamp + vsync
        let token = b"android.hardware.graphics.composer@2.4::IComposerCallback";
        let display_val: u64 = 0;
        let ts_val: i64 = 11_278_599_982_896_000;
        let vsync_val: u32 = 11_111_111;

        let mut data = Vec::new();
        data.extend_from_slice(token); // 57 bytes
        data.push(0); // null terminator (58)
        data.push(0); // pad to 4 (59)
        data.push(0); // pad to 4 (60 = params_start)
        data.extend_from_slice(&display_val.to_le_bytes()); // [60..68]
        data.extend_from_slice(&ts_val.to_le_bytes()); // [68..76]
        data.extend_from_slice(&vsync_val.to_le_bytes()); // [76..80]
        assert_eq!(data.len(), 80, "buffer must be exactly 80 bytes");

        let start = hidl_params_start(&data).unwrap();
        assert_eq!(start, 60, "token pads to 60");

        let candidate_pkgs = vec![
            "android.hardware.graphics.composer@2.4".to_string(),
            "android.hardware.graphics.composer@2.1".to_string(),
        ];
        let nodes = decode_hidl_params(&reg, 35, &m, &data, start, &[], &[], &candidate_pkgs, None);

        assert_eq!(
            nodes.len(),
            3,
            "all three params must decode; got {nodes:?}"
        );
        assert!(
            matches!(nodes[0].value, DecodedValue::U64(0)),
            "display must be 0 (primary display), got {:?}",
            nodes[0].value
        );
        assert!(
            matches!(nodes[1].value, DecodedValue::I64(v) if v == ts_val),
            "timestamp mismatch: got {:?}",
            nodes[1].value
        );
        assert!(
            matches!(nodes[2].value, DecodedValue::U64(v) if v == vsync_val as u64),
            "vsyncPeriodNanos mismatch: got {:?}",
            nodes[2].value
        );
    }

    // Bug A: top-level struct arg decoded via buffer_object + candidate_pkgs resolution.
    // onVsyncPeriodTimingChanged(Display display, VsyncPeriodChangeTimeline updatedTimeline)
    //   display (u64) at [0..8] = 0
    //   buffer_object for updatedTimeline at [8..48] (40 bytes, PTR tag)
    // VsyncPeriodChangeTimeline = { int64_t newVsyncAppliedTimeNanos, bool refreshRequired,
    //                               int64_t refreshTimeNanos } = 24 bytes (natural alignment)
    #[test]
    fn top_level_struct_arg_via_buffer_object() {
        use crate::model::Field;
        let struct_fqn = "android.hardware.graphics.composer@2.4::VsyncPeriodChangeTimeline";
        let reg = {
            let mut o = OverlayLayer {
                source_path: "t".into(),
                interfaces: Default::default(),
                enums: Default::default(),
                parcelables: Default::default(),
                unions: Default::default(),
                typedefs: Default::default(),
            };
            // Display = uint64_t
            o.typedefs.insert(
                "android.hardware.graphics.composer@2.1::Display".into(),
                TypeRef::Primitive(Prim::U64),
            );
            // VsyncPeriodChangeTimeline struct
            o.parcelables.insert(
                struct_fqn.into(),
                crate::model::Parcelable {
                    fqn: struct_fqn.into(),
                    fields: vec![
                        Field {
                            name: "newVsyncAppliedTimeNanos".into(),
                            ty: TypeRef::Primitive(Prim::I64),
                        },
                        Field {
                            name: "refreshRequired".into(),
                            ty: TypeRef::Primitive(Prim::Bool),
                        },
                        Field {
                            name: "refreshTimeNanos".into(),
                            ty: TypeRef::Primitive(Prim::I64),
                        },
                    ],
                },
            );
            Registry::from_parts(vec![o], None, HashMap::new())
        };

        let m = method(vec![
            in_param(
                "display",
                TypeRef::UserDefined("android.hardware.graphics.composer@2.1::Display".into()),
            ),
            in_param(
                "updatedTimeline",
                TypeRef::UserDefined("VsyncPeriodChangeTimeline".into()),
            ),
        ]);

        // data: display(8) + buffer_object(40)
        let mut data = Vec::new();
        data.extend_from_slice(&0u64.to_le_bytes()); // display=0 at [0..8]
        data.extend_from_slice(&buf_obj(0, 24, 0, 0)); // struct PTR at [8..48]

        let offs = offsets_buf(&[8]);

        // VsyncPeriodChangeTimeline payload (24 bytes with natural alignment):
        //   newVsyncAppliedTimeNanos (i64) at [0..8]
        //   refreshRequired (bool)         at [8] = 1
        //   padding                        at [9..16]
        //   refreshTimeNanos (i64)         at [16..24]
        let apply_ns: i64 = 999_000_000;
        let refresh_ns: i64 = 888_000_000;
        let mut struct_payload = Vec::new();
        struct_payload.extend_from_slice(&apply_ns.to_le_bytes()); // [0..8]
        struct_payload.push(1u8); // refreshRequired=true [8]
        struct_payload.extend_from_slice(&[0u8; 7]); // padding [9..16]
        struct_payload.extend_from_slice(&refresh_ns.to_le_bytes()); // [16..24]

        let payloads: Vec<(u32, Vec<u8>)> = vec![(0, struct_payload)];

        let candidate_pkgs = vec![
            "android.hardware.graphics.composer@2.4".to_string(),
            "android.hardware.graphics.composer@2.1".to_string(),
        ];
        let nodes = decode_hidl_params(
            &reg,
            35,
            &m,
            &data,
            0,
            &offs,
            &payloads,
            &candidate_pkgs,
            None,
        );

        assert_eq!(nodes.len(), 2, "expected display + struct; got {nodes:?}");
        assert_eq!(nodes[0].name, "display");
        assert!(matches!(nodes[0].value, DecodedValue::U64(0)));

        assert_eq!(nodes[1].name, "updatedTimeline");
        assert!(
            matches!(&nodes[1].value, DecodedValue::Parcelable { fqn, null: false } if fqn == struct_fqn),
            "got {:?}",
            nodes[1].value
        );
        assert_eq!(nodes[1].children.len(), 3, "struct should have 3 fields");
        assert_eq!(nodes[1].children[0].name, "newVsyncAppliedTimeNanos");
        assert!(matches!(nodes[1].children[0].value, DecodedValue::I64(v) if v == apply_ns));
        assert_eq!(nodes[1].children[1].name, "refreshRequired");
        assert!(matches!(
            nodes[1].children[1].value,
            DecodedValue::Bool(true)
        ));
        assert_eq!(nodes[1].children[2].name, "refreshTimeNanos");
        assert!(matches!(nodes[1].children[2].value, DecodedValue::I64(v) if v == refresh_ns));
    }

    // vec<handle> with 2 handles, each native_handle{version:12, numFds:1, numInts:2, ints:[a,b]}.
    // sg tree:
    //   obj0 at 0:    top-level vec bbo (no parent)
    //   obj1 at 40:   elements bbo (parent=0, parent_off=0); 2 × 16-byte slots
    //   obj2 at 80:   native_handle for elem0 (parent=1, parent_off=0)
    //   obj3 at 120:  native_handle for elem1 (parent=1, parent_off=16)
    // native_handle_t = {version=12, numFds=1, numInts=2, fd_slot=0, int_a=0xAA, int_b=0xBB}
    #[test]
    fn decodes_vec_of_handles() {
        let reg = empty_reg();
        let m = method(vec![in_param(
            "inHandles",
            TypeRef::List(Box::new(TypeRef::HidlHandle)),
        )]);

        let mut data = Vec::new();
        data.extend_from_slice(&buf_obj(0, 16, 0, 0)); // obj0
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 32, 0, 0)); // obj1
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 24, 1, 0)); // obj2
        data.extend_from_slice(&buf_obj(binder_object::HAS_PARENT, 24, 1, 16)); // obj3

        let offs = offsets_buf(&[0, 40, 80, 120]);

        // native_handle_t payload: version=12, numFds=1, numInts=2, fd_placeholder=0,
        //                          int_a=0xAA, int_b=0xBB
        let nh_payload = || -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(&12u32.to_le_bytes()); // version
            v.extend_from_slice(&1u32.to_le_bytes()); // numFds
            v.extend_from_slice(&2u32.to_le_bytes()); // numInts
            v.extend_from_slice(&0u32.to_le_bytes()); // fd placeholder
            v.extend_from_slice(&0xAAu32.to_le_bytes()); // int 0
            v.extend_from_slice(&0xBBu32.to_le_bytes()); // int 1
            v
        };

        let payloads: Vec<(u32, Vec<u8>)> = vec![
            (0, sg_payload(2)), // vec: count=2
            (1, vec![0u8; 32]), // elements: 2 × 16-byte {ptr, pad} slots
            (2, nh_payload()),  // native_handle for elem0
            (3, nh_payload()),  // native_handle for elem1
        ];

        let nodes = decode_hidl_params(&reg, 34, &m, &data, 0, &offs, &payloads, &[], None);

        assert_eq!(nodes.len(), 1, "expected one vec node, got {nodes:?}");
        assert_eq!(nodes[0].name, "inHandles");
        assert!(
            matches!(
                &nodes[0].value,
                DecodedValue::Array {
                    len: 2,
                    null: false
                }
            ),
            "got {:?}",
            nodes[0].value
        );
        assert_eq!(nodes[0].children.len(), 2, "expected 2 handle elements");

        for (i, handle_node) in nodes[0].children.iter().enumerate() {
            assert!(
                matches!(&handle_node.value, DecodedValue::Parcelable { fqn, null: false } if fqn == "native_handle"),
                "handle {i} should be native_handle parcelable, got {:?}",
                handle_node.value
            );
            let by_name: std::collections::HashMap<&str, &DecodedNode> = handle_node
                .children
                .iter()
                .map(|n| (n.name.as_str(), n))
                .collect();
            assert!(
                matches!(by_name["numFds"].value, DecodedValue::U64(1)),
                "handle {i} numFds mismatch"
            );
            assert!(
                matches!(by_name["numInts"].value, DecodedValue::U64(2)),
                "handle {i} numInts mismatch"
            );
            let ints = by_name["ints"];
            assert!(
                matches!(
                    &ints.value,
                    DecodedValue::Array {
                        len: 2,
                        null: false
                    }
                ),
                "handle {i} ints array mismatch"
            );
            assert_eq!(ints.children.len(), 2);
            assert!(
                matches!(ints.children[0].value, DecodedValue::U64(0xAA)),
                "handle {i} int[0] mismatch"
            );
            assert!(
                matches!(ints.children[1].value, DecodedValue::U64(0xBB)),
                "handle {i} int[1] mismatch"
            );
        }
    }

    #[test]
    fn set_power_mode_2_2_nested_enum_resolves_via_iface_fqn() {
        // setPowerMode_2_2(Display display, PowerMode mode) generates (Error error)
        // Display = uint64_t (typedef from @2.1::types.hal resolved via candidate_pkgs)
        // PowerMode = enum in IComposerClient body (nested type), resolved via iface_fqn
        //   when candidate_pkgs alone can't find it.
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let reg = Registry::with_aosp_dir(repo_root.join("data/aosp"));

        let m = method(vec![
            in_param("display", TypeRef::UserDefined("Display".into())),
            in_param("mode", TypeRef::UserDefined("PowerMode".into())),
        ]);

        // Display (u64) = 1, PowerMode (i32) = 2 (ON)
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u64.to_le_bytes()); // display
        buf.extend_from_slice(&2i32.to_le_bytes()); // mode = ON

        let candidate_pkgs = vec![
            "android.hardware.graphics.composer@2.2".to_string(),
            "android.hardware.graphics.composer@2.1".to_string(),
        ];
        let iface_fqn = "android.hardware.graphics.composer@2.2::IComposerClient";

        let nodes = decode_hidl_params(
            &reg,
            36,
            &m,
            &buf,
            0,
            &[],
            &[],
            &candidate_pkgs,
            Some(iface_fqn),
        );
        assert_eq!(nodes.len(), 2, "expected 2 nodes, got {nodes:?}");
        assert_eq!(nodes[0].name, "display");
        assert!(
            matches!(nodes[0].value, DecodedValue::U64(1)),
            "expected display=U64(1), got {:?}",
            nodes[0].value
        );
        assert_eq!(nodes[1].name, "mode");
        // PowerMode is decoded as an enum: repr 2 = ON
        assert!(
            matches!(nodes[1].value, DecodedValue::Enum { repr: 2, .. }),
            "expected Enum(repr=2), got {:?}",
            nodes[1].value
        );
    }
}
