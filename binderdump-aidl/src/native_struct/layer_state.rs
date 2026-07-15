// Native decoders for the ISurfaceComposer / SurfaceFlinger struct family — layer_state_t and
// the small geometry structs it embeds (matrix22_t, FrameTimelineInfo, FloatRect crop). front-half
// variants are branched on sdk; every field is verified against per-sdk frameworks/native sources.

use crate::decode::{depth_exceeded, node, DecodedNode, DecodedValue, ParcelCursor};

// matrix22_t::write(Parcel&): 4 consecutive writeFloat calls, no header.
// android15-release LayerState.cpp ~line 770–775. spec §7.
// fields in order: dsdx, dtdx, dtdy, dsdy.
pub(super) fn matrix22(cur: &mut ParcelCursor, start: usize, depth: u32) -> Option<DecodedNode> {
    if depth_exceeded(depth) {
        return None;
    }
    let mut children = Vec::with_capacity(4);
    for name in ["dsdx", "dtdx", "dtdy", "dsdy"] {
        let fs = cur.pos;
        let v = cur.read_f32()?;
        let mut child = node(DecodedValue::F64(v as f64), "float", fs, 4, vec![]);
        child.name = name.to_string();
        children.push(child);
    }
    Some(node(
        DecodedValue::Parcelable {
            fqn: "matrix22_t".to_string(),
            null: false,
        },
        "matrix22_t",
        start,
        cur.pos - start,
        children,
    ))
}

// FrameTimelineInfo (AIDL structured parcelable, written directly via writeToParcel — no presence flag).
// android15-release FrameTimelineInfo.aidl. spec §2.
// wire: [i32 aidl_size (incl itself)][i64 vsyncId][i32 inputEventId][i64 startTimeNanos]
//       [i32 useForRefreshRateSelection][i64 skippedFrameVsyncId][i64 skippedFrameStartTimeNanos].
// computed size = 44 bytes; always resyncs to aidl_size boundary for forward compat.
pub(super) fn frame_timeline_info(
    cur: &mut ParcelCursor,
    start: usize,
    depth: u32,
) -> Option<DecodedNode> {
    if depth_exceeded(depth) {
        return None;
    }
    let aidl_start = cur.pos;
    let raw_size = cur.read_i32()?;
    if raw_size < 4 {
        return None;
    }
    let end = aidl_start + raw_size as usize;
    if end > cur.buf_len() {
        return None;
    }
    let mut children = Vec::new();
    macro_rules! guard_read {
        ($read:expr, $label:expr, $name:expr, $val:expr) => {
            if cur.pos < end {
                let fs = cur.pos;
                if let Some(v) = $read {
                    let mut c = node($val(v), $label, fs, cur.pos - fs, vec![]);
                    c.name = $name.to_string();
                    children.push(c);
                }
            }
        };
    }
    guard_read!(cur.read_i64(), "long", "vsyncId", DecodedValue::I64);
    guard_read!(cur.read_i32(), "int", "inputEventId", |v: i32| {
        DecodedValue::I64(v as i64)
    });
    guard_read!(cur.read_i64(), "long", "startTimeNanos", DecodedValue::I64);
    guard_read!(
        cur.read_i32(),
        "int",
        "useForRefreshRateSelection",
        |v: i32| DecodedValue::I64(v as i64)
    );
    guard_read!(
        cur.read_i64(),
        "long",
        "skippedFrameVsyncId",
        DecodedValue::I64
    );
    guard_read!(
        cur.read_i64(),
        "long",
        "skippedFrameStartTimeNanos",
        DecodedValue::I64
    );
    cur.seek(end)?;
    Some(node(
        DecodedValue::Parcelable {
            fqn: "FrameTimelineInfo".to_string(),
            null: false,
        },
        "FrameTimelineInfo",
        start,
        cur.pos - start,
        children,
    ))
}

// FloatRect crop: 4 floats, written in order top/left/bottom/right.
// verified from android16-release LayerState.cpp writeFloat calls.
fn crop_floats(cur: &mut ParcelCursor, start: usize, depth: u32) -> Option<DecodedNode> {
    if depth_exceeded(depth) {
        return None;
    }
    let mut children = Vec::with_capacity(4);
    for nm in ["top", "left", "bottom", "right"] {
        let fs = cur.pos;
        let v = cur.read_f32()?;
        let mut c = node(DecodedValue::F64(v as f64), "float", fs, 4, vec![]);
        c.name = nm.to_string();
        children.push(c);
    }
    Some(node(
        DecodedValue::Parcelable {
            fqn: "FloatRect".to_string(),
            null: false,
        },
        "FloatRect",
        start,
        cur.pos - start,
        children,
    ))
}

// layer_state_t::write(Parcel&) — front-half branched on sdk; raw-tail from field 12.
// all front-half positions written unconditionally; no what-gating. spec §3.
// dispatched as "ComposerState" | "layer_state_t".
//
// sdk 33 (android13-release LayerState.cpp):
//   surface, layerId, what(u64), x, y, z, w(u32), h(u32), layerStack.id, alpha(f32),
//   flags, mask, matrix22, crop(Rect i32×4).
// sdk 34/35 baseline (android15-release LayerState.cpp):
//   surface, layerId, what(u64), x, y, z, layerStack.id, flags, mask, matrix22,
//   crop(Rect i32×4).
// sdk 36 (android16-release LayerState.cpp):
//   same as baseline but crop = FloatRect (f32×4, order: top/left/bottom/right).
// sdk 37 (android17-release LayerState.cpp):
//   what = LayerChangedSet = BitSet<65> = std::array<uint64_t,2>; written via
//   output.write(what.data(), what.dataSize()) = 16 bytes raw, no length prefix.
//   crop = FloatRect (same as sdk 36).
// unknown sdk: falls through to {34,35} baseline.
pub(super) fn layer_state(
    sdk: u32,
    cur: &mut ParcelCursor,
    start: usize,
    depth: u32,
) -> Option<DecodedNode> {
    if depth_exceeded(depth) {
        return None;
    }
    let mut children = Vec::new();

    // 1: surface — strongbinder (layer handle)
    {
        let bs = cur.pos;
        let (handle, strong) = cur.read_binder_object()?;
        let mut c = node(
            DecodedValue::Binder { handle, strong },
            "IBinder",
            bs,
            cur.pos - bs,
            vec![],
        );
        c.name = "surface".to_string();
        children.push(c);
    }
    // 2: layerId — int32
    {
        let fs = cur.pos;
        let v = cur.read_i32()?;
        let mut c = node(DecodedValue::I64(v as i64), "int", fs, 4, vec![]);
        c.name = "layerId".to_string();
        children.push(c);
    }
    // 3: what — sdk 37: 16-byte raw blob (BitSet<65> = 2×u64, no length prefix);
    //           others: uint64 dirty-flags bitmask, always written unconditionally.
    match sdk {
        37 => {
            let fs = cur.pos;
            cur.skip(16)?;
            let mut c = node(DecodedValue::Bytes, "raw", fs, 16, vec![]);
            c.name = "what".to_string();
            children.push(c);
        }
        _ => {
            let fs = cur.pos;
            let v = cur.read_u64()?;
            let mut c = node(DecodedValue::U64(v), "long", fs, 8, vec![]);
            c.name = "what".to_string();
            children.push(c);
        }
    }
    // 4: x — float
    {
        let fs = cur.pos;
        let v = cur.read_f32()?;
        let mut c = node(DecodedValue::F64(v as f64), "float", fs, 4, vec![]);
        c.name = "x".to_string();
        children.push(c);
    }
    // 5: y — float
    {
        let fs = cur.pos;
        let v = cur.read_f32()?;
        let mut c = node(DecodedValue::F64(v as f64), "float", fs, 4, vec![]);
        c.name = "y".to_string();
        children.push(c);
    }
    // 6: z — int32 (layer Z order)
    {
        let fs = cur.pos;
        let v = cur.read_i32()?;
        let mut c = node(DecodedValue::I64(v as i64), "int", fs, 4, vec![]);
        c.name = "z".to_string();
        children.push(c);
    }
    // sdk 33: w(u32) and h(u32) inserted between z and layerStack.id
    if sdk == 33 {
        let fs = cur.pos;
        let v = cur.read_u32()?;
        let mut c = node(DecodedValue::U64(v as u64), "int", fs, 4, vec![]);
        c.name = "w".to_string();
        children.push(c);

        let fs = cur.pos;
        let v = cur.read_u32()?;
        let mut c = node(DecodedValue::U64(v as u64), "int", fs, 4, vec![]);
        c.name = "h".to_string();
        children.push(c);
    }
    // 7: layerStack.id — uint32
    {
        let fs = cur.pos;
        let v = cur.read_u32()?;
        let mut c = node(DecodedValue::U64(v as u64), "int", fs, 4, vec![]);
        c.name = "layerStack.id".to_string();
        children.push(c);
    }
    // sdk 33: alpha(f32) inserted between layerStack.id and flags
    if sdk == 33 {
        let fs = cur.pos;
        let v = cur.read_f32()?;
        let mut c = node(DecodedValue::F64(v as f64), "float", fs, 4, vec![]);
        c.name = "alpha".to_string();
        children.push(c);
    }
    // 8: flags — uint32 (eLayer* constants)
    {
        let fs = cur.pos;
        let v = cur.read_u32()?;
        let mut c = node(DecodedValue::U64(v as u64), "int", fs, 4, vec![]);
        c.name = "flags".to_string();
        children.push(c);
    }
    // 9: mask — uint32
    {
        let fs = cur.pos;
        let v = cur.read_u32()?;
        let mut c = node(DecodedValue::U64(v as u64), "int", fs, 4, vec![]);
        c.name = "mask".to_string();
        children.push(c);
    }
    // 10: matrix — matrix22_t (4 floats dsdx/dtdx/dtdy/dsdy, no header; spec §7)
    {
        let ms = cur.pos;
        let mut mn = matrix22(cur, ms, depth + 1)?;
        mn.name = "matrix".to_string();
        children.push(mn);
    }
    // 11: crop — Rect (4×i32) for sdk <= 35; FloatRect (4×f32) for sdk >= 36
    {
        let rs = cur.pos;
        let mut rn = if sdk >= 36 {
            crop_floats(cur, rs, depth + 1)?
        } else {
            super::rect(cur, rs, depth + 1)?
        };
        rn.name = "crop".to_string();
        children.push(rn);
    }
    // fields 12+ are build-variant and diverge by sdk/build; raw-tail the remainder.
    {
        let rs = cur.pos;
        let rem = cur.buf_len().saturating_sub(rs);
        if rem > 0 {
            cur.skip(rem)?;
            let mut tail = node(DecodedValue::Bytes, "raw", rs, rem, vec![]);
            tail.name = "back_half".to_string();
            children.push(tail);
        }
    }
    Some(node(
        DecodedValue::Parcelable {
            fqn: "layer_state_t".to_string(),
            null: false,
        },
        "layer_state_t",
        start,
        cur.pos - start,
        children,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::ParcelCursor;
    use crate::registry::Registry;

    fn call(fqn: &str, buf: &[u8]) -> Option<DecodedNode> {
        let reg = Registry::empty();
        let mut cur = ParcelCursor::new(buf, 0);
        super::super::decode(&reg, 35, &mut cur, fqn, 0, 0)
    }

    fn call_with_offsets(fqn: &str, buf: &[u8], offsets: &[u8]) -> Option<DecodedNode> {
        let reg = Registry::empty();
        let mut cur = ParcelCursor::new(buf, 0).with_offsets(offsets);
        super::super::decode(&reg, 35, &mut cur, fqn, 0, 0)
    }

    fn call_sdk(sdk: u32, fqn: &str, buf: &[u8], offsets: &[u8]) -> Option<DecodedNode> {
        let reg = Registry::empty();
        let mut cur = ParcelCursor::new(buf, 0).with_offsets(offsets);
        super::super::decode(&reg, sdk, &mut cur, fqn, 0, 0)
    }

    // append a flat_binder_object (BINDER type, strong local binder) plus its int32
    // stability trailer to buf. returns the byte offset where the object starts (for
    // the offsets array).
    fn push_binder(buf: &mut Vec<u8>, value: u64) -> usize {
        let off = buf.len();
        buf.extend_from_slice(&crate::binder_object::BINDER.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.extend_from_slice(&value.to_le_bytes()); // binder ptr
        buf.extend_from_slice(&0u64.to_le_bytes()); // cookie
        buf.extend_from_slice(&0i32.to_le_bytes()); // stability trailer
        off
    }

    // encode a vec of byte offsets as 8-byte LE entries (binder_size_t format)
    fn offsets_bytes(positions: &[usize]) -> Vec<u8> {
        let mut v = Vec::new();
        for &p in positions {
            v.extend_from_slice(&(p as u64).to_le_bytes());
        }
        v
    }

    // matrix22_t: 4 floats dsdx, dtdx, dtdy, dsdy (spec §7)
    #[test]
    fn decodes_matrix22() {
        let mut buf = Vec::new();
        for v in [1.0f32, 0.5, 0.25, 2.0] {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        let n = call("matrix22_t", &buf).unwrap();
        assert!(matches!(
            &n.value,
            DecodedValue::Parcelable { fqn, null: false } if fqn == "matrix22_t"
        ));
        assert_eq!(n.children.len(), 4);
        assert_eq!(n.children[0].name, "dsdx");
        assert!(matches!(n.children[0].value, DecodedValue::F64(v) if (v - 1.0).abs() < 1e-6));
        assert_eq!(n.children[1].name, "dtdx");
        assert_eq!(n.children[2].name, "dtdy");
        assert_eq!(n.children[3].name, "dsdy");
        assert!(matches!(n.children[3].value, DecodedValue::F64(v) if (v - 2.0).abs() < 1e-6));
        assert_eq!(n.len, 16);
    }

    // Rect: 4 i32 left, top, right, bottom — no header (LightFlattenable-fixed)
    #[test]
    fn decodes_rect() {
        let mut buf = Vec::new();
        for v in [10i32, 20, 100, 200] {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        let n = call("Rect", &buf).unwrap();
        assert!(matches!(
            &n.value,
            DecodedValue::Parcelable { fqn, null: false } if fqn == "Rect"
        ));
        assert_eq!(n.children.len(), 4);
        assert_eq!(n.children[0].name, "left");
        assert!(matches!(n.children[0].value, DecodedValue::I64(10)));
        assert_eq!(n.children[1].name, "top");
        assert!(matches!(n.children[1].value, DecodedValue::I64(20)));
        assert_eq!(n.children[2].name, "right");
        assert!(matches!(n.children[2].value, DecodedValue::I64(100)));
        assert_eq!(n.children[3].name, "bottom");
        assert!(matches!(n.children[3].value, DecodedValue::I64(200)));
        assert_eq!(n.len, 16);
    }

    // FrameTimelineInfo: nominal decode — aidl_size=44, all 6 fields present. spec §2.
    // wire: [i32 44][i64 vsyncId=-1][i32 inputEventId=0][i64 startTimeNanos=1000000]
    //       [i32 useForRefreshRateSelection=0][i64 skippedFrameVsyncId=-1][i64 skippedFrameStartTimeNanos=0]
    #[test]
    fn decodes_frame_timeline_info() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&44i32.to_le_bytes()); // aidl_size (incl itself) = 44
        buf.extend_from_slice(&(-1i64).to_le_bytes()); // vsyncId = INVALID_VSYNC_ID
        buf.extend_from_slice(&0i32.to_le_bytes()); // inputEventId
        buf.extend_from_slice(&1_000_000i64.to_le_bytes()); // startTimeNanos
        buf.extend_from_slice(&0i32.to_le_bytes()); // useForRefreshRateSelection
        buf.extend_from_slice(&(-1i64).to_le_bytes()); // skippedFrameVsyncId
        buf.extend_from_slice(&0i64.to_le_bytes()); // skippedFrameStartTimeNanos
        let n = call("FrameTimelineInfo", &buf).unwrap();
        assert!(matches!(
            &n.value,
            DecodedValue::Parcelable { fqn, null: false } if fqn == "FrameTimelineInfo"
        ));
        // aidl_size field itself(4) + 6 fields: 8+4+8+4+8+8 = 40; total = 44
        assert_eq!(n.len, 44);
        assert_eq!(n.children.len(), 6);
        assert_eq!(n.children[0].name, "vsyncId");
        assert!(matches!(n.children[0].value, DecodedValue::I64(-1)));
        assert_eq!(n.children[1].name, "inputEventId");
        assert!(matches!(n.children[1].value, DecodedValue::I64(0)));
        assert_eq!(n.children[2].name, "startTimeNanos");
        assert!(matches!(n.children[2].value, DecodedValue::I64(1_000_000)));
        assert_eq!(n.children[3].name, "useForRefreshRateSelection");
        assert!(matches!(n.children[3].value, DecodedValue::I64(0)));
        assert_eq!(n.children[4].name, "skippedFrameVsyncId");
        assert!(matches!(n.children[4].value, DecodedValue::I64(-1)));
        assert_eq!(n.children[5].name, "skippedFrameStartTimeNanos");
        assert!(matches!(n.children[5].value, DecodedValue::I64(0)));
    }

    // FrameTimelineInfo: forward compat — aidl_size=52 has 8 extra bytes; cursor resyncs past them.
    #[test]
    fn frame_timeline_info_forward_compat_resync() {
        let sentinel = 0x1234_5678i32;
        let mut buf = Vec::new();
        buf.extend_from_slice(&52i32.to_le_bytes()); // aidl_size = 52 (8 extra bytes)
        buf.extend_from_slice(&(-1i64).to_le_bytes()); // vsyncId
        buf.extend_from_slice(&0i32.to_le_bytes()); // inputEventId
        buf.extend_from_slice(&0i64.to_le_bytes()); // startTimeNanos
        buf.extend_from_slice(&0i32.to_le_bytes()); // useForRefreshRateSelection
        buf.extend_from_slice(&(-1i64).to_le_bytes()); // skippedFrameVsyncId
        buf.extend_from_slice(&0i64.to_le_bytes()); // skippedFrameStartTimeNanos
        buf.extend_from_slice(&0xDEAD_BEEFu64.to_le_bytes()); // future unknown field (8 bytes)
        buf.extend_from_slice(&sentinel.to_le_bytes()); // sentinel after block

        let reg = Registry::empty();
        let mut cur = ParcelCursor::new(&buf, 0);
        let n = super::super::decode(&reg, 35, &mut cur, "FrameTimelineInfo", 0, 0).unwrap();
        assert_eq!(n.children.len(), 6);
        // cursor must sit at offset 52 (start of sentinel)
        assert_eq!(cur.pos, 52);
        assert_eq!(cur.read_i32().unwrap(), sentinel);
    }

    // FrameTimelineInfo: invalid aidl_size < 4 returns None.
    #[test]
    fn frame_timeline_info_invalid_size_returns_none() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&3i32.to_le_bytes()); // aidl_size < 4, invalid
        assert!(call("FrameTimelineInfo", &buf).is_none());
    }

    // layer_state_t: front-half decode (fields 1–11 verified, back half raw-tailed).
    // verifies surface binder, layerId, what, geometry scalars, matrix, crop — and that
    // back_half raw node covers everything after crop with cursor at buf end.
    #[test]
    fn layer_state_front_half_and_raw_tail() {
        let mut buf = Vec::new();
        let b0 = push_binder(&mut buf, 0xA1); // 1: surface
        buf.extend_from_slice(&42i32.to_le_bytes()); // 2: layerId
        buf.extend_from_slice(&0xDEAD_CAFEu64.to_le_bytes()); // 3: what
        buf.extend_from_slice(&1.5f32.to_le_bytes()); // 4: x
        buf.extend_from_slice(&2.5f32.to_le_bytes()); // 5: y
        buf.extend_from_slice(&3i32.to_le_bytes()); // 6: z
        buf.extend_from_slice(&1u32.to_le_bytes()); // 7: layerStack.id
        buf.extend_from_slice(&0u32.to_le_bytes()); // 8: flags
        buf.extend_from_slice(&0u32.to_le_bytes()); // 9: mask
        for v in [1.0f32, 0.0, 0.0, 1.0] {
            // 10: matrix22_t
            buf.extend_from_slice(&v.to_le_bytes());
        }
        for v in [0i32, 0, 100, 200] {
            // 11: crop Rect
            buf.extend_from_slice(&v.to_le_bytes());
        }
        // back half: 40 bytes of build-variant data — should appear as raw tail
        let back_half_len = 40usize;
        buf.extend_from_slice(&vec![0xBBu8; back_half_len]);

        let offsets = offsets_bytes(&[b0]);
        let n = call_with_offsets("layer_state_t", &buf, &offsets).unwrap();
        assert!(matches!(
            &n.value,
            DecodedValue::Parcelable { fqn, null: false } if fqn == "layer_state_t"
        ));
        // total length = front (28+4+8+4+4+4+4+4+4+16+16=96; the surface binder is a
        // 24-byte flat_binder_object plus its 4-byte stability trailer) + back_half
        assert_eq!(n.len, 96 + back_half_len);

        let f = |name: &str| n.children.iter().find(|c| c.name == name).unwrap();
        assert!(matches!(
            f("surface").value,
            DecodedValue::Binder {
                handle: 0xA1,
                strong: true
            }
        ));
        assert!(matches!(f("layerId").value, DecodedValue::I64(42)));
        assert!(matches!(f("what").value, DecodedValue::U64(0xDEAD_CAFE)));
        assert!(matches!(f("x").value, DecodedValue::F64(v) if (v - 1.5f64).abs() < 1e-5));
        assert!(matches!(f("y").value, DecodedValue::F64(v) if (v - 2.5f64).abs() < 1e-5));
        assert!(matches!(f("z").value, DecodedValue::I64(3)));
        assert!(matches!(f("layerStack.id").value, DecodedValue::U64(1)));

        let crop = f("crop");
        assert!(matches!(&crop.value, DecodedValue::Parcelable { fqn, .. } if fqn == "Rect"));
        assert_eq!(crop.len, 16);

        // raw tail
        let tail = f("back_half");
        assert_eq!(tail.len, back_half_len);
        assert!(matches!(tail.value, DecodedValue::Bytes));
    }

    // sdk 33: w(u32)+h(u32) after z; alpha(f32) after layerStack.id; crop as int Rect.
    // verified from android13-release LayerState.cpp.
    #[test]
    fn layer_state_sdk33_front_half() {
        let mut buf = Vec::new();
        let b0 = push_binder(&mut buf, 0xA1); // 1: surface
        buf.extend_from_slice(&1i32.to_le_bytes()); // 2: layerId
        buf.extend_from_slice(&0xDEAD_CAFEu64.to_le_bytes()); // 3: what (u64 on sdk 33)
        buf.extend_from_slice(&1.0f32.to_le_bytes()); // 4: x
        buf.extend_from_slice(&2.0f32.to_le_bytes()); // 5: y
        buf.extend_from_slice(&3i32.to_le_bytes()); // 6: z
        buf.extend_from_slice(&800u32.to_le_bytes()); // 7: w (sdk 33)
        buf.extend_from_slice(&600u32.to_le_bytes()); // 8: h (sdk 33)
        buf.extend_from_slice(&1u32.to_le_bytes()); // 9: layerStack.id
        buf.extend_from_slice(&0.5f32.to_le_bytes()); // 10: alpha (sdk 33)
        buf.extend_from_slice(&0u32.to_le_bytes()); // 11: flags
        buf.extend_from_slice(&0u32.to_le_bytes()); // 12: mask
        for v in [1.0f32, 0.0, 0.0, 1.0] {
            buf.extend_from_slice(&v.to_le_bytes()); // 13: matrix22_t
        }
        for v in [0i32, 0, 100, 200] {
            buf.extend_from_slice(&v.to_le_bytes()); // 14: crop Rect (ints)
        }

        let offsets = offsets_bytes(&[b0]);
        let n = call_sdk(33, "layer_state_t", &buf, &offsets).unwrap();

        let f = |name: &str| n.children.iter().find(|c| c.name == name).unwrap();
        assert!(matches!(f("w").value, DecodedValue::U64(800)));
        assert!(matches!(f("h").value, DecodedValue::U64(600)));
        assert!(matches!(f("alpha").value, DecodedValue::F64(v) if (v - 0.5f64).abs() < 1e-5));

        let crop = f("crop");
        assert!(matches!(&crop.value, DecodedValue::Parcelable { fqn, .. } if fqn == "Rect"));
        assert_eq!(crop.len, 16);
        // crop children are ints
        assert!(matches!(crop.children[0].value, DecodedValue::I64(0)));
    }

    // sdk 36: crop decoded as 4 floats (FloatRect); no w/h/alpha; what is still u64.
    // verified from android16-release LayerState.cpp writeFloat calls (top/left/bottom/right).
    #[test]
    fn layer_state_sdk36_front_half() {
        let mut buf = Vec::new();
        let b0 = push_binder(&mut buf, 0xA2); // 1: surface
        buf.extend_from_slice(&2i32.to_le_bytes()); // 2: layerId
        buf.extend_from_slice(&0x1111u64.to_le_bytes()); // 3: what (u64)
        buf.extend_from_slice(&0.0f32.to_le_bytes()); // 4: x
        buf.extend_from_slice(&0.0f32.to_le_bytes()); // 5: y
        buf.extend_from_slice(&0i32.to_le_bytes()); // 6: z
        buf.extend_from_slice(&0u32.to_le_bytes()); // 7: layerStack.id
        buf.extend_from_slice(&0u32.to_le_bytes()); // 8: flags
        buf.extend_from_slice(&0u32.to_le_bytes()); // 9: mask
        for v in [1.0f32, 0.0, 0.0, 1.0] {
            buf.extend_from_slice(&v.to_le_bytes()); // 10: matrix22_t
        }
        // 11: crop as FloatRect (top, left, bottom, right)
        buf.extend_from_slice(&1.5f32.to_le_bytes()); // top
        buf.extend_from_slice(&2.5f32.to_le_bytes()); // left
        buf.extend_from_slice(&3.5f32.to_le_bytes()); // bottom
        buf.extend_from_slice(&4.5f32.to_le_bytes()); // right

        let offsets = offsets_bytes(&[b0]);
        let n = call_sdk(36, "layer_state_t", &buf, &offsets).unwrap();

        let f = |name: &str| n.children.iter().find(|c| c.name == name);
        // no sdk-33 extra fields
        assert!(f("w").is_none());
        assert!(f("h").is_none());
        assert!(f("alpha").is_none());

        let crop = f("crop").unwrap();
        assert!(matches!(&crop.value, DecodedValue::Parcelable { fqn, .. } if fqn == "FloatRect"));
        assert_eq!(crop.len, 16);
        let top = crop.children.iter().find(|c| c.name == "top").unwrap();
        assert!(matches!(top.value, DecodedValue::F64(v) if (v - 1.5f64).abs() < 1e-5));
    }

    // sdk 37: what decoded as 16-byte raw blob (BitSet<65> = 2×u64); crop as FloatRect.
    // verified: LayerChangedSet = BitSet<65> in android17-release LayerState.h;
    // BitSet<65>::dataSize() = 2*sizeof(uint64_t) = 16 from android17-release BitSet.h;
    // written via output.write(what.data(), what.dataSize()) — no length prefix.
    #[test]
    fn layer_state_sdk37_front_half() {
        let mut buf = Vec::new();
        let b0 = push_binder(&mut buf, 0xA3); // 1: surface
        buf.extend_from_slice(&3i32.to_le_bytes()); // 2: layerId
                                                    // 3: what — 16-byte blob (BitSet<65>, 2×u64)
        buf.extend_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes()); // word 0
        buf.extend_from_slice(&0x1234_5678_9ABC_DEF0u64.to_le_bytes()); // word 1
        buf.extend_from_slice(&0.0f32.to_le_bytes()); // 4: x
        buf.extend_from_slice(&0.0f32.to_le_bytes()); // 5: y
        buf.extend_from_slice(&0i32.to_le_bytes()); // 6: z
        buf.extend_from_slice(&0u32.to_le_bytes()); // 7: layerStack.id
        buf.extend_from_slice(&0u32.to_le_bytes()); // 8: flags
        buf.extend_from_slice(&0u32.to_le_bytes()); // 9: mask
        for v in [1.0f32, 0.0, 0.0, 1.0] {
            buf.extend_from_slice(&v.to_le_bytes()); // 10: matrix22_t
        }
        // 11: crop as FloatRect (top, left, bottom, right)
        buf.extend_from_slice(&10.0f32.to_le_bytes()); // top
        buf.extend_from_slice(&20.0f32.to_le_bytes()); // left
        buf.extend_from_slice(&30.0f32.to_le_bytes()); // bottom
        buf.extend_from_slice(&40.0f32.to_le_bytes()); // right

        let offsets = offsets_bytes(&[b0]);
        let n = call_sdk(37, "layer_state_t", &buf, &offsets).unwrap();

        let f = |name: &str| n.children.iter().find(|c| c.name == name).unwrap();

        // what is a raw blob of 16 bytes
        let what = f("what");
        assert!(matches!(what.value, DecodedValue::Bytes));
        assert_eq!(what.len, 16);

        // crop is FloatRect
        let crop = f("crop");
        assert!(matches!(&crop.value, DecodedValue::Parcelable { fqn, .. } if fqn == "FloatRect"));
        let top = crop.children.iter().find(|c| c.name == "top").unwrap();
        assert!(matches!(top.value, DecodedValue::F64(v) if (v - 10.0f64).abs() < 1e-5));
    }
}
