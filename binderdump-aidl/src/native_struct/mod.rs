// Hand-written decoders for native C++ structs that use bespoke write(Parcel&) layouts
// (not the AIDL convention). Dispatched by the final segment of a UserDefined type's fqn.
// The per-family decoders live in the submodules; `rect` is shared (layer_state geometry and
// Intent.sourceBounds both decode an android.graphics.Rect).

mod intent;
mod layer_state;

pub(crate) use intent::intent_body;

use crate::decode::{depth_exceeded, node, DecodedNode, DecodedValue, ParcelCursor};
use crate::registry::Registry;

// dispatch a UserDefined type to its hand-written decoder; None if not a known native struct.
pub fn decode(
    reg: &Registry,
    sdk: u32,
    cur: &mut ParcelCursor,
    fqn: &str,
    start: usize,
    depth: u32,
) -> Option<DecodedNode> {
    let _ = reg;
    match fqn.rsplit('.').next().unwrap_or(fqn) {
        "matrix22_t" => layer_state::matrix22(cur, start, depth),
        "Rect" => rect(cur, start, depth),
        "FrameTimelineInfo" => layer_state::frame_timeline_info(cur, start, depth),
        "ComposerState" | "layer_state_t" => layer_state::layer_state(sdk, cur, start, depth),
        _ => None,
    }
}

// Rect (LightFlattenable-fixed): 16 B raw, no header.
// android15-release: left, top, right, bottom as int32. spec §3 rows 11/55/56.
pub(super) fn rect(cur: &mut ParcelCursor, start: usize, depth: u32) -> Option<DecodedNode> {
    if depth_exceeded(depth) {
        return None;
    }
    let mut children = Vec::with_capacity(4);
    for name in ["left", "top", "right", "bottom"] {
        let fs = cur.pos;
        let v = cur.read_i32()?;
        let mut child = node(DecodedValue::I64(v as i64), "int", fs, 4, vec![]);
        child.name = name.to_string();
        children.push(child);
    }
    Some(node(
        DecodedValue::Parcelable {
            fqn: "Rect".to_string(),
            null: false,
        },
        "Rect",
        start,
        cur.pos - start,
        children,
    ))
}
