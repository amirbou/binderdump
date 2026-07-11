// Decoder for android.content.Intent — a hand-written Java Parcelable (writeToParcel, no size
// header). Field order + encodings verified against frameworks/base Intent.java (android13-17)
// and real payloads. Dispatched from decode.rs's UserDefined arm (which consumes the
// writeTypedObject presence flag first). The extras Bundle reuses decode.rs's shared decoder.

use crate::decode::{depth_exceeded, node, DecodedNode, DecodedValue, ParcelCursor};
use crate::registry::Registry;

fn intent_parent(children: Vec<DecodedNode>, start: usize, end: usize) -> DecodedNode {
    node(
        DecodedValue::Parcelable {
            fqn: "android.content.Intent".to_string(),
            null: false,
        },
        "Intent",
        start,
        end - start,
        children,
    )
}

// android.content.Intent body (no writeTypedObject presence flag — the caller consumes it).
// Field order + encodings verified against frameworks/base Intent.java (android13-17) and real
// sdk35 payloads. mExtendedFlags (field 6) exists only sdk>=35. Strings are String8 (writeString8,
// API>=30 — all supported SDKs); ComponentName stays String16. clipData is variable-length and
// unmodeled: if present, decode stops there. extras is decoded via the shared Bundle decoder.
pub(crate) fn intent_body(
    reg: &Registry,
    sdk: u32,
    cur: &mut ParcelCursor,
    start: usize,
    depth: u32,
) -> Option<DecodedNode> {
    if depth_exceeded(depth) {
        return None;
    }
    let mut children: Vec<DecodedNode> = Vec::new();

    macro_rules! str8 {
        ($name:expr) => {{
            let fs = cur.pos;
            let s = cur.read_string8()?;
            let mut c = node(DecodedValue::Str(s), "String", fs, cur.pos - fs, vec![]);
            c.name = $name.to_string();
            children.push(c);
        }};
    }
    macro_rules! int_field {
        ($name:expr) => {{
            let fs = cur.pos;
            let v = cur.read_i32()?;
            let mut c = node(DecodedValue::I64(v as i64), "int", fs, 4, vec![]);
            c.name = $name.to_string();
            children.push(c);
        }};
    }

    str8!("action");

    // data (Uri): int32 type-id. 0=null; 1/2/3 (StringUri/OpaqueUri/HierarchicalUri) each write
    // exactly one String8 (writeInt(TYPE_ID) + writeString8(toString()) — Uri.java android15).
    // Any other id is unexpected: stop rather than misread a String8 length from mid-stream.
    {
        let fs = cur.pos;
        let tid = cur.read_i32()?;
        match tid {
            0 => {
                let mut c = node(DecodedValue::Str(None), "Uri", fs, cur.pos - fs, vec![]);
                c.name = "data".to_string();
                children.push(c);
            }
            1 | 2 | 3 => {
                let s = cur.read_string8()?;
                let mut c = node(DecodedValue::Str(s), "Uri", fs, cur.pos - fs, vec![]);
                c.name = "data".to_string();
                children.push(c);
            }
            _ => {
                let mut c = node(
                    DecodedValue::RawTail {
                        reason: format!("unexpected Uri type-id {}", tid),
                    },
                    "Uri",
                    fs,
                    cur.pos - fs,
                    vec![],
                );
                c.name = "data".to_string();
                children.push(c);
                return Some(intent_parent(children, start, cur.pos));
            }
        }
    }

    str8!("type");
    str8!("identifier");
    int_field!("flags");
    if sdk >= 35 {
        int_field!("extendedFlags");
    }
    str8!("package");

    // component (ComponentName): String16 package + String16 class; null via String16 len -1.
    {
        let fs = cur.pos;
        let val = match cur.read_string16()? {
            None => DecodedValue::Str(None),
            Some(pkg) => {
                let class = cur.read_string16()?.unwrap_or_default();
                DecodedValue::Str(Some(format!("{}/{}", pkg, class)))
            }
        };
        let mut c = node(val, "ComponentName", fs, cur.pos - fs, vec![]);
        c.name = "component".to_string();
        children.push(c);
    }

    // sourceBounds: int32 presence + Rect (4 ints).
    if cur.read_i32()? == 1 {
        let rs = cur.pos;
        if let Some(mut r) = super::rect(cur, rs, depth + 1) {
            r.name = "sourceBounds".to_string();
            children.push(r);
        }
    }

    // categories: int32 count + N x String8.
    {
        let n = cur.read_i32()?;
        if n > 0 {
            let cs = cur.pos;
            let mut cats: Vec<DecodedNode> = Vec::new();
            for i in 0..n {
                let fs = cur.pos;
                let s = cur.read_string8()?;
                let mut c = node(DecodedValue::Str(s), "String", fs, cur.pos - fs, vec![]);
                c.name = format!("[{}]", i);
                cats.push(c);
            }
            let mut parent = node(
                DecodedValue::Array {
                    len: n as usize,
                    null: false,
                },
                "categories",
                cs,
                cur.pos - cs,
                cats,
            );
            parent.name = "categories".to_string();
            children.push(parent);
        }
    }

    // selector: int32 presence + recursive Intent.
    if cur.read_i32()? == 1 {
        let ss = cur.pos;
        match intent_body(reg, sdk, cur, ss, depth + 1) {
            Some(mut sel) => {
                sel.name = "selector".to_string();
                children.push(sel);
            }
            None => return Some(intent_parent(children, start, cur.pos)),
        }
    }

    // clipData: int32 presence. ClipData is variable-length and unmodeled; if present, stop.
    if cur.read_i32()? == 1 {
        let mut c = node(
            DecodedValue::RawTail {
                reason: "clipData present (not decoded)".to_string(),
            },
            "ClipData",
            cur.pos,
            0,
            vec![],
        );
        c.name = "clipData".to_string();
        children.push(c);
        return Some(intent_parent(children, start, cur.pos));
    }

    int_field!("contentUserHint");

    // extras: Bundle (shared decoder handles length + magic + arraymap). A well-formed Bundle
    // always resyncs to its block end; None means a truncated/malformed parcel, so keep the
    // front half rather than collapsing the whole Intent.
    {
        let bs = cur.pos;
        match crate::decode::decode_bundle_body(reg, sdk, cur, "extras", bs, depth + 1) {
            Some(mut b) => {
                b.name = "extras".to_string();
                children.push(b);
            }
            None => return Some(intent_parent(children, start, cur.pos)),
        }
    }

    // originalIntent: int32 presence + recursive Intent. Non-fatal: a trailing overrun here
    // still yields the decoded front half.
    if let Some(1) = cur.read_i32() {
        let os = cur.pos;
        if let Some(mut oi) = intent_body(reg, sdk, cur, os, depth + 1) {
            oi.name = "originalIntent".to_string();
            children.push(oi);
        }
    }

    Some(intent_parent(children, start, cur.pos))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::ParcelCursor;
    use crate::registry::Registry;

    // --- Intent wire-format builders ---
    fn s8(s: &str) -> Vec<u8> {
        let mut v = (s.len() as i32).to_le_bytes().to_vec();
        v.extend_from_slice(s.as_bytes());
        v.push(0); // NUL
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }
    fn s8_null() -> Vec<u8> {
        (-1i32).to_le_bytes().to_vec()
    }
    fn s16(s: &str) -> Vec<u8> {
        let units: Vec<u16> = s.encode_utf16().collect();
        let mut v = (units.len() as i32).to_le_bytes().to_vec();
        for u in &units {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v.extend_from_slice(&0u16.to_le_bytes()); // NUL
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }
    fn i(n: i32) -> Vec<u8> {
        n.to_le_bytes().to_vec()
    }

    // Intent body for the given sdk: action "a.b.C", null data/type/id/package,
    // component pkg/cls, no bounds/categories/selector/clipData, contentUserHint -2,
    // empty extras bundle, no originalIntent. mExtendedFlags present only on sdk>=35.
    fn intent_bytes(sdk: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(s8("a.b.C")); // action
        b.extend(i(0)); // data: null Uri
        b.extend(s8_null()); // type
        b.extend(s8_null()); // identifier
        b.extend(i(0x10)); // flags
        if sdk >= 35 {
            b.extend(i(0)); // extendedFlags
        }
        b.extend(s8_null()); // package
        b.extend(s16("pkg")); // component package
        b.extend(s16("cls")); // component class
        b.extend(i(0)); // sourceBounds absent
        b.extend(i(0)); // categories count 0
        b.extend(i(0)); // selector absent
        b.extend(i(0)); // clipData absent
        b.extend(i(-2)); // contentUserHint (USER_CURRENT)
        b.extend(i(0)); // extras: empty bundle (len 0)
        b.extend(i(0)); // originalIntent absent
        b
    }

    fn child<'a>(n: &'a DecodedNode, name: &str) -> Option<&'a DecodedNode> {
        n.children.iter().find(|c| c.name == name)
    }

    #[test]
    fn decodes_intent_sdk35() {
        let reg = Registry::empty();
        let buf = intent_bytes(35);
        let mut cur = ParcelCursor::new(&buf, 0);
        let n = intent_body(&reg, 35, &mut cur, 0, 0).expect("intent decodes");
        assert_eq!(cur.pos, buf.len(), "consumed whole body");
        assert!(
            matches!(&n.value, DecodedValue::Parcelable { fqn, null: false } if fqn == "android.content.Intent")
        );
        assert!(
            matches!(&child(&n, "action").unwrap().value, DecodedValue::Str(Some(s)) if s == "a.b.C")
        );
        assert!(
            matches!(&child(&n, "component").unwrap().value, DecodedValue::Str(Some(s)) if s == "pkg/cls")
        );
        assert!(matches!(
            &child(&n, "data").unwrap().value,
            DecodedValue::Str(None)
        ));
        assert!(matches!(
            &child(&n, "contentUserHint").unwrap().value,
            DecodedValue::I64(-2)
        ));
        assert!(child(&n, "extras").is_some());
        assert!(child(&n, "extendedFlags").is_some());
    }

    #[test]
    fn decodes_intent_sdk33_has_no_extended_flags() {
        let reg = Registry::empty();
        let buf = intent_bytes(33);
        let mut cur = ParcelCursor::new(&buf, 0);
        let n = intent_body(&reg, 33, &mut cur, 0, 0).expect("intent decodes");
        assert_eq!(cur.pos, buf.len(), "sdk33 body stays aligned");
        assert!(child(&n, "extendedFlags").is_none());
        // fields after the missing extendedFlags must still align
        assert!(
            matches!(&child(&n, "component").unwrap().value, DecodedValue::Str(Some(s)) if s == "pkg/cls")
        );
    }

    #[test]
    fn intent_typed_object_null_presence() {
        // through the public param decoder + the decode.rs UserDefined arm: a Java-backend
        // Intent param with writeTypedObject presence flag 0 decodes to a null Intent.
        use crate::model::{Direction, Method, Parameter, TypeRef};
        let reg = Registry::empty();
        let m = Method {
            name: "m".into(),
            params: vec![Parameter {
                name: "intent".into(),
                ty: TypeRef::UserDefined("android.content.Intent".into()),
                direction: Direction::In,
            }],
            return_type: None,
            oneway: true,
            code: None,
        };
        let buf = i(0); // presence = 0
        let nodes = crate::decode::decode_aidl_params(&reg, 35, &m, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert!(matches!(
            &nodes[0].value,
            DecodedValue::Parcelable { null: true, .. }
        ));
    }

    #[test]
    fn intent_decodes_string_uri_and_categories() {
        // non-null data (StringUri type-id 1 + String8) and a categories list.
        let reg = Registry::empty();
        let mut b = Vec::new();
        b.extend(s8("a")); // action
        b.extend(i(1)); // data type-id = StringUri
        b.extend(s8("content://x/y")); // uri string
        b.extend(s8_null()); // type
        b.extend(s8_null()); // identifier
        b.extend(i(0)); // flags
        b.extend(i(0)); // extendedFlags (sdk35)
        b.extend(s8_null()); // package
        b.extend(i(-1)); // component null (String16 len -1)
        b.extend(i(0)); // sourceBounds absent
        b.extend(i(2)); // categories count = 2
        b.extend(s8("android.intent.category.DEFAULT"));
        b.extend(s8("android.intent.category.BROWSABLE"));
        b.extend(i(0)); // selector absent
        b.extend(i(0)); // clipData absent
        b.extend(i(0)); // contentUserHint
        b.extend(i(0)); // extras empty bundle
        b.extend(i(0)); // originalIntent absent
        let mut cur = ParcelCursor::new(&b, 0);
        let n = intent_body(&reg, 35, &mut cur, 0, 0).expect("intent decodes");
        assert_eq!(cur.pos, b.len());
        assert!(
            matches!(&child(&n, "data").unwrap().value, DecodedValue::Str(Some(s)) if s == "content://x/y")
        );
        let cats = child(&n, "categories").unwrap();
        assert!(matches!(&cats.value, DecodedValue::Array { len: 2, .. }));
        assert!(
            matches!(&cats.children[0].value, DecodedValue::Str(Some(s)) if s.contains("DEFAULT"))
        );
    }

    #[test]
    fn intent_decodes_nested_selector() {
        let reg = Registry::empty();
        let mut b = Vec::new();
        b.extend(s8("outer")); // action
        b.extend(i(0)); // data null
        b.extend(s8_null()); // type
        b.extend(s8_null()); // identifier
        b.extend(i(0)); // flags
        b.extend(i(0)); // extendedFlags
        b.extend(s8_null()); // package
        b.extend(i(-1)); // component null
        b.extend(i(0)); // sourceBounds absent
        b.extend(i(0)); // categories 0
        b.extend(i(1)); // selector PRESENT
        b.extend(intent_bytes(35)); // nested Intent (action "a.b.C")
        b.extend(i(0)); // clipData absent
        b.extend(i(0)); // contentUserHint
        b.extend(i(0)); // extras empty
        b.extend(i(0)); // originalIntent absent
        let mut cur = ParcelCursor::new(&b, 0);
        let n = intent_body(&reg, 35, &mut cur, 0, 0).expect("intent decodes");
        assert_eq!(cur.pos, b.len(), "nested selector stays aligned");
        let sel = child(&n, "selector").unwrap();
        assert!(
            matches!(&child(sel, "action").unwrap().value, DecodedValue::Str(Some(s)) if s == "a.b.C")
        );
    }

    #[test]
    fn intent_clipdata_present_stops() {
        let reg = Registry::empty();
        let mut b = Vec::new();
        b.extend(s8("act"));
        b.extend(i(0)); // data null
        b.extend(s8_null()); // type
        b.extend(s8_null()); // identifier
        b.extend(i(0)); // flags
        b.extend(i(0)); // extendedFlags (sdk35)
        b.extend(s8_null()); // package
        b.extend(i(-1)); // component null (String16 len -1)
        b.extend(i(0)); // sourceBounds absent
        b.extend(i(0)); // categories 0
        b.extend(i(0)); // selector absent
        b.extend(i(1)); // clipData PRESENT -> stop
        b.extend(i(999)); // garbage that must NOT be read
        let mut cur = ParcelCursor::new(&b, 0);
        let n = intent_body(&reg, 35, &mut cur, 0, 0).expect("partial intent");
        let cd = child(&n, "clipData").unwrap();
        assert!(
            matches!(&cd.value, DecodedValue::RawTail { reason } if reason.contains("clipData"))
        );
        assert!(
            child(&n, "contentUserHint").is_none(),
            "stopped before contentUserHint"
        );
    }
}
