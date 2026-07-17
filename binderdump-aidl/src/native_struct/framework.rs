// Hand-written decoders for common framework Java Parcelables passed as AIDL args
// via Parcel.writeTypedObject. The caller (decode.rs) reads the int32 presence flag;
// the bodies here start at the parcelable's own writeToParcel output.

use crate::decode::{node, DecodedNode, DecodedValue, ParcelCursor};

// dispatch a framework parcelable body by fqn. `start` is the value start (before the
// presence flag the caller already consumed), so the node spans the whole field.
pub(crate) fn body(cur: &mut ParcelCursor, fqn: &str, start: usize) -> Option<DecodedNode> {
    match fqn.rsplit('.').next().unwrap_or(fqn) {
        "ComponentName" => component_name(cur, start),
        "Uri" => uri(cur, start),
        _ => None,
    }
}

pub(crate) fn is_framework_parcelable(fqn: &str) -> bool {
    matches!(fqn, "android.content.ComponentName" | "android.net.Uri")
}

// ComponentName.writeToParcel: String16 package + String16 class. Rendered as
// "package/class" to match how the framework logs it.
fn component_name(cur: &mut ParcelCursor, start: usize) -> Option<DecodedNode> {
    let val = match cur.read_string16()? {
        None => DecodedValue::Str(None),
        Some(pkg) => match cur.read_string16()? {
            Some(class) => DecodedValue::Str(Some(format!("{}/{}", pkg, class))),
            None => DecodedValue::Str(Some(pkg)),
        },
    };
    Some(node(val, "ComponentName", start, cur.pos - start, vec![]))
}

// Uri.writeToParcel: int32 type id, then a type-specific body. StringUri (1) writes
// the whole URI as a String8; NULL_TYPE_ID (0) is a null Uri. OpaqueUri (2) and
// HierarchicalUri (3) split the URI into parts and are not modelled here.
fn uri(cur: &mut ParcelCursor, start: usize) -> Option<DecodedNode> {
    let type_id = cur.read_i32()?;
    let val = match type_id {
        0 => DecodedValue::Str(None),
        1 => DecodedValue::Str(cur.read_string8()?),
        _ => return None,
    };
    Some(node(val, "Uri", start, cur.pos - start, vec![]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s16(s: &str) -> Vec<u8> {
        let u: Vec<u16> = s.encode_utf16().collect();
        let mut b = (u.len() as i32).to_le_bytes().to_vec();
        for c in &u {
            b.extend_from_slice(&c.to_le_bytes());
        }
        b.extend_from_slice(&[0, 0]); // u16 NUL
        while b.len() % 4 != 0 {
            b.push(0);
        }
        b
    }

    fn s8(s: &str) -> Vec<u8> {
        let mut b = (s.len() as i32).to_le_bytes().to_vec();
        b.extend_from_slice(s.as_bytes());
        b.push(0); // NUL
        while b.len() % 4 != 0 {
            b.push(0);
        }
        b
    }

    // real ComponentName return wire (frame 599, IActivityManager.startService):
    // String16 package + String16 class, rendered "package/class".
    #[test]
    fn component_name_pkg_class() {
        let mut buf = s16("com.google.android.gms");
        buf.extend(s16("com.google.android.gms.Foo"));
        let mut cur = ParcelCursor::new(&buf, 0);
        let n = component_name(&mut cur, 0).unwrap();
        assert!(
            matches!(&n.value, DecodedValue::Str(Some(s)) if s == "com.google.android.gms/com.google.android.gms.Foo")
        );
        assert_eq!(cur.pos, buf.len());
    }

    // real Uri param wire (frame 28, IContentService.registerContentObserver):
    // int32 type=1 (StringUri) + String8 uri.
    #[test]
    fn uri_string_uri() {
        let mut buf = 1i32.to_le_bytes().to_vec();
        buf.extend(s8("content://call_log"));
        let mut cur = ParcelCursor::new(&buf, 0);
        let n = uri(&mut cur, 0).unwrap();
        assert!(matches!(&n.value, DecodedValue::Str(Some(s)) if s == "content://call_log"));
        assert_eq!(cur.pos, buf.len());
    }
}
