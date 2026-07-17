// Hand-written decoders for common framework Java Parcelables passed as AIDL args
// via Parcel.writeTypedObject. The caller (decode.rs) reads the int32 presence flag;
// the bodies here start at the parcelable's own writeToParcel output.

use crate::decode::{
    decode_bundle_body, decode_parcelable, node, DecodedNode, DecodedValue, ParcelCursor,
};
use crate::registry::Registry;

// dispatch a framework parcelable body by fqn. `start` is the value start (before the
// presence flag the caller already consumed), so the node spans the whole field. reg/sdk/
// depth are only needed by the container types (ParceledListSlice) that recurse into
// other parcelables; the self-contained ones ignore them.
pub(crate) fn body(
    reg: &Registry,
    sdk: u32,
    cur: &mut ParcelCursor,
    fqn: &str,
    start: usize,
    depth: u32,
) -> Option<DecodedNode> {
    match fqn.rsplit('.').next().unwrap_or(fqn) {
        "ComponentName" => component_name(cur, start),
        "Uri" => uri(cur, start),
        "UserHandle" => user_handle(cur, start),
        "WorkSource" => work_source(cur, start),
        "Message" => message(reg, sdk, cur, start, depth),
        "ParceledListSlice" => parceled_list_slice(reg, sdk, cur, start, depth),
        _ => None,
    }
}

pub(crate) fn is_framework_parcelable(fqn: &str) -> bool {
    matches!(
        fqn,
        "android.content.ComponentName"
            | "android.net.Uri"
            | "android.os.UserHandle"
            | "android.os.WorkSource"
            | "android.os.Message"
            | "android.content.pm.ParceledListSlice"
            | "com.android.modules.utils.ParceledListSlice"
    )
}

// a DecodedNode with an explicit field name (framework bodies build named children).
fn named(
    name: &str,
    value: DecodedValue,
    label: &str,
    start: usize,
    len: usize,
    children: Vec<DecodedNode>,
) -> DecodedNode {
    let mut n = node(value, label, start, len, children);
    n.name = name.to_string();
    n
}

// Parcel.writeIntArray: int32 count (-1 = null) then that many int32.
fn int_array(name: &str, cur: &mut ParcelCursor) -> Option<DecodedNode> {
    let start = cur.pos;
    let count = cur.read_i32()?;
    if count < 0 {
        let len = cur.pos - start;
        return Some(named(
            name,
            DecodedValue::Array { len: 0, null: true },
            "int[]",
            start,
            len,
            vec![],
        ));
    }
    let mut children = Vec::with_capacity((count as usize).min(1024));
    for _ in 0..count {
        let fs = cur.pos;
        let v = cur.read_i32()?;
        children.push(node(DecodedValue::I64(v as i64), "int", fs, 4, vec![]));
    }
    let n = count as usize;
    let len = cur.pos - start;
    Some(named(
        name,
        DecodedValue::Array {
            len: n,
            null: false,
        },
        "int[]",
        start,
        len,
        children,
    ))
}

// Parcel.writeStringArray: int32 count (-1 = null) then that many String16.
fn string_array(name: &str, cur: &mut ParcelCursor) -> Option<DecodedNode> {
    let start = cur.pos;
    let count = cur.read_i32()?;
    if count < 0 {
        let len = cur.pos - start;
        return Some(named(
            name,
            DecodedValue::Array { len: 0, null: true },
            "String[]",
            start,
            len,
            vec![],
        ));
    }
    let mut children = Vec::with_capacity((count as usize).min(1024));
    for _ in 0..count {
        let fs = cur.pos;
        let s = cur.read_string16()?;
        children.push(node(
            DecodedValue::Str(s),
            "String",
            fs,
            cur.pos - fs,
            vec![],
        ));
    }
    let n = count as usize;
    let len = cur.pos - start;
    Some(named(
        name,
        DecodedValue::Array {
            len: n,
            null: false,
        },
        "String[]",
        start,
        len,
        children,
    ))
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

// Uri.writeToParcel: int32 type id, then the body. NULL_TYPE_ID (0) is a null Uri;
// StringUri (1), OpaqueUri (2) and HierarchicalUri (3) all write the full URI as a
// single String8 of toString() (frameworks/base android.net.Uri; the 2/3 subclasses
// stopped writing split parts long ago — readFrom reparses the String8).
fn uri(cur: &mut ParcelCursor, start: usize) -> Option<DecodedNode> {
    let type_id = cur.read_i32()?;
    let val = match type_id {
        0 => DecodedValue::Str(None),
        1..=3 => DecodedValue::Str(cur.read_string8()?),
        _ => return None,
    };
    Some(node(val, "Uri", start, cur.pos - start, vec![]))
}

// UserHandle.writeToParcel: a single int32 user id (mHandle). -1 = USER_ALL, 0 = system.
fn user_handle(cur: &mut ParcelCursor, start: usize) -> Option<DecodedNode> {
    let id = cur.read_i32()?;
    Some(node(
        DecodedValue::I64(id as i64),
        "UserHandle",
        start,
        cur.pos - start,
        vec![],
    ))
}

// WorkSource.writeToParcel (frameworks/base android.os.WorkSource): int32 mNum,
// int[] mUids, String[] mNames, then the work-chain block: int32 chain-count
// (-1 = no chains) and, when present, a writeParcelableList of WorkChains. Each
// WorkChain is itself int32 mSize, int[] mUids, String[] mTags.
fn work_source(cur: &mut ParcelCursor, start: usize) -> Option<DecodedNode> {
    let mut children = Vec::new();
    let num_start = cur.pos;
    let num = cur.read_i32()?;
    children.push(named(
        "mNum",
        DecodedValue::I64(num as i64),
        "int",
        num_start,
        4,
        vec![],
    ));
    children.push(int_array("uids", cur)?);
    children.push(string_array("names", cur)?);

    // work chains: a null chain list writes a single writeInt(-1). A non-null list writes
    // writeInt(mChains.size()) then writeParcelableList, which writes its own writeInt(size)
    // again followed by one writeParcelable per chain. writeParcelable writes the element
    // class name (String16, null = -1) then the body — NOT a writeTypedObject presence flag.
    // The common case is null (-1); the double count only appears for a present (possibly
    // empty) list.
    let chain_start = cur.pos;
    let chain_count = cur.read_i32()?;
    if chain_count >= 0 {
        let mut chain_kids = Vec::with_capacity((chain_count as usize).min(1024));
        let list_count = cur.read_i32()?; // writeParcelableList's own size
        for _ in 0..list_count.max(0) {
            let cs = cur.pos;
            match cur.read_string16()? {
                None => chain_kids.push(named(
                    "WorkChain",
                    DecodedValue::Parcelable {
                        fqn: "WorkChain".to_string(),
                        null: true,
                    },
                    "WorkChain",
                    cs,
                    cur.pos - cs,
                    vec![],
                )),
                Some(_) => chain_kids.push(work_chain(cur, cs)?),
            }
        }
        children.push(named(
            "chains",
            DecodedValue::Array {
                len: chain_kids.len(),
                null: false,
            },
            "WorkChain[]",
            chain_start,
            cur.pos - chain_start,
            chain_kids,
        ));
    }
    Some(node(
        DecodedValue::Parcelable {
            fqn: "android.os.WorkSource".to_string(),
            null: false,
        },
        "WorkSource",
        start,
        cur.pos - start,
        children,
    ))
}

// WorkSource.WorkChain.writeToParcel: int32 mSize, int[] mUids, String[] mTags.
fn work_chain(cur: &mut ParcelCursor, start: usize) -> Option<DecodedNode> {
    let sz_start = cur.pos;
    let size = cur.read_i32()?;
    let children = vec![
        named(
            "mSize",
            DecodedValue::I64(size as i64),
            "int",
            sz_start,
            4,
            vec![],
        ),
        int_array("uids", cur)?,
        string_array("tags", cur)?,
    ];
    Some(node(
        DecodedValue::Parcelable {
            fqn: "WorkChain".to_string(),
            null: false,
        },
        "WorkChain",
        start,
        cur.pos - start,
        children,
    ))
}

// Message.writeToParcel (frameworks/base android.os.Message): int32 what, arg1, arg2;
// int32 obj-present flag (1 -> writeParcelable obj); int64 when; writeBundle data; then
// a reserved int32 word; then Messenger replyTo (a strong binder or null via
// writeStrongBinder); int32 sendingUid, workSourceUid.
//
// The reserved word sits between the Bundle blob and the Messenger flat_binder_object on
// every observed Android-17 frame (value 0, always exactly 4 bytes, independent of
// alignment). It is not emitted by any line of Message/Bundle/writeBundle/writeStrongBinder
// in the AOSP tree we could trace; it is treated as reserved and confirmed empirically —
// with it, sendingUid/workSourceUid land correctly across every Message in the corpus.
fn message(
    reg: &Registry,
    sdk: u32,
    cur: &mut ParcelCursor,
    start: usize,
    depth: u32,
) -> Option<DecodedNode> {
    let mut children = Vec::new();
    for name in ["what", "arg1", "arg2"] {
        let fs = cur.pos;
        let v = cur.read_i32()?;
        children.push(named(
            name,
            DecodedValue::I64(v as i64),
            "int",
            fs,
            4,
            vec![],
        ));
    }
    // obj: writeInt(1) + writeParcelable(p) when non-null, else writeInt(0).
    let obj_start = cur.pos;
    match cur.read_i32()? {
        0 => {}
        1 => {
            // writeParcelable = String16 class name (writeParcelableCreator) + writeToParcel.
            let name = cur.read_string16()??;
            let mut child = decode_parcelable(reg, sdk, cur, &name, cur.pos, depth + 1)?;
            child.name = "obj".to_string();
            child.start = obj_start;
            child.len = cur.pos - obj_start;
            children.push(child);
        }
        _ => return None,
    }
    let when_start = cur.pos;
    let when = cur.read_i64()?;
    children.push(named(
        "when",
        DecodedValue::I64(when),
        "long",
        when_start,
        8,
        vec![],
    ));
    // data: Parcel.writeBundle (int32 length, -1 = null, else BNDL magic + map).
    let mut data = decode_bundle_body(reg, sdk, cur, "Bundle", cur.pos, depth + 1)?;
    data.name = "data".to_string();
    children.push(data);
    cur.skip(4)?; // reserved word (see fn comment)
                  // replyTo: Messenger.writeMessengerOrNullToParcel writes a strong binder or null.
    let rt_start = cur.pos;
    let (handle, strong) = cur.read_binder_object()?;
    children.push(named(
        "replyTo",
        DecodedValue::Binder { handle, strong },
        "Messenger",
        rt_start,
        cur.pos - rt_start,
        vec![],
    ));
    for name in ["sendingUid", "workSourceUid"] {
        let fs = cur.pos;
        let v = cur.read_i32()?;
        children.push(named(
            name,
            DecodedValue::I64(v as i64),
            "int",
            fs,
            4,
            vec![],
        ));
    }
    Some(node(
        DecodedValue::Parcelable {
            fqn: "android.os.Message".to_string(),
            null: false,
        },
        "Message",
        start,
        cur.pos - start,
        children,
    ))
}

// BaseParceledListSlice.writeToParcel: int32 N; if N > 0, the element class name
// (writeParcelableCreator -> String16) then, per inlined element, int32 1 + the
// element's writeToParcel body. A terminal int32 0 marks a truncated list whose tail
// is streamed over a retriever binder — we stop there. Elements only decode if their
// type is a structured parcelable in the corpus; an undecodable element ends the walk
// but the envelope (type + count) is still surfaced.
fn parceled_list_slice(
    reg: &Registry,
    sdk: u32,
    cur: &mut ParcelCursor,
    start: usize,
    depth: u32,
) -> Option<DecodedNode> {
    let count = cur.read_i32()?;
    let mut children = Vec::new();
    let mut elem_fqn = String::new();
    if count > 0 {
        elem_fqn = cur.read_string16()?.unwrap_or_default();
        for _ in 0..count {
            match cur.read_i32()? {
                1 => {
                    let es = cur.pos;
                    match decode_parcelable(reg, sdk, cur, &elem_fqn, es, depth + 1) {
                        Some(child) => children.push(child),
                        None => break, // element type not modelled; stop but keep the envelope
                    }
                }
                _ => break, // 0 = truncated (retriever binder follows) or malformed
            }
        }
    }
    let label = if elem_fqn.is_empty() {
        "ParceledListSlice".to_string()
    } else {
        format!(
            "ParceledListSlice<{}>",
            elem_fqn.rsplit('.').next().unwrap()
        )
    };
    Some(node(
        DecodedValue::Array {
            len: count.max(0) as usize,
            null: count < 0,
        },
        &label,
        start,
        cur.pos - start,
        children,
    ))
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

    // real HierarchicalUri param wire (frame with checkUriPermission): int32 type=3 +
    // String8 of the whole uri (types 1/2/3 all write toString() as a String8).
    #[test]
    fn uri_hierarchical_is_string8() {
        let mut buf = 3i32.to_le_bytes().to_vec();
        buf.extend(s8("content://media/external/images/media/33"));
        let mut cur = ParcelCursor::new(&buf, 0);
        let n = uri(&mut cur, 0).unwrap();
        assert!(
            matches!(&n.value, DecodedValue::Str(Some(s)) if s == "content://media/external/images/media/33")
        );
        assert_eq!(cur.pos, buf.len());
    }

    #[test]
    fn uri_null() {
        let buf = 0i32.to_le_bytes().to_vec();
        let mut cur = ParcelCursor::new(&buf, 0);
        let n = uri(&mut cur, 0).unwrap();
        assert!(matches!(&n.value, DecodedValue::Str(None)));
        assert_eq!(cur.pos, 4);
    }

    // UserHandle.writeToParcel is a single int32 (real wire from
    // ILauncherApps.shouldHideFromSuggestions: userId 0).
    #[test]
    fn user_handle_single_int() {
        let buf = 10i32.to_le_bytes().to_vec();
        let mut cur = ParcelCursor::new(&buf, 0);
        let n = user_handle(&mut cur, 0).unwrap();
        assert!(matches!(&n.value, DecodedValue::I64(10)));
        assert_eq!(cur.pos, 4);
    }

    // WorkSource with no chains: mNum, int[] uids, String[] names, chain-count -1.
    #[test]
    fn work_source_no_chains() {
        let mut buf = 2i32.to_le_bytes().to_vec(); // mNum
        buf.extend(2i32.to_le_bytes()); // uids count
        buf.extend(1000i32.to_le_bytes());
        buf.extend(1001i32.to_le_bytes());
        buf.extend((-1i32).to_le_bytes()); // names = null
        buf.extend((-1i32).to_le_bytes()); // chains = none
        let mut cur = ParcelCursor::new(&buf, 0);
        let n = work_source(&mut cur, 0).unwrap();
        assert_eq!(cur.pos, buf.len());
        assert_eq!(n.children[0].name, "mNum");
        let uids = &n.children[1];
        assert_eq!(uids.name, "uids");
        assert!(matches!(uids.value, DecodedValue::Array { len: 2, .. }));
        assert!(matches!(uids.children[0].value, DecodedValue::I64(1000)));
        assert!(matches!(
            n.children[2].value,
            DecodedValue::Array { null: true, .. }
        ));
    }

    // WorkSource with one WorkChain (real IPowerManager.acquireWakeLock wire shape):
    // the chain block is writeInt(mChains.size) then writeParcelableList's own writeInt(N)
    // and, per chain, writeParcelable = String16 class name + WorkChain body.
    #[test]
    fn work_source_with_chain() {
        let mut buf = 0i32.to_le_bytes().to_vec(); // mNum
        buf.extend(1i32.to_le_bytes()); // uids count
        buf.extend(10280i32.to_le_bytes()); // uid
        buf.extend((-1i32).to_le_bytes()); // names = null
        buf.extend(1i32.to_le_bytes()); // mChains.size()
        buf.extend(1i32.to_le_bytes()); // writeParcelableList count
        buf.extend(s16("android.os.WorkSource$WorkChain")); // writeParcelableCreator
        buf.extend(1i32.to_le_bytes()); // WorkChain mSize
        buf.extend(1i32.to_le_bytes()); // WorkChain uids count
        buf.extend(10280i32.to_le_bytes());
        buf.extend(1i32.to_le_bytes()); // WorkChain tags count
        buf.extend(s16("com.example"));
        let mut cur = ParcelCursor::new(&buf, 0);
        let n = work_source(&mut cur, 0).unwrap();
        assert_eq!(cur.pos, buf.len());
        let chains = n.children.iter().find(|c| c.name == "chains").unwrap();
        assert!(matches!(chains.value, DecodedValue::Array { len: 1, .. }));
        assert_eq!(chains.children[0].children[0].name, "mSize");
    }

    #[test]
    fn int_array_null() {
        let buf = (-1i32).to_le_bytes().to_vec();
        let mut cur = ParcelCursor::new(&buf, 0);
        let n = int_array("x", &mut cur).unwrap();
        assert!(matches!(n.value, DecodedValue::Array { null: true, .. }));
        assert_eq!(cur.pos, 4);
    }

    // Message with a null obj, empty data Bundle, the reserved word, a null Messenger
    // (inline flat_binder_object with binder=0), and the two trailing uids — the shape
    // seen on IMessenger.send. Exercises the reserved-word skip and full field walk.
    #[test]
    fn message_full_walk() {
        use crate::registry::Registry;
        let mut buf = Vec::new();
        buf.extend(6i32.to_le_bytes()); // what
        buf.extend(0i32.to_le_bytes()); // arg1
        buf.extend(0i32.to_le_bytes()); // arg2
        buf.extend(0i32.to_le_bytes()); // obj = null
        buf.extend(0i64.to_le_bytes()); // when
        buf.extend(0i32.to_le_bytes()); // writeBundle: length 0 (empty bundle)
        buf.extend(0i32.to_le_bytes()); // reserved word
                                        // null strong binder: flat_binder_object with type BINDER, binder=0 (no offset).
        buf.extend(0x7362_2a85u32.to_le_bytes()); // hdr.type = BINDER
        buf.extend(0i32.to_le_bytes()); // flags
        buf.extend(0i64.to_le_bytes()); // binder = 0 (null)
        buf.extend(0i64.to_le_bytes()); // cookie
        buf.extend(0i32.to_le_bytes()); // stability trailer
        buf.extend((-1i32).to_le_bytes()); // sendingUid
        buf.extend((-1i32).to_le_bytes()); // workSourceUid
        let reg = Registry::empty();
        let mut cur = ParcelCursor::new(&buf, 0);
        let n = message(&reg, 37, &mut cur, 0, 0).unwrap();
        assert_eq!(cur.pos, buf.len());
        let by = |name: &str| n.children.iter().find(|c| c.name == name).unwrap();
        assert!(matches!(by("what").value, DecodedValue::I64(6)));
        assert!(matches!(by("data").value, DecodedValue::Bundle { .. }));
        assert!(matches!(
            by("replyTo").value,
            DecodedValue::Binder { handle: 0, .. }
        ));
        assert!(matches!(by("sendingUid").value, DecodedValue::I64(-1)));
        assert!(matches!(by("workSourceUid").value, DecodedValue::I64(-1)));
    }
}
