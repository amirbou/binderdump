// android.gui.ListenerStats — the parameter of ITransactionComposerListener::onTransactionCompleted.
// In android15 ListenerStats/TransactionStats/CallbackId are Parcelables (writeToParcel, standard
// 4-byte Parcel encoding — NOT Flattenable). Source: frameworks/native/libs/gui/
// ITransactionCompletedListener.cpp (android15-release), ListenerStats/TransactionStats/CallbackId
// ::writeToParcel. Verified byte-for-byte against real captures.
//
// Only the front half is decodable. Per TransactionStats: the callbackIds vector (id + type) and
// latchTime are fixed. The presentFence (sp<Fence>, FD-carrying) and the SurfaceStats vector
// (each starts with a strong binder + more Fences, plus a build/aconfig-variant eventStats) are
// not modeled — the decoder stops at the presentFence flag and raw-tails the remainder.

use crate::decode::{depth_exceeded, node, DecodedNode, DecodedValue, ParcelCursor};

// bound the count-prefixed loops so a corrupt/hostile parcel can't spin.
const MAX_ENTRIES: i32 = 256;

pub(super) fn listener_stats(
    cur: &mut ParcelCursor,
    start: usize,
    depth: u32,
) -> Option<DecodedNode> {
    if depth_exceeded(depth) {
        return None;
    }
    // The ListenerStats param is written via writeParcelable: int32 non-null flag then the body.
    if cur.read_i32()? == 0 {
        return Some(node(
            DecodedValue::Parcelable {
                fqn: "android.gui.ListenerStats".to_string(),
                null: true,
            },
            "ListenerStats",
            start,
            cur.pos - start,
            vec![],
        ));
    }

    let mut children: Vec<DecodedNode> = Vec::new();

    // ListenerStats: int32 count of TransactionStats, then each via writeParcelable.
    let count = cur.read_i32()?;
    let mut num = node(
        DecodedValue::I64(count as i64),
        "int",
        cur.pos - 4,
        4,
        vec![],
    );
    num.name = "num_transaction_stats".to_string();
    children.push(num);

    // Decode the first TransactionStats' fixed front half. Later entries and the variant tail
    // (fence, surfaceStats) fall into back_half — TransactionStats has no size header, so once we
    // reach the fence we can't find the next boundary.
    if count > 0 {
        let ts_start = cur.pos;
        let _nonnull = cur.read_i32()?; // TransactionStats writeParcelable flag
        let mut ts_children: Vec<DecodedNode> = Vec::new();

        // callbackIds: int32 count, then each CallbackId { int64 id, int32 type } behind a flag.
        let cb_count = cur.read_i32()?;
        let cb_start = cur.pos;
        let mut ids: Vec<DecodedNode> = Vec::new();
        for j in 0..cb_count.clamp(0, MAX_ENTRIES) {
            let _cb_flag = cur.read_i32()?;
            let id = cur.read_i64()?;
            let ty = cur.read_i32()?;
            let mut c = node(DecodedValue::I64(id), "long", cur.pos - 16, 16, vec![]);
            c.name = format!("[{}] id={} type={}", j, id, ty);
            ids.push(c);
        }
        let mut cb = node(
            DecodedValue::Array {
                len: ids.len(),
                null: false,
            },
            "callbackIds",
            cb_start,
            cur.pos - cb_start,
            ids,
        );
        cb.name = "callbackIds".to_string();
        ts_children.push(cb);

        let fs = cur.pos;
        let latch = cur.read_i64()?;
        let mut lt = node(DecodedValue::I64(latch), "long", fs, 8, vec![]);
        lt.name = "latchTime".to_string();
        ts_children.push(lt);

        let fs = cur.pos;
        let present = cur.read_i32()? != 0;
        let mut pf = node(DecodedValue::Bool(present), "bool", fs, 4, vec![]);
        pf.name = "presentFence_present".to_string();
        ts_children.push(pf);

        let mut ts = node(
            DecodedValue::Parcelable {
                fqn: "android.gui.TransactionStats".to_string(),
                null: false,
            },
            "TransactionStats",
            ts_start,
            cur.pos - ts_start,
            ts_children,
        );
        ts.name = "[0]".to_string();
        children.push(ts);
    }

    // Everything after the first TransactionStats' front half is variant (fence, surfaceStats,
    // and any further TransactionStats). Surface it as an opaque back_half.
    let rem = cur.buf_len().saturating_sub(cur.pos);
    if rem > 0 {
        let rs = cur.pos;
        cur.skip(rem)?;
        let mut tail = node(DecodedValue::Bytes, "raw", rs, rem, vec![]);
        tail.name = "back_half".to_string();
        children.push(tail);
    }

    Some(node(
        DecodedValue::Parcelable {
            fqn: "android.gui.ListenerStats".to_string(),
            null: false,
        },
        "ListenerStats",
        start,
        cur.pos - start,
        children,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn i32b(n: i32) -> Vec<u8> {
        n.to_le_bytes().to_vec()
    }
    fn i64b(n: i64) -> Vec<u8> {
        n.to_le_bytes().to_vec()
    }

    #[test]
    fn decodes_listener_stats_front_half() {
        // Matches a real onTransactionCompleted payload: 1 TransactionStats, 2 callback ids
        // (924, 923, type 0), latchTime, presentFence present, then a variant tail.
        let mut b = Vec::new();
        b.extend(i32b(1)); // ListenerStats non-null flag
        b.extend(i32b(1)); // TransactionStats count
        b.extend(i32b(1)); // TransactionStats non-null flag
        b.extend(i32b(2)); // callbackIds count
        b.extend(i32b(1));
        b.extend(i64b(924));
        b.extend(i32b(0)); // callbackId[0]
        b.extend(i32b(1));
        b.extend(i64b(923));
        b.extend(i32b(0)); // callbackId[1]
        b.extend(i64b(52699407495)); // latchTime
        b.extend(i32b(1)); // presentFence present
        b.extend(vec![0xabu8; 40]); // variant tail (fence + surfaceStats)

        let mut cur = ParcelCursor::new(&b, 0);
        let n = listener_stats(&mut cur, 0, 0).expect("decodes");
        assert!(
            matches!(&n.value, DecodedValue::Parcelable { fqn, null: false } if fqn == "android.gui.ListenerStats")
        );
        let num = n
            .children
            .iter()
            .find(|c| c.name == "num_transaction_stats")
            .unwrap();
        assert!(matches!(num.value, DecodedValue::I64(1)));
        let ts = n.children.iter().find(|c| c.name == "[0]").unwrap();
        let cb = ts
            .children
            .iter()
            .find(|c| c.name == "callbackIds")
            .unwrap();
        assert!(matches!(cb.value, DecodedValue::Array { len: 2, .. }));
        assert!(cb.children[0].name.contains("id=924"));
        let lt = ts.children.iter().find(|c| c.name == "latchTime").unwrap();
        assert!(matches!(lt.value, DecodedValue::I64(52699407495)));
        assert!(n.children.iter().any(|c| c.name == "back_half"));
    }

    #[test]
    fn null_listener_stats() {
        let b = i32b(0);
        let mut cur = ParcelCursor::new(&b, 0);
        let n = listener_stats(&mut cur, 0, 0).unwrap();
        assert!(matches!(
            &n.value,
            DecodedValue::Parcelable { null: true, .. }
        ));
    }

    #[test]
    fn empty_listener_stats_has_no_transaction_stats() {
        let mut b = Vec::new();
        b.extend(i32b(1)); // non-null
        b.extend(i32b(0)); // zero TransactionStats
        let mut cur = ParcelCursor::new(&b, 0);
        let n = listener_stats(&mut cur, 0, 0).unwrap();
        let num = n
            .children
            .iter()
            .find(|c| c.name == "num_transaction_stats")
            .unwrap();
        assert!(matches!(num.value, DecodedValue::I64(0)));
        assert!(!n.children.iter().any(|c| c.name == "[0]"));
    }

    #[test]
    fn truncated_mid_callbackid_bails_cleanly() {
        let mut b = Vec::new();
        b.extend(i32b(1)); // non-null
        b.extend(i32b(1)); // 1 TransactionStats
        b.extend(i32b(1)); // TS non-null
        b.extend(i32b(1)); // 1 callbackId
        b.extend(i32b(1)); // callbackId flag, then truncate before the i64 id
        let mut cur = ParcelCursor::new(&b, 0);
        assert!(listener_stats(&mut cur, 0, 0).is_none());
    }
}
