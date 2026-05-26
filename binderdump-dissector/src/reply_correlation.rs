use binderdump_epan_sys as epan;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

// `req_frame == 0` / `rep_frame == 0` mean "unset". Wireshark assigns frame
// numbers starting at 1 (pinfo->num is 1-based), so 0 is a safe sentinel.
#[derive(Debug, Clone, Default)]
pub struct TxnState {
    pub req_frame: u32,
    pub rep_frame: u32,
    pub req_time: Option<epan::nstime_t>,
    pub interface: Option<String>,
    pub method_name: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct FrameMeta {
    pub debug_id: i32,
    pub in_reply_to_debug_id: i32,
    pub reply: i32, // 0 = transaction, 1 = reply
}

#[derive(Default)]
struct State {
    txns: HashMap<i32, TxnState>,
    frames: HashMap<u32, FrameMeta>,
}

static STATE: OnceLock<Mutex<State>> = OnceLock::new();

fn state() -> &'static Mutex<State> {
    STATE.get_or_init(|| Mutex::new(State::default()))
}

pub fn clear() {
    if let Ok(mut s) = state().lock() {
        s.txns.clear();
        s.frames.clear();
    }
}

// called by the main dissector on first pass per binderdump frame
// (gated by `!PINFO_FD_VISITED`). records both the per-frame snapshot
// and the per-transaction state.
pub fn record_frame(
    frame: u32,
    abs_ts: epan::nstime_t,
    debug_id: i32,
    in_reply_to_debug_id: i32,
    reply: i32,
    interface: Option<String>,
    method_name: Option<String>,
) {
    let Ok(mut s) = state().lock() else { return };
    s.frames.insert(
        frame,
        FrameMeta {
            debug_id,
            in_reply_to_debug_id,
            reply,
        },
    );
    let key = if reply == 0 {
        debug_id
    } else {
        in_reply_to_debug_id
    };
    if key == 0 {
        return;
    }
    let entry = s.txns.entry(key).or_default();
    if reply == 0 {
        if entry.req_frame == 0 {
            entry.req_frame = frame;
            entry.req_time = Some(abs_ts);
            entry.interface = interface;
            entry.method_name = method_name;
        }
    } else if entry.rep_frame == 0 {
        entry.rep_frame = frame;
    }
}

pub fn lookup_frame(frame: u32) -> Option<FrameMeta> {
    state().lock().ok()?.frames.get(&frame).copied()
}

pub fn lookup_txn(key: i32) -> Option<TxnState> {
    if key == 0 {
        return None;
    }
    state().lock().ok()?.txns.get(&key).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64, nsecs: i32) -> epan::nstime_t {
        epan::nstime_t { secs, nsecs }
    }

    #[test]
    fn record_request_then_lookup() {
        clear();
        record_frame(
            10,
            ts(100, 0),
            42,
            0,
            0,
            Some("a.b.IFoo".into()),
            Some("hello".into()),
        );
        let t = lookup_txn(42).expect("txn");
        assert_eq!(t.req_frame, 10);
        assert_eq!(t.interface.as_deref(), Some("a.b.IFoo"));
        let m = lookup_frame(10).expect("meta");
        assert_eq!(m.debug_id, 42);
        assert_eq!(m.reply, 0);
    }

    #[test]
    fn record_reply_then_lookup() {
        clear();
        record_frame(5, ts(0, 0), 7, 0, 0, None, None);
        record_frame(11, ts(0, 0), 99, 7, 1, None, None);
        let t = lookup_txn(7).expect("txn");
        assert_eq!(t.req_frame, 5);
        assert_eq!(t.rep_frame, 11);
        let m = lookup_frame(11).expect("meta");
        assert_eq!(m.in_reply_to_debug_id, 7);
        assert_eq!(m.reply, 1);
    }

    #[test]
    fn first_seen_wins_on_duplicate_frame_records() {
        clear();
        record_frame(1, ts(0, 0), 5, 0, 0, Some("first".into()), Some("a".into()));
        record_frame(
            2,
            ts(0, 0),
            5,
            0,
            0,
            Some("second".into()),
            Some("b".into()),
        );
        let t = lookup_txn(5).expect("txn");
        assert_eq!(t.req_frame, 1);
        assert_eq!(t.interface.as_deref(), Some("first"));
    }

    #[test]
    fn clear_wipes_both_maps() {
        clear();
        record_frame(1, ts(0, 0), 1, 0, 0, None, None);
        clear();
        assert!(lookup_txn(1).is_none());
        assert!(lookup_frame(1).is_none());
    }

    #[test]
    fn lookup_unknown_returns_none() {
        clear();
        assert!(lookup_txn(99).is_none());
        assert!(lookup_frame(99).is_none());
        assert!(lookup_txn(0).is_none());
    }
}
