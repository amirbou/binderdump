use binderdump_aidl::model::Method;
use binderdump_epan_sys as epan;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

// `req_frame == 0` / `rep_frame == 0` mean "unset". Wireshark assigns frame
// numbers starting at 1 (pinfo->num is 1-based), so 0 is a safe sentinel.
#[derive(Debug, Clone, Default)]
pub struct TxnState {
    pub req_frame: u32,
    pub rep_frame: u32,
    pub req_pid: i32,
    pub req_tid: i32,
    pub req_cmdline: Option<String>,
    pub rep_debug_id: i32,
    pub req_time: Option<epan::nstime_t>,
    pub interface: Option<String>,
    pub method_name: Option<String>,
    pub method: Option<&'static Method>,
    pub is_native: bool,
    pub is_hidl: bool,
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
    next_stream_index: u32,
    stream_index_by_anchor: HashMap<i32, u32>,
    n_by_rep_debug_id: HashMap<i32, i32>,
}

impl State {
    fn clear(&mut self) {
        self.txns.clear();
        self.frames.clear();
        self.next_stream_index = 0;
        self.stream_index_by_anchor.clear();
        self.n_by_rep_debug_id.clear();
    }

    fn record_frame(
        &mut self,
        frame: u32,
        abs_ts: epan::nstime_t,
        debug_id: i32,
        in_reply_to_debug_id: i32,
        reply: i32,
        req_pid: i32,
        req_tid: i32,
        req_cmdline: Option<String>,
        interface: Option<String>,
        method_name: Option<String>,
        method: Option<&'static Method>,
        is_native: bool,
        is_hidl: bool,
    ) {
        self.frames.insert(
            frame,
            FrameMeta {
                debug_id,
                in_reply_to_debug_id,
                reply,
            },
        );
        // Pick the stream anchor — the debug_id we use to group frames of one
        // logical transaction. For a request (reply == 0), the anchor is the
        // request's own debug_id (call this `N`). For a reply, the anchor is
        // ideally `in_reply_to_debug_id` (also `N`), so the reply maps to the
        // same stream as its originating request. BR_REPLY frames sometimes
        // arrive with `in_reply_to_debug_id == 0` (kernel only stamps it on the
        // BC side); for those we fall back to the reply's own debug_id (`Y`),
        // which is later unified with `N` once the matching BC_REPLY is seen.
        let anchor = if reply == 0 {
            debug_id
        } else if in_reply_to_debug_id != 0 {
            in_reply_to_debug_id
        } else {
            debug_id
        };

        // BC_REPLY case: this is the one frame that names both Y (its own
        // debug_id, the reply's id) and N (in_reply_to_debug_id, the request's
        // id). Use it to unify the two anchors into one stream index. There are
        // two orderings to handle:
        //   - Y already has an index (BR_REPLY was seen first as an orphan with
        //     anchor = Y): alias N → Y's index so future requests/replies under
        //     N land in the same stream.
        //   - N already has an index (normal: request arrived before BC_REPLY):
        //     alias Y → N's index so orphan BR_REPLY frames (anchor = Y) join.
        // We also record Y → N in `n_by_rep_debug_id` so lookups by frame can
        // walk Y back to N when only the orphan side is known.
        if reply != 0 && in_reply_to_debug_id != 0 && debug_id != 0 {
            let y = debug_id;
            let n = in_reply_to_debug_id;
            let y_idx = self.stream_index_by_anchor.get(&y).copied();
            let n_idx = self.stream_index_by_anchor.get(&n).copied();
            match (y_idx, n_idx) {
                (Some(yi), None) => {
                    self.stream_index_by_anchor.insert(n, yi);
                }
                (None, Some(ni)) => {
                    self.stream_index_by_anchor.insert(y, ni);
                }
                _ => {}
            }
            self.n_by_rep_debug_id.insert(y, n);
        }

        if anchor != 0 && !self.stream_index_by_anchor.contains_key(&anchor) {
            let idx = self.next_stream_index;
            self.stream_index_by_anchor.insert(anchor, idx);
            self.next_stream_index += 1;
        }
        let key = if reply == 0 {
            debug_id
        } else {
            in_reply_to_debug_id
        };
        if key == 0 {
            return;
        }
        let entry = self.txns.entry(key).or_default();
        if reply == 0 {
            if entry.req_frame == 0 {
                entry.req_frame = frame;
                entry.req_pid = req_pid;
                entry.req_time = Some(abs_ts);
                entry.interface = interface;
                entry.method_name = method_name;
                entry.method = method;
                entry.is_native = is_native;
                entry.is_hidl = is_hidl;
            }
            // caller tid/cmdline come only from the send (BC) frame. it is NOT
            // necessarily the first frame seen for this debug_id (the recv/BR frame
            // can arrive first and set req_frame), so this is deliberately not gated
            // on req_frame == 0. the send frame is the only caller that passes
            // req_cmdline = Some(..); "first non-None wins" then prevents a later
            // recv record (None) or a duplicate from clobbering it.
            if entry.req_cmdline.is_none() {
                if let Some(c) = req_cmdline {
                    entry.req_tid = req_tid;
                    entry.req_cmdline = Some(c);
                }
            }
        } else if entry.rep_frame == 0 {
            entry.rep_frame = frame;
            entry.rep_debug_id = debug_id;
        }
    }

    fn lookup_frame(&self, frame: u32) -> Option<FrameMeta> {
        self.frames.get(&frame).copied()
    }

    fn lookup_txn(&self, key: i32) -> Option<TxnState> {
        if key == 0 {
            return None;
        }
        self.txns.get(&key).cloned()
    }

    // Resolve a reply frame to its originating request's TxnState. The kernel only
    // stamps in_reply_to_debug_id (N) on the BC_REPLY (write) side; a BR_REPLY (read)
    // frame carries in_reply_to_debug_id == 0 but its own reply debug_id (Y), so for
    // those we walk n_by_rep_debug_id[Y] = N (recorded when the BC_REPLY was seen).
    fn txn_for_reply(&self, in_reply_to_debug_id: i32, reply_debug_id: i32) -> Option<TxnState> {
        if let Some(t) = self.lookup_txn(in_reply_to_debug_id) {
            return Some(t);
        }
        let n = self.n_by_rep_debug_id.get(&reply_debug_id)?;
        self.lookup_txn(*n)
    }

    // caller tid + cmdline for a transaction, recorded from its send frame.
    // none until the send frame has been seen.
    fn caller_info(&self, debug_id: i32) -> Option<(i32, String)> {
        if debug_id == 0 {
            return None;
        }
        let t = self.txns.get(&debug_id)?;
        t.req_cmdline.as_deref().map(|c| (t.req_tid, c.to_owned()))
    }

    #[cfg(test)]
    fn stream_index_for_anchor(&self, anchor: i32) -> Option<u32> {
        self.stream_index_by_anchor.get(&anchor).copied()
    }

    fn stream_index_for_any_debug_id(&self, d: i32) -> Option<u32> {
        if let Some(&idx) = self.stream_index_by_anchor.get(&d) {
            return Some(idx);
        }
        let n = self.n_by_rep_debug_id.get(&d)?;
        self.stream_index_by_anchor.get(n).copied()
    }

    fn stream_index_for_frame(&self, frame: u32) -> Option<u32> {
        let meta = self.frames.get(&frame)?;
        let anchor = if meta.reply == 0 {
            meta.debug_id
        } else if meta.in_reply_to_debug_id != 0 {
            meta.in_reply_to_debug_id
        } else {
            meta.debug_id
        };
        if anchor == 0 {
            return None;
        }
        self.stream_index_by_anchor.get(&anchor).copied()
    }

    // Resolve a frame to its TxnState's req_pid. Walks the same anchor logic as
    // stream_index_for_frame; for orphan BR_REPLY frames (anchor = Y), follows
    // n_by_rep_debug_id[Y] = N to find the canonical TxnState. Returns None when
    // the frame isn't part of a known stream.
    fn req_pid_for_frame(&self, frame: u32) -> Option<i32> {
        let meta = self.frames.get(&frame)?;
        let anchor = if meta.reply == 0 {
            meta.debug_id
        } else if meta.in_reply_to_debug_id != 0 {
            meta.in_reply_to_debug_id
        } else {
            meta.debug_id
        };
        if anchor == 0 {
            return None;
        }
        if let Some(t) = self.txns.get(&anchor) {
            return Some(t.req_pid);
        }
        let n = self.n_by_rep_debug_id.get(&anchor)?;
        self.txns.get(n).map(|t| t.req_pid)
    }
}

static STATE: OnceLock<Mutex<State>> = OnceLock::new();

fn state() -> &'static Mutex<State> {
    STATE.get_or_init(|| Mutex::new(State::default()))
}

pub fn clear() {
    if let Ok(mut s) = state().lock() {
        s.clear();
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
    req_pid: i32,
    req_tid: i32,
    req_cmdline: Option<String>,
    interface: Option<String>,
    method_name: Option<String>,
    method: Option<&'static Method>,
    is_native: bool,
    is_hidl: bool,
) {
    let Ok(mut s) = state().lock() else { return };
    s.record_frame(
        frame,
        abs_ts,
        debug_id,
        in_reply_to_debug_id,
        reply,
        req_pid,
        req_tid,
        req_cmdline,
        interface,
        method_name,
        method,
        is_native,
        is_hidl,
    );
}

pub fn lookup_frame(frame: u32) -> Option<FrameMeta> {
    state().lock().ok()?.lookup_frame(frame)
}

pub fn lookup_txn(key: i32) -> Option<TxnState> {
    state().lock().ok()?.lookup_txn(key)
}

// resolve a reply frame (BC_REPLY or orphan BR_REPLY) to its originating TxnState.
pub fn txn_for_reply(in_reply_to_debug_id: i32, reply_debug_id: i32) -> Option<TxnState> {
    state()
        .lock()
        .ok()?
        .txn_for_reply(in_reply_to_debug_id, reply_debug_id)
}

pub fn caller_info(debug_id: i32) -> Option<(i32, String)> {
    state().lock().ok()?.caller_info(debug_id)
}

pub fn stream_index_for_any_debug_id(d: i32) -> Option<u32> {
    state().lock().ok()?.stream_index_for_any_debug_id(d)
}

pub fn stream_index_for_frame(frame: u32) -> Option<u32> {
    state().lock().ok()?.stream_index_for_frame(frame)
}

pub fn req_pid_for_frame(frame: u32) -> Option<i32> {
    state().lock().ok()?.req_pid_for_frame(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64, nsecs: i32) -> epan::nstime_t {
        epan::nstime_t { secs, nsecs }
    }

    #[test]
    fn record_request_then_lookup() {
        let mut s = State::default();
        s.record_frame(
            10,
            ts(100, 0),
            42,
            0,
            0,
            0,
            0,
            None,
            Some("a.b.IFoo".into()),
            Some("hello".into()),
            None,
            false,
            false,
        );
        let t = s.lookup_txn(42).expect("txn");
        assert_eq!(t.req_frame, 10);
        assert_eq!(t.interface.as_deref(), Some("a.b.IFoo"));
        let m = s.lookup_frame(10).expect("meta");
        assert_eq!(m.debug_id, 42);
        assert_eq!(m.reply, 0);
    }

    #[test]
    fn record_reply_then_lookup() {
        let mut s = State::default();
        s.record_frame(
            5,
            ts(0, 0),
            7,
            0,
            0,
            0,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        s.record_frame(
            11,
            ts(0, 0),
            99,
            7,
            1,
            0,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        let t = s.lookup_txn(7).expect("txn");
        assert_eq!(t.req_frame, 5);
        assert_eq!(t.rep_frame, 11);
        let m = s.lookup_frame(11).expect("meta");
        assert_eq!(m.in_reply_to_debug_id, 7);
        assert_eq!(m.reply, 1);
    }

    #[test]
    fn first_seen_wins_on_duplicate_frame_records() {
        let mut s = State::default();
        s.record_frame(
            1,
            ts(0, 0),
            5,
            0,
            0,
            0,
            0,
            None,
            Some("first".into()),
            Some("a".into()),
            None,
            false,
            false,
        );
        s.record_frame(
            2,
            ts(0, 0),
            5,
            0,
            0,
            0,
            0,
            None,
            Some("second".into()),
            Some("b".into()),
            None,
            false,
            false,
        );
        let t = s.lookup_txn(5).expect("txn");
        assert_eq!(t.req_frame, 1);
        assert_eq!(t.interface.as_deref(), Some("first"));
    }

    #[test]
    fn clear_wipes_both_maps() {
        let mut s = State::default();
        s.record_frame(
            1,
            ts(0, 0),
            1,
            0,
            0,
            0,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        s.clear();
        assert!(s.lookup_txn(1).is_none());
        assert!(s.lookup_frame(1).is_none());
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let s = State::default();
        assert!(s.lookup_txn(99).is_none());
        assert!(s.lookup_frame(99).is_none());
        assert!(s.lookup_txn(0).is_none());
    }

    #[test]
    fn record_request_stores_req_pid() {
        let mut s = State::default();
        s.record_frame(
            10,
            ts(100, 0),
            42,
            0,
            0,
            1234, // req_pid
            0,
            None,
            Some("a.b.IFoo".into()),
            Some("hello".into()),
            None,
            false,
            false,
        );
        let t = s.lookup_txn(42).expect("txn");
        assert_eq!(t.req_pid, 1234);
    }

    #[test]
    fn req_pid_first_seen_wins() {
        let mut s = State::default();
        s.record_frame(
            1,
            ts(0, 0),
            5,
            0,
            0,
            100,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        s.record_frame(
            2,
            ts(0, 0),
            5,
            0,
            0,
            999,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        let t = s.lookup_txn(5).expect("txn");
        assert_eq!(t.req_pid, 100);
    }

    #[test]
    fn bc_reply_fills_rep_debug_id() {
        let mut s = State::default();
        // request: debug_id=10, no in_reply_to, reply=0
        s.record_frame(
            1,
            ts(0, 0),
            10,
            0,
            0,
            100,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        // reply: debug_id=20, in_reply_to=10, reply=1
        s.record_frame(
            2,
            ts(0, 0),
            20,
            10,
            1,
            0,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        let t = s.lookup_txn(10).expect("txn");
        assert_eq!(t.rep_debug_id, 20);
    }

    #[test]
    fn rep_debug_id_first_seen_wins() {
        let mut s = State::default();
        s.record_frame(
            1,
            ts(0, 0),
            10,
            0,
            0,
            100,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        s.record_frame(
            2,
            ts(0, 0),
            20,
            10,
            1,
            0,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        // a second reply event with same in_reply_to but different debug_id
        s.record_frame(
            3,
            ts(0, 0),
            99,
            10,
            1,
            0,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        let t = s.lookup_txn(10).expect("txn");
        assert_eq!(t.rep_debug_id, 20);
    }

    #[test]
    fn stream_index_starts_at_zero() {
        let mut s = State::default();
        s.record_frame(
            1,
            ts(0, 0),
            42,
            0,
            0,
            100,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        assert_eq!(s.stream_index_for_anchor(42), Some(0));
    }

    #[test]
    fn stream_index_is_monotonic() {
        let mut s = State::default();
        s.record_frame(
            1,
            ts(0, 0),
            10,
            0,
            0,
            100,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        s.record_frame(
            2,
            ts(0, 0),
            20,
            0,
            0,
            101,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        s.record_frame(
            3,
            ts(0, 0),
            30,
            0,
            0,
            102,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        assert_eq!(s.stream_index_for_anchor(10), Some(0));
        assert_eq!(s.stream_index_for_anchor(20), Some(1));
        assert_eq!(s.stream_index_for_anchor(30), Some(2));
    }

    #[test]
    fn same_anchor_reuses_index() {
        let mut s = State::default();
        s.record_frame(
            1,
            ts(0, 0),
            42,
            0,
            0,
            100,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        s.record_frame(
            2,
            ts(0, 0),
            42,
            0,
            0,
            100,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        assert_eq!(s.stream_index_for_anchor(42), Some(0));
    }

    #[test]
    fn clear_resets_counter() {
        let mut s = State::default();
        s.record_frame(
            1,
            ts(0, 0),
            42,
            0,
            0,
            100,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        s.clear();
        s.record_frame(
            1,
            ts(0, 0),
            99,
            0,
            0,
            100,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        assert_eq!(s.stream_index_for_anchor(99), Some(0));
    }

    #[test]
    fn bc_reply_aliases_y_to_n_when_orphan_seen_first() {
        let mut s = State::default();
        // Orphan BR_REPLY (no in_reply_to): anchor=Y=99, allocates index 0.
        s.record_frame(
            1,
            ts(0, 0),
            99,
            0,
            1,
            0,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        assert_eq!(s.stream_index_for_anchor(99), Some(0));
        // BC_REPLY arrives later: debug_id=99 (Y), in_reply_to=10 (N).
        // Should NOT allocate a new index — should alias N→0.
        s.record_frame(
            2,
            ts(0, 0),
            99,
            10,
            1,
            0,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        assert_eq!(s.stream_index_for_anchor(10), Some(0));
        assert_eq!(s.stream_index_for_anchor(99), Some(0));
        // next_stream_index should still be 1 (only one allocation total).
        // Record an unrelated request — gets index 1, proving counter is 1.
        s.record_frame(
            3,
            ts(0, 0),
            7,
            0,
            0,
            50,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        assert_eq!(s.stream_index_for_anchor(7), Some(1));
    }

    #[test]
    fn n_by_rep_debug_id_populated_on_bc_reply() {
        let mut s = State::default();
        s.record_frame(
            1,
            ts(0, 0),
            10,
            0,
            0,
            100,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        s.record_frame(
            2,
            ts(0, 0),
            99,
            10,
            1,
            0,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        // Both anchors should map to the same index.
        assert_eq!(s.stream_index_for_anchor(10), s.stream_index_for_anchor(99));
    }

    #[test]
    fn stream_index_for_any_debug_id_resolves_via_y_to_n() {
        let mut s = State::default();
        s.record_frame(
            1,
            ts(0, 0),
            10,
            0,
            0,
            100,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        s.record_frame(
            2,
            ts(0, 0),
            99,
            10,
            1,
            0,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        let n_idx = s.stream_index_for_any_debug_id(10);
        let y_idx = s.stream_index_for_any_debug_id(99);
        assert!(n_idx.is_some());
        assert_eq!(n_idx, y_idx);
    }

    #[test]
    fn stream_index_for_frame_returns_index() {
        let mut s = State::default();
        s.record_frame(
            7,
            ts(0, 0),
            42,
            0,
            0,
            100,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        assert_eq!(s.stream_index_for_frame(7), Some(0));
    }

    #[test]
    fn stream_index_for_frame_returns_none_for_unknown_frame() {
        let s = State::default();
        assert_eq!(s.stream_index_for_frame(999), None);
    }

    #[test]
    fn req_pid_for_frame_resolves_orphan_br_reply_via_y_to_n() {
        let mut s = State::default();
        // BC_TRANSACTION (party A=100 → kernel): anchor=N=10, req_pid=100.
        s.record_frame(
            1,
            ts(0, 0),
            10,
            0,
            0,
            100,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        // BC_REPLY (party B sends; debug_id=Y=99, in_reply_to=N=10).
        // Aliases Y→N in n_by_rep_debug_id.
        s.record_frame(
            2,
            ts(0, 0),
            99,
            10,
            1,
            200,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        // BR_REPLY (party A reads; debug_id=Y=99, in_reply_to=0 — orphan-shape).
        s.record_frame(
            3,
            ts(0, 0),
            99,
            0,
            1,
            200,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        // Frame 3's anchor is Y=99 (orphan). Helper must walk Y→N=10 → req_pid=100.
        assert_eq!(s.req_pid_for_frame(3), Some(100));
        // Frame 1 (the request) resolves directly to its anchor.
        assert_eq!(s.req_pid_for_frame(1), Some(100));
        // Unknown frame returns None.
        assert_eq!(s.req_pid_for_frame(999), None);
    }

    #[test]
    fn caller_info_recorded_from_send_frame() {
        let mut s = State::default();
        s.record_frame(
            1,
            ts(0, 0),
            42,
            0,
            0,
            100,
            1001,
            Some("com.example.app".into()),
            None,
            None,
            None,
            false,
            false,
        );
        assert_eq!(s.caller_info(42), Some((1001, "com.example.app".into())));
    }

    #[test]
    fn caller_info_not_overwritten_by_recv_frame() {
        let mut s = State::default();
        s.record_frame(
            1,
            ts(0, 0),
            42,
            0,
            0,
            0,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        assert_eq!(s.caller_info(42), None);
        s.record_frame(
            2,
            ts(0, 0),
            42,
            0,
            0,
            100,
            1001,
            Some("com.example.app".into()),
            None,
            None,
            None,
            false,
            false,
        );
        assert_eq!(s.caller_info(42), Some((1001, "com.example.app".into())));
        s.record_frame(
            3,
            ts(0, 0),
            42,
            0,
            0,
            100,
            2002,
            Some("other".into()),
            None,
            None,
            None,
            false,
            false,
        );
        assert_eq!(s.caller_info(42), Some((1001, "com.example.app".into())));
    }

    #[test]
    fn caller_info_unknown_is_none() {
        let s = State::default();
        assert_eq!(s.caller_info(0), None);
        assert_eq!(s.caller_info(999), None);
    }

    #[test]
    fn stores_and_returns_originating_method() {
        use binderdump_aidl::model::Method;
        // 'static method (registry is a singleton in production; leak one for the test).
        let m: &'static Method = Box::leak(Box::new(Method {
            name: "doThing".to_string(),
            params: vec![],
            return_type: None,
            oneway: false,
            code: None,
        }));
        let mut s = State::default();
        // request frame (reply == 0), debug_id 7, carries the method.
        s.record_frame(
            1,
            ts(0, 0),
            7,
            0,
            0,
            0,
            0,
            None,
            Some("a.IFoo".into()),
            Some("doThing".into()),
            Some(m),
            false,
            false,
        );
        // reply frame keyed by in_reply_to_debug_id = 7.
        s.record_frame(
            2,
            ts(0, 0),
            99,
            7,
            1,
            0,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        let txn = s.lookup_txn(7).unwrap();
        assert!(txn.method.is_some());
        assert_eq!(txn.method.unwrap().name, "doThing");
    }

    #[test]
    fn txn_for_reply_resolves_orphan_br_reply() {
        use binderdump_aidl::model::Method;
        let m: &'static Method = Box::leak(Box::new(Method {
            name: "getThing".to_string(),
            params: vec![],
            return_type: None,
            oneway: false,
            code: None,
        }));
        let mut s = State::default();
        // request: debug_id N = 10, carries the method.
        s.record_frame(
            1,
            ts(0, 0),
            10,
            0,
            0,
            100,
            0,
            None,
            Some("a.IFoo".into()),
            Some("getThing".into()),
            Some(m),
            false,
            false,
        );
        // BC_REPLY: own debug_id Y = 99, in_reply_to N = 10 -> records n_by_rep_debug_id[99]=10.
        s.record_frame(
            2,
            ts(0, 0),
            99,
            10,
            1,
            0,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        // orphan BR_REPLY: in_reply_to == 0, own debug_id Y = 99 -> resolves via the fallback.
        let txn = s.txn_for_reply(0, 99).unwrap();
        assert_eq!(txn.method.unwrap().name, "getThing");
        // BC_REPLY direct path (in_reply_to set) still resolves.
        assert!(s.txn_for_reply(10, 99).unwrap().method.is_some());
    }

    #[test]
    fn carries_is_native_flag() {
        use binderdump_aidl::model::Method;
        let m: &'static Method = Box::leak(Box::new(Method {
            name: "getUpdatableDriverPath".to_string(),
            params: vec![],
            return_type: None,
            oneway: false,
            code: None,
        }));
        let mut s = State::default();
        s.record_frame(
            1,
            ts(0, 0),
            7,
            0,
            0,
            0,
            0,
            None,
            Some("a.IFoo".into()),
            Some("getUpdatableDriverPath".into()),
            Some(m),
            true,
            false,
        );
        s.record_frame(
            2,
            ts(0, 0),
            99,
            7,
            1,
            0,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        let txn = s.lookup_txn(7).unwrap();
        assert!(txn.is_native);
    }

    #[test]
    fn carries_is_hidl_flag() {
        use binderdump_aidl::model::Method;
        let m: &'static Method = Box::leak(Box::new(Method {
            name: "getDevices".to_string(),
            params: vec![],
            return_type: None,
            oneway: false,
            code: None,
        }));
        let mut s = State::default();
        s.record_frame(
            1,
            ts(0, 0),
            8,
            0,
            0,
            0,
            0,
            None,
            Some("android.hardware.audio@6.0::IDevicesFactory".into()),
            Some("getDevices".into()),
            Some(m),
            false,
            true,
        );
        s.record_frame(
            2,
            ts(0, 0),
            99,
            8,
            1,
            0,
            0,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        let txn = s.lookup_txn(8).unwrap();
        assert!(txn.is_hidl);
    }
}
