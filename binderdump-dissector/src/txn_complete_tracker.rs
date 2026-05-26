// per-thread BC slot + per-frame attribution for BR_TRANSACTION_COMPLETE.
// record_bc() notes the most recent BC_TRANSACTION/BC_REPLY debug_id for a
// thread; attribute_complete() ties a frame to that slot so the post-dissector
// can emit a txn_complete_for_debug_id field.

use binderdump_structs::binder_types::binder_return::BinderReturn;
use binderdump_structs::binder_types::bwr_trait::Bwr;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

#[derive(Default)]
struct State {
    // per-thread slot: which debug_id was the most recently issued
    // BC_TRANSACTION / BC_REPLY on this thread.
    last_bc: HashMap<(i32, i32), i32>,
    // per-frame attribution: which debug_id this frame's
    // BR_TRANSACTION_COMPLETE attributes to. None means no attribution.
    frame_attr: HashMap<u32, i32>,
}

static STATE: OnceLock<Mutex<State>> = OnceLock::new();

fn state() -> &'static Mutex<State> {
    STATE.get_or_init(|| Mutex::new(State::default()))
}

pub fn clear() {
    if let Ok(mut s) = state().lock() {
        s.last_bc.clear();
        s.frame_attr.clear();
    }
}

/// Record that thread (pid, tid) just issued a BC_TRANSACTION or BC_REPLY
/// with the given debug_id. Overwrites any prior slot for that thread —
/// libbinder runs one txn per thread sequentially so the most-recent BC
/// is always the next one to be ACK'd.
pub fn record_bc(pid: i32, tid: i32, debug_id: i32) {
    let Ok(mut s) = state().lock() else { return };
    s.last_bc.insert((pid, tid), debug_id);
}

/// Note that this frame contains a BR_TRANSACTION_COMPLETE for thread
/// (pid, tid). Looks up the current slot and, if a BC has been seen for
/// that thread, records (frame → that BC's debug_id) so the
/// post-dissector can emit the txn_complete_for_debug_id field.
pub fn attribute_complete(frame: u32, pid: i32, tid: i32) {
    let Ok(mut s) = state().lock() else { return };
    if let Some(&id) = s.last_bc.get(&(pid, tid)) {
        s.frame_attr.insert(frame, id);
    }
}

/// Returns the debug_id that this frame's BR_TRANSACTION_COMPLETE was
/// attributed to, if any.
pub fn lookup_frame(frame: u32) -> Option<i32> {
    state().lock().ok()?.frame_attr.get(&frame).copied()
}

// walk one direction of a BINDER_WRITE_READ buffer and update tracker state.
// on the write side, record the debug_id in the BC slot for this thread.
// on the read side, scan for BR_TRANSACTION_COMPLETE and attribute each one.
pub fn process_bwr_data(
    frame: u32,
    pid: i32,
    tid: i32,
    is_write: bool,
    data: &[u8],
    txn_debug_id: Option<i32>,
) {
    if is_write {
        if let Some(id) = txn_debug_id {
            if id != 0 {
                record_bc(pid, tid, id);
            }
        }
        return;
    }
    // read side: walk BR commands looking for BR_TRANSACTION_COMPLETE.
    if data.is_empty() {
        return;
    }
    let mut pos = 0;
    while pos < data.len() {
        let Ok(ret) = BinderReturn::from_bytes(&data[pos..]) else {
            break;
        };
        let consumed = ret.size();
        if consumed == 0 {
            break;
        }
        if matches!(ret, BinderReturn::TransactionComplete) {
            attribute_complete(frame, pid, tid);
        }
        pos += consumed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use binderdump_structs::binder_types::binder_return::binder_return;

    #[test]
    fn record_bc_then_attribute_complete() {
        clear();
        record_bc(1, 2, 42);
        attribute_complete(5, 1, 2);
        assert_eq!(lookup_frame(5), Some(42));
    }

    #[test]
    fn attribute_complete_with_no_slot_is_noop() {
        clear();
        attribute_complete(5, 1, 2);
        assert_eq!(lookup_frame(5), None);
    }

    #[test]
    fn slot_is_per_thread() {
        clear();
        record_bc(1, 2, 42);
        record_bc(1, 3, 99);
        attribute_complete(5, 1, 2);
        attribute_complete(6, 1, 3);
        assert_eq!(lookup_frame(5), Some(42));
        assert_eq!(lookup_frame(6), Some(99));
    }

    #[test]
    fn most_recent_bc_wins_in_slot() {
        clear();
        record_bc(1, 2, 42);
        record_bc(1, 2, 100);
        attribute_complete(5, 1, 2);
        assert_eq!(lookup_frame(5), Some(100));
    }

    #[test]
    fn clear_wipes_both_maps() {
        clear();
        record_bc(1, 2, 42);
        attribute_complete(5, 1, 2);
        clear();
        assert_eq!(lookup_frame(5), None);
    }

    fn br_header(cmd: u32) -> Vec<u8> {
        cmd.to_le_bytes().to_vec()
    }

    #[test]
    fn process_bwr_data_write_records_when_txn_debug_id_set() {
        clear();
        process_bwr_data(7, 100, 200, true, &[], Some(42));
        // no frame attribution on write side; check that BR_TRANSACTION_COMPLETE
        // on a later read frame on the same thread picks up 42.
        let buf = br_header(binder_return::BR_TRANSACTION_COMPLETE as u32);
        process_bwr_data(8, 100, 200, false, &buf, None);
        assert_eq!(lookup_frame(8), Some(42));
    }

    #[test]
    fn process_bwr_data_write_with_none_or_zero_does_not_record() {
        clear();
        process_bwr_data(7, 100, 200, true, &[], None);
        let buf = br_header(binder_return::BR_TRANSACTION_COMPLETE as u32);
        process_bwr_data(8, 100, 200, false, &buf, None);
        assert_eq!(lookup_frame(8), None);

        clear();
        process_bwr_data(7, 100, 200, true, &[], Some(0));
        process_bwr_data(8, 100, 200, false, &buf, None);
        assert_eq!(lookup_frame(8), None);
    }

    #[test]
    fn process_bwr_data_read_walks_multiple_br_commands() {
        clear();
        record_bc(100, 200, 42);
        // BR_NOOP (no payload) + BR_TRANSACTION_COMPLETE (no payload).
        let mut buf = br_header(binder_return::BR_NOOP as u32);
        buf.extend(br_header(binder_return::BR_TRANSACTION_COMPLETE as u32));
        process_bwr_data(9, 100, 200, false, &buf, None);
        assert_eq!(lookup_frame(9), Some(42));
    }
}
