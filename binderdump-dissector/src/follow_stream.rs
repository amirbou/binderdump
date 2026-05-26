use crate::dissect_flat_objects::{OffsetKind, OffsetSummary};
use binderdump_epan_sys::epan;
use std::collections::HashMap;
use std::ffi::c_int;
use std::os::raw::{c_char, c_void};
use std::sync::{Mutex, OnceLock};

pub use crate::dissect_flat_objects::parse_offset_summaries;

#[derive(Debug, Clone)]
pub struct TapData {
    pub debug_id: i32,
    pub in_reply_to_debug_id: i32,
    pub reply: i32,
    pub code: u32,
    pub flags: u32,
    pub interface: Option<String>,
    pub method: Option<String>,
    pub src_pid: i32,
    pub src_cmdline: String,
    pub dst_pid: i32,
    pub dst_cmdline: String,
    pub data: Vec<u8>,
    pub abs_ts: epan::nstime_t,
    pub offsets: Vec<OffsetSummary>,
}

static POOL: OnceLock<Mutex<HashMap<u32, TapData>>> = OnceLock::new();

fn pool() -> &'static Mutex<HashMap<u32, TapData>> {
    POOL.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn clear() {
    if let Ok(mut p) = pool().lock() {
        p.clear();
    }
}

pub fn insert(frame: u32, td: TapData) {
    let Ok(mut p) = pool().lock() else { return };
    p.insert(frame, td);
}

pub fn lookup(frame: u32) -> Option<TapData> {
    pool().lock().ok()?.get(&frame).cloned()
}

static TAP_ID: OnceLock<c_int> = OnceLock::new();

pub fn store_tap_id(id: c_int) {
    let _ = TAP_ID.set(id);
}

pub fn tap_id() -> Option<c_int> {
    TAP_ID.get().copied()
}

/// returns a stable non-NULL pointer used as a "tap data is present for this
/// frame" marker. the actual TapData is looked up from the pool by frame
/// number, so this pointer never needs to be dereferenced by the tap callback.
pub fn frame_marker() -> *const c_void {
    static MARKER: u8 = 0;
    &MARKER as *const u8 as *const c_void
}

use crate::reply_correlation::FrameMeta;

pub fn stream_id_for(meta: &FrameMeta) -> Option<u32> {
    let key = if meta.reply == 0 {
        meta.debug_id
    } else {
        meta.in_reply_to_debug_id
    };
    if key == 0 {
        None
    } else {
        Some(key as u32)
    }
}

pub fn build_filter(stream_index: u32) -> String {
    format!("binderdump_reply.transaction_stream_id == {}", stream_index)
}

pub fn format_hex_dump(bytes: &[u8], indent: &str) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for (row_idx, chunk) in bytes.chunks(16).enumerate() {
        let offset = row_idx * 16;
        out.push_str(indent);
        out.push_str(&format!("{:04x}  ", offset));

        let mut hex = String::new();
        for i in 0..16 {
            if i > 0 && i % 2 == 0 {
                hex.push(' ');
            }
            if i < chunk.len() {
                hex.push_str(&format!("{:02x}", chunk[i]));
            } else {
                hex.push_str("  ");
            }
        }
        out.push_str(&hex);
        out.push_str("  ");

        let mut ascii = String::new();
        for &b in chunk {
            if (0x20..=0x7e).contains(&b) {
                ascii.push(b as char);
            } else {
                ascii.push('.');
            }
        }
        for _ in ascii.chars().count()..16 {
            ascii.push(' ');
        }
        out.push_str(&ascii);
        out.push('\n');
    }
    out
}

pub fn format_offsets(offsets: &[OffsetSummary]) -> String {
    if offsets.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    out.push_str(&format!(
        "  offsets:   {} bytes, {} objects\n",
        offsets.len() * 8,
        offsets.len()
    ));
    for s in offsets {
        match &s.kind {
            OffsetKind::Binder { weak, ptr, cookie } => {
                let tag = if *weak { "WEAK_BINDER" } else { "BINDER" };
                out.push_str(&format!(
                    "    [{}] {:7} ptr=0x{:x} cookie=0x{:x}\n",
                    s.idx, tag, ptr, cookie
                ));
            }
            OffsetKind::Handle {
                weak,
                handle,
                cookie,
            } => {
                let tag = if *weak { "WEAK_HANDLE" } else { "HANDLE" };
                out.push_str(&format!(
                    "    [{}] {:7} handle={} cookie=0x{:x}\n",
                    s.idx, tag, handle, cookie
                ));
            }
            OffsetKind::Fd { fd } => {
                out.push_str(&format!("    [{}] {:7} fd={}\n", s.idx, "FD", fd));
            }
            OffsetKind::FdArray { num_fds, parent } => {
                out.push_str(&format!(
                    "    [{}] {:7} num_fds={} parent={}\n",
                    s.idx, "FDA", num_fds, parent
                ));
            }
            OffsetKind::Ptr {
                size,
                buffer_addr,
                payload,
                ..
            } => {
                out.push_str(&format!(
                    "    [{}] {:7} size={} buffer_addr=0x{:x}\n",
                    s.idx, "PTR", size, buffer_addr
                ));
                if let Some(bytes) = payload {
                    out.push_str(&format_hex_dump(bytes, "        "));
                }
            }
        }
    }
    out
}

/// determines the binary "side" (client=false / server=true) for a Follow
/// Stream record. when req_pid is known (non-zero), color by party: the
/// original BC_TRANSACTION sender is "client", everything else is "server".
/// when req_pid is 0 (we never saw the request — capture started
/// mid-flight), fall back to the simpler reply-direction split.
pub fn is_server_for_party(td: &TapData, req_pid: i32) -> bool {
    if req_pid != 0 {
        td.src_pid != req_pid
    } else {
        td.reply != 0
    }
}

pub fn format_record(td: &TapData, frame: u32, t_rel_secs: f64) -> String {
    let arrow = if td.reply == 0 {
        "\u{2192}"
    } else {
        "\u{2190}"
    };
    let mut out = String::new();

    let src_label = if td.src_cmdline.is_empty() {
        format!("pid {}", td.src_pid)
    } else {
        format!("pid {} ({})", td.src_pid, td.src_cmdline)
    };
    let dst_label = if td.dst_cmdline.is_empty() {
        format!("pid {}", td.dst_pid)
    } else {
        format!("pid {} ({})", td.dst_pid, td.dst_cmdline)
    };

    out.push_str(&format!(
        "{} frame {}  t=+{:.6}s  {} \u{2192} {}\n",
        arrow, frame, t_rel_secs, src_label, dst_label
    ));

    if td.reply == 0 {
        let base_call = match (td.interface.as_deref(), td.method.as_deref()) {
            (Some(iface), Some(method)) => format!("{}.{}()", iface, method),
            (Some(iface), None) => format!("{}::{}", iface, td.code),
            (None, _) => format!("<unknown interface>::{}", td.code),
        };
        out.push_str(&format!("  call:      {}\n", base_call));
        out.push_str(&format!("  flags:     0x{:x}\n", td.flags));
    } else {
        out.push_str("  reply\n");
    }
    out.push_str(&format!("  data:      {} bytes\n", td.data.len()));
    out.push_str(&format_hex_dump(&td.data, "  "));
    out.push_str(&format_offsets(&td.offsets));
    out
}

unsafe extern "C" fn conv_filter(
    _edt: *mut epan::epan_dissect_t,
    pinfo: *mut epan::packet_info,
    stream: *mut std::os::raw::c_uint,
    sub_stream: *mut std::os::raw::c_uint,
) -> *mut c_char {
    if pinfo.is_null() {
        return std::ptr::null_mut();
    }
    let frame = (*(*pinfo).fd).num;
    let Some(idx) = crate::reply_correlation::stream_index_for_frame(frame) else {
        return std::ptr::null_mut();
    };
    if !stream.is_null() {
        *stream = idx;
    }
    if !sub_stream.is_null() {
        *sub_stream = 0;
    }
    let filter = build_filter(idx);
    let Ok(c) = std::ffi::CString::new(filter) else {
        return std::ptr::null_mut();
    };
    epan::g_strdup(c.as_ptr())
}

unsafe extern "C" fn index_filter(
    stream: std::os::raw::c_uint,
    _sub_stream: std::os::raw::c_uint,
) -> *mut c_char {
    let filter = build_filter(stream);
    let Ok(c) = std::ffi::CString::new(filter) else {
        return std::ptr::null_mut();
    };
    epan::g_strdup(c.as_ptr())
}

unsafe extern "C" fn addr_filter_stub(
    _src: *mut epan::address,
    _dst: *mut epan::address,
    _sport: c_int,
    _dport: c_int,
) -> *mut c_char {
    std::ptr::null_mut()
}

unsafe extern "C" fn port_to_display_stub(
    _alloc: *mut epan::wmem_allocator_t,
    _port: std::os::raw::c_uint,
) -> *mut c_char {
    std::ptr::null_mut()
}

// tshark's `-z follow,<proto>,<mode>,<id>` validates `id < stream_count()`
// before invoking index_filter. We don't maintain a bounded stream universe
// (streams are debug_ids, which can be any positive i32), so return u32::MAX
// to skip the bound check. The Follow GUI uses conv_filter for the actual
// stream selection, so the count is informational only.
unsafe extern "C" fn stream_count_stub() -> u32 {
    u32::MAX
}

unsafe extern "C" fn tap_packet(
    tapdata: *mut c_void,
    pinfo: *mut epan::packet_info,
    _edt: *mut epan::epan_dissect_t,
    _data: *const c_void,
    _flags: epan::tap_flags_t,
) -> epan::tap_packet_status {
    if tapdata.is_null() || pinfo.is_null() {
        return epan::tap_packet_status_TAP_PACKET_DONT_REDRAW;
    }
    let info = tapdata as *mut epan::follow_info_t;
    let frame = (*(*pinfo).fd).num;

    let Some(td) = lookup(frame) else {
        return epan::tap_packet_status_TAP_PACKET_DONT_REDRAW;
    };

    let t_rel = compute_relative_ts(info, &td);
    let text = format_record(&td, frame, t_rel);

    // allocate record + byte array via glib so Wireshark frees them later
    let record =
        epan::g_malloc0(std::mem::size_of::<epan::follow_record_t>()) as *mut epan::follow_record_t;
    if record.is_null() {
        return epan::tap_packet_status_TAP_PACKET_DONT_REDRAW;
    }
    let arr = epan::g_byte_array_new();
    if arr.is_null() {
        epan::g_free(record as *mut c_void);
        return epan::tap_packet_status_TAP_PACKET_DONT_REDRAW;
    }
    epan::g_byte_array_append(arr, text.as_ptr(), text.len() as u32);

    let req_pid = crate::reply_correlation::req_pid_for_frame(frame).unwrap_or(0);
    (*record).is_server = is_server_for_party(&td, req_pid);
    (*record).packet_num = frame;
    (*record).seq = 0;
    (*record).abs_ts = (*(*pinfo).fd).abs_ts;
    (*record).data = arr;

    (*info).payload = epan::g_list_prepend((*info).payload, record as *mut c_void);

    let dir = if td.reply != 0 { 1 } else { 0 };
    (*info).bytes_written[dir] += text.len() as std::os::raw::c_uint;

    epan::tap_packet_status_TAP_PACKET_REDRAW
}

unsafe fn compute_relative_ts(info: *mut epan::follow_info_t, td: &TapData) -> f64 {
    // walk the existing payload list to find the earliest abs_ts seen so far
    let mut earliest = td.abs_ts;
    let mut node = (*info).payload;
    while !node.is_null() {
        let rec = (*node).data as *const epan::follow_record_t;
        if !rec.is_null() {
            let ts = (*rec).abs_ts;
            if ts.secs < earliest.secs || (ts.secs == earliest.secs && ts.nsecs < earliest.nsecs) {
                earliest = ts;
            }
        }
        node = (*node).next;
    }
    let dsec = td.abs_ts.secs - earliest.secs;
    let dns = td.abs_ts.nsecs - earliest.nsecs;
    dsec as f64 + dns as f64 / 1.0e9
}

pub fn register(proto_id: c_int) {
    unsafe {
        // Pass None for sub_stream_id: tshark's `-z follow,...` initializes
        // sub_stream_index to -1 when a sub_stream callback is registered, and
        // then rejects any stream because sub_stream_index<0 fails its check.
        // None makes it init to 0 instead.
        epan::register_follow_stream(
            proto_id,
            c"binderdump".as_ptr(),
            Some(conv_filter),
            Some(index_filter),
            Some(addr_filter_stub),
            Some(port_to_display_stub),
            Some(tap_packet),
            Some(stream_count_stub),
            None,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reply_correlation::FrameMeta;

    fn sample(frame_marker: i32) -> TapData {
        TapData {
            debug_id: frame_marker,
            in_reply_to_debug_id: 0,
            reply: 0,
            code: 33,
            flags: 0x10,
            interface: Some("a.b.IFoo".into()),
            method: Some("bar".into()),
            src_pid: 1,
            src_cmdline: "p1".into(),
            dst_pid: 2,
            dst_cmdline: "p2".into(),
            data: vec![],
            abs_ts: epan::nstime_t { secs: 0, nsecs: 0 },
            offsets: vec![],
        }
    }

    #[test]
    fn insert_then_lookup_roundtrips() {
        clear();
        insert(7, sample(42));
        let got = lookup(7).expect("present");
        assert_eq!(got.debug_id, 42);
    }

    #[test]
    fn clear_wipes_pool() {
        clear();
        insert(7, sample(42));
        clear();
        assert!(lookup(7).is_none());
    }

    #[test]
    fn lookup_unknown_returns_none() {
        clear();
        assert!(lookup(999).is_none());
    }

    #[test]
    fn stream_id_for_request_returns_debug_id() {
        let meta = FrameMeta {
            debug_id: 42,
            in_reply_to_debug_id: 0,
            reply: 0,
        };
        assert_eq!(stream_id_for(&meta), Some(42));
    }

    #[test]
    fn stream_id_for_reply_returns_in_reply_to() {
        let meta = FrameMeta {
            debug_id: 99,
            in_reply_to_debug_id: 42,
            reply: 1,
        };
        assert_eq!(stream_id_for(&meta), Some(42));
    }

    #[test]
    fn stream_id_zero_returns_none() {
        let meta_req = FrameMeta {
            debug_id: 0,
            in_reply_to_debug_id: 0,
            reply: 0,
        };
        let meta_rep = FrameMeta {
            debug_id: 99,
            in_reply_to_debug_id: 0,
            reply: 1,
        };
        assert_eq!(stream_id_for(&meta_req), None);
        assert_eq!(stream_id_for(&meta_rep), None);
    }

    #[test]
    fn build_filter_single_term() {
        assert_eq!(
            build_filter(13),
            "binderdump_reply.transaction_stream_id == 13"
        );
    }

    #[test]
    fn build_filter_zero_index_works() {
        assert_eq!(
            build_filter(0),
            "binderdump_reply.transaction_stream_id == 0"
        );
    }

    #[test]
    fn hex_dump_single_row_padded() {
        let out = format_hex_dump(&[0x41, 0x42, 0x43, 0x00], "  ");
        assert_eq!(
            out,
            "  0000  4142 4300                                ABC.            \n"
        );
    }

    #[test]
    fn hex_dump_full_row() {
        let bytes: Vec<u8> = (0..16).collect();
        let out = format_hex_dump(&bytes, "  ");
        assert_eq!(
            out,
            "  0000  0001 0203 0405 0607 0809 0a0b 0c0d 0e0f  ................\n"
        );
    }

    #[test]
    fn hex_dump_two_rows() {
        let bytes: Vec<u8> = (0..20).collect();
        let out = format_hex_dump(&bytes, "  ");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("  0000  "));
        assert!(lines[1].starts_with("  0010  "));
    }

    #[test]
    fn hex_dump_empty_yields_empty_string() {
        assert_eq!(format_hex_dump(&[], "  "), "");
    }

    fn ts(secs: i64, nsecs: i32) -> epan::nstime_t {
        epan::nstime_t { secs, nsecs }
    }

    #[test]
    fn format_record_request_resolved() {
        let td = TapData {
            debug_id: 42,
            in_reply_to_debug_id: 0,
            reply: 0,
            code: 33,
            flags: 0x10,
            interface: Some("android.os.IServiceManager".into()),
            method: Some("checkService".into()),
            src_pid: 1234,
            src_cmdline: "/system/bin/system_server".into(),
            dst_pid: 5678,
            dst_cmdline: "com.example.app".into(),
            data: vec![0x41, 0x42],
            abs_ts: ts(0, 0),
            offsets: vec![],
        };
        let out = format_record(&td, 23, 0.0);
        assert!(out.contains("\u{2192} frame 23"));
        assert!(out.contains("t=+0.000000s"));
        assert!(out
            .contains("pid 1234 (/system/bin/system_server) \u{2192} pid 5678 (com.example.app)"));
        assert!(out.contains("call:      android.os.IServiceManager.checkService()"));
        assert!(out.contains("flags:     0x10"));
        assert!(out.contains("data:      2 bytes"));
        assert!(out.contains("0000  4142"));
    }

    #[test]
    fn format_record_reply_minimal() {
        let td = TapData {
            debug_id: 99,
            in_reply_to_debug_id: 42,
            reply: 1,
            code: 0,
            flags: 0,
            interface: None,
            method: None,
            src_pid: 5678,
            src_cmdline: "com.example".into(),
            dst_pid: 1234,
            dst_cmdline: "system_server".into(),
            data: vec![0x0c, 0x00, 0x00, 0x00],
            abs_ts: ts(0, 1_247_000),
            offsets: vec![],
        };
        let out = format_record(&td, 26, 0.001247);
        assert!(out.contains("\u{2190} frame 26"));
        assert!(out.contains("reply"));
        assert!(out.contains("data:      4 bytes"));
        assert!(out.contains("0000  0c00 0000"));
        assert!(!out.contains("interface:"));
        assert!(!out.contains("method:"));
    }

    #[test]
    fn format_record_unresolved_request_uses_fallbacks() {
        let td = TapData {
            debug_id: 42,
            in_reply_to_debug_id: 0,
            reply: 0,
            code: 99,
            flags: 0,
            interface: None,
            method: None,
            src_pid: 1,
            src_cmdline: "".into(),
            dst_pid: 2,
            dst_cmdline: "".into(),
            data: vec![],
            abs_ts: ts(0, 0),
            offsets: vec![],
        };
        let out = format_record(&td, 1, 0.0);
        assert!(out.contains("call:      <unknown interface>::99"));
        assert!(out.contains("pid 1 \u{2192} pid 2"));
        assert!(out.contains("data:      0 bytes"));
        assert!(!out.contains("0000  "));
    }

    #[test]
    fn format_record_relative_time_microseconds() {
        let td = TapData {
            debug_id: 42,
            in_reply_to_debug_id: 0,
            reply: 0,
            code: 0,
            flags: 0,
            interface: None,
            method: None,
            src_pid: 0,
            src_cmdline: "".into(),
            dst_pid: 0,
            dst_cmdline: "".into(),
            data: vec![],
            abs_ts: ts(0, 0),
            offsets: vec![],
        };
        let out = format_record(&td, 1, 0.000024);
        assert!(out.contains("t=+0.000024s"), "actual: {}", out);
    }

    fn td_with(src_pid: i32, reply: i32) -> TapData {
        TapData {
            debug_id: 0,
            in_reply_to_debug_id: 0,
            reply,
            code: 0,
            flags: 0,
            interface: None,
            method: None,
            src_pid,
            src_cmdline: "".into(),
            dst_pid: 0,
            dst_cmdline: "".into(),
            data: vec![],
            abs_ts: epan::nstime_t { secs: 0, nsecs: 0 },
            offsets: vec![],
        }
    }

    #[test]
    fn is_server_uses_req_pid_when_known() {
        assert_eq!(is_server_for_party(&td_with(100, 0), 100), false);
        assert_eq!(is_server_for_party(&td_with(200, 0), 100), true);
        // direction (reply flag) ignored when req_pid is set
        assert_eq!(is_server_for_party(&td_with(100, 1), 100), false);
        assert_eq!(is_server_for_party(&td_with(200, 1), 100), true);
    }

    #[test]
    fn is_server_falls_back_to_reply_when_req_pid_zero() {
        assert_eq!(is_server_for_party(&td_with(100, 0), 0), false);
        assert_eq!(is_server_for_party(&td_with(100, 1), 0), true);
    }

    #[test]
    fn format_record_interface_known_method_unknown_uses_code() {
        let td = TapData {
            debug_id: 42,
            in_reply_to_debug_id: 0,
            reply: 0,
            code: 99,
            flags: 0,
            interface: Some("a.b.IFoo".into()),
            method: None,
            src_pid: 1,
            src_cmdline: "".into(),
            dst_pid: 2,
            dst_cmdline: "".into(),
            data: vec![],
            abs_ts: epan::nstime_t { secs: 0, nsecs: 0 },
            offsets: vec![],
        };
        let out = format_record(&td, 1, 0.0);
        assert!(out.contains("call:      a.b.IFoo::99"));
        // Verify NOT a method-call form (no '.' or '(' after the iface name).
        assert!(!out.contains("a.b.IFoo("));
    }

    use binderdump_structs::bwr_layer::{PtrPayload, TransactionProtocol};

    fn synth_handle_object(handle: u32, cookie: u64) -> Vec<u8> {
        // flat_binder_object: type(u32) + flags(u32) + union(8) + cookie(u64) = 24 bytes.
        let mut v = Vec::with_capacity(24);
        v.extend((binderdump_sys::BINDER_TYPE_HANDLE as u32).to_le_bytes());
        v.extend(0u32.to_le_bytes());
        v.extend((handle as u64).to_le_bytes()); // union: handle zero-extended
        v.extend(cookie.to_le_bytes());
        v
    }

    fn synth_fd_object(fd: i32) -> Vec<u8> {
        let mut v = Vec::with_capacity(24);
        v.extend((binderdump_sys::BINDER_TYPE_FD as u32).to_le_bytes());
        v.extend(0u32.to_le_bytes());
        v.extend((fd as u32 as u64).to_le_bytes());
        v.extend(0u64.to_le_bytes());
        v
    }

    fn synth_ptr_object(size: u64, buffer_addr: u64) -> Vec<u8> {
        // binder_buffer_object: type + flags + buffer(u64) + length(u64) + parent(u64) + parent_offset(u64) = 40 bytes.
        let mut v = Vec::with_capacity(40);
        v.extend((binderdump_sys::BINDER_TYPE_PTR as u32).to_le_bytes());
        v.extend(0u32.to_le_bytes());
        v.extend(buffer_addr.to_le_bytes());
        v.extend(size.to_le_bytes());
        v.extend(0u64.to_le_bytes());
        v.extend(0u64.to_le_bytes());
        v
    }

    fn txn_with(
        data: Vec<u8>,
        offsets: Vec<u64>,
        ptr_payloads: Vec<PtrPayload>,
    ) -> TransactionProtocol {
        let offsets_bytes: Vec<u8> = offsets.iter().flat_map(|o| o.to_le_bytes()).collect();
        let mut txn = TransactionProtocol::default();
        txn.data = data;
        txn.offsets = offsets_bytes;
        txn.ptr_payloads = ptr_payloads;
        txn
    }

    #[test]
    fn parse_offset_summaries_handle() {
        let obj = synth_handle_object(5, 0);
        let txn = txn_with(obj, vec![0], vec![]);
        let s = parse_offset_summaries(&txn).expect("ok");
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].idx, 0);
        match &s[0].kind {
            OffsetKind::Handle { weak, handle, .. } => {
                assert_eq!(*weak, false);
                assert_eq!(*handle, 5);
            }
            other => panic!("unexpected kind: {:?}", other),
        }
    }

    #[test]
    fn parse_offset_summaries_fd() {
        let obj = synth_fd_object(7);
        let txn = txn_with(obj, vec![0], vec![]);
        let s = parse_offset_summaries(&txn).expect("ok");
        assert_eq!(s.len(), 1);
        match &s[0].kind {
            OffsetKind::Fd { fd } => assert_eq!(*fd, 7),
            other => panic!("unexpected kind: {:?}", other),
        }
    }

    #[test]
    fn parse_offset_summaries_ptr_attaches_payload() {
        let obj = synth_ptr_object(44, 0x7f000000);
        let txn = txn_with(
            obj,
            vec![0],
            vec![PtrPayload {
                offset_index: 0,
                buffer_addr: 0x7f000000,
                total_size: 44,
                data: vec![1, 2, 3, 4],
            }],
        );
        let s = parse_offset_summaries(&txn).expect("ok");
        assert_eq!(s.len(), 1);
        match &s[0].kind {
            OffsetKind::Ptr {
                size,
                buffer_addr,
                payload,
                ..
            } => {
                assert_eq!(*size, 44);
                assert_eq!(*buffer_addr, 0x7f000000);
                assert_eq!(payload.as_deref(), Some([1u8, 2, 3, 4].as_slice()));
            }
            other => panic!("unexpected kind: {:?}", other),
        }
    }

    #[test]
    fn parse_offset_summaries_unknown_type_errors() {
        let mut obj = Vec::with_capacity(24);
        obj.extend(0xdeadbeef_u32.to_le_bytes());
        obj.extend(vec![0u8; 20]);
        let txn = txn_with(obj, vec![0], vec![]);
        let err = parse_offset_summaries(&txn).expect_err("expected error");
        let msg = format!("{}", err);
        assert!(msg.contains("0xdeadbeef"), "msg: {}", msg);
    }

    #[test]
    fn parse_offset_summaries_offset_past_data_stops() {
        let obj = synth_handle_object(5, 0);
        let txn = txn_with(obj, vec![100], vec![]);
        let s = parse_offset_summaries(&txn).expect("ok");
        // iter_flat_objects silently stops when an offsets entry points past
        // data — only the per-entry type id / size is treated as a hard error.
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn format_offsets_handle_one_line() {
        let s = vec![OffsetSummary {
            idx: 0,
            offset_in_buffer: 0,
            kind: OffsetKind::Handle {
                weak: false,
                handle: 5,
                cookie: 0,
            },
        }];
        let out = format_offsets(&s);
        assert!(out.contains("offsets:   8 bytes, 1 objects"));
        assert!(out.contains("[0] HANDLE  handle=5 cookie=0x0"));
        assert!(!out.contains("0000  "));
    }

    #[test]
    fn format_offsets_ptr_renders_inner_hex() {
        let s = vec![OffsetSummary {
            idx: 0,
            offset_in_buffer: 0,
            kind: OffsetKind::Ptr {
                size: 4,
                buffer_addr: 0x7fab,
                parent: 0,
                payload: Some(vec![0x41, 0x42, 0x43, 0x44]),
            },
        }];
        let out = format_offsets(&s);
        assert!(out.contains("[0] PTR     size=4 buffer_addr=0x7fab"));
        assert!(out.contains("0000  4142 4344"));
    }

    #[test]
    fn format_offsets_empty_returns_empty() {
        assert_eq!(format_offsets(&[]), String::new());
    }

    #[test]
    fn format_record_includes_offsets_block_when_nonempty() {
        let mut td = TapData {
            debug_id: 42,
            in_reply_to_debug_id: 0,
            reply: 0,
            code: 33,
            flags: 0,
            interface: Some("a.b.IFoo".into()),
            method: Some("bar".into()),
            src_pid: 1,
            src_cmdline: "p1".into(),
            dst_pid: 2,
            dst_cmdline: "p2".into(),
            data: vec![],
            abs_ts: epan::nstime_t { secs: 0, nsecs: 0 },
            offsets: vec![],
        };
        td.offsets.push(OffsetSummary {
            idx: 0,
            offset_in_buffer: 0,
            kind: OffsetKind::Handle {
                weak: false,
                handle: 5,
                cookie: 0,
            },
        });
        let out = format_record(&td, 1, 0.0);
        assert!(out.contains("offsets:"));
        assert!(out.contains("[0] HANDLE  handle=5"));
    }

    #[test]
    fn format_record_omits_offsets_block_when_empty() {
        let td = TapData {
            debug_id: 42,
            in_reply_to_debug_id: 0,
            reply: 0,
            code: 0,
            flags: 0,
            interface: None,
            method: None,
            src_pid: 0,
            src_cmdline: "".into(),
            dst_pid: 0,
            dst_cmdline: "".into(),
            data: vec![],
            abs_ts: epan::nstime_t { secs: 0, nsecs: 0 },
            offsets: vec![],
        };
        let out = format_record(&td, 1, 0.0);
        assert!(!out.contains("offsets:"));
    }
}
