// post-dissector that adds cross-frame correlation fields (response_in,
// response_to, response_time, request interface/method) to binderdump frames.
// registered as a Wireshark post-dissector so it runs after the main
// binderdump dissector has populated the reply_correlation state.

use crate::epan_utils::{
    add_generated_string, add_generated_time, add_generated_uint, make_hf_register_info,
};
use binderdump_epan_sys::epan;
use std::ffi::{c_int, c_void, CString};
use std::sync::OnceLock;

static mut HF_RESPONSE_IN: c_int = -1;
static mut HF_RESPONSE_TO: c_int = -1;
static mut HF_RESPONSE_TIME: c_int = -1;
static mut HF_REQUEST_INTERFACE: c_int = -1;
static mut HF_REQUEST_METHOD: c_int = -1;
static mut HF_TRANSACTION_STREAM_ID: c_int = -1;
static mut ETT_BINDERDUMP_REPLY: c_int = -1;

static mut EI_ORPHAN_REPLY: epan::expert_field = epan::expert_field { ei: -1, hf: -1 };

static PROTO_ID: OnceLock<c_int> = OnceLock::new();

#[allow(static_mut_refs)]
pub fn register() {
    let proto_id = unsafe {
        epan::proto_register_protocol(
            c"Binderdump Reply Correlation".as_ptr(),
            c"Binderdump Reply".as_ptr(),
            c"binderdump_reply".as_ptr(),
        )
    };
    PROTO_ID.get_or_init(|| proto_id);

    // these strings are embedded in c"..." literals so they live for the
    // process lifetime — safe to hand raw pointers to Wireshark.
    static mut HF_INFO: [epan::hf_register_info; 6] = unsafe { std::mem::zeroed() };

    unsafe {
        // FRAMENUM_TYPE: smuggle the request/response role through the
        // `strings` pointer field — Wireshark reads it as GPOINTER_TO_INT.
        HF_INFO[0] = make_hf_register_info(
            &raw mut HF_RESPONSE_IN,
            c"Response In",
            c"binderdump_reply.response_in",
            epan::ftenum::FT_FRAMENUM,
            epan::field_display_e::BASE_NONE as c_int,
            epan::ft_framenum_type_FT_FRAMENUM_RESPONSE as usize as *const c_void,
        );
        HF_INFO[1] = make_hf_register_info(
            &raw mut HF_RESPONSE_TO,
            c"Request In",
            c"binderdump_reply.response_to",
            epan::ftenum::FT_FRAMENUM,
            epan::field_display_e::BASE_NONE as c_int,
            epan::ft_framenum_type_FT_FRAMENUM_REQUEST as usize as *const c_void,
        );
        HF_INFO[2] = make_hf_register_info(
            &raw mut HF_RESPONSE_TIME,
            c"Response Time",
            c"binderdump_reply.response_time",
            epan::ftenum::FT_RELATIVE_TIME,
            epan::field_display_e::BASE_NONE as c_int,
            std::ptr::null(),
        );
        HF_INFO[3] = make_hf_register_info(
            &raw mut HF_REQUEST_INTERFACE,
            c"Request Interface",
            c"binderdump_reply.request_interface",
            epan::ftenum::FT_STRING,
            epan::field_display_e::BASE_NONE as c_int,
            std::ptr::null(),
        );
        HF_INFO[4] = make_hf_register_info(
            &raw mut HF_REQUEST_METHOD,
            c"Request Method",
            c"binderdump_reply.request_method",
            epan::ftenum::FT_STRING,
            epan::field_display_e::BASE_NONE as c_int,
            std::ptr::null(),
        );
        HF_INFO[5] = make_hf_register_info(
            &raw mut HF_TRANSACTION_STREAM_ID,
            c"Transaction stream ID",
            c"binderdump_reply.transaction_stream_id",
            epan::ftenum::FT_UINT32,
            epan::field_display_e::BASE_DEC as c_int,
            std::ptr::null(),
        );

        epan::proto_register_field_array(proto_id, HF_INFO.as_mut_ptr(), HF_INFO.len() as c_int);

        let ett_ptrs: [*mut c_int; 1] = [&raw mut ETT_BINDERDUMP_REPLY];
        epan::proto_register_subtree_array(ett_ptrs.as_ptr() as *const *mut _, 1);

        // expert info: a reply whose originating BC_TRANSACTION was never
        // captured (capture started mid-flight, ringbuf drop, etc).
        static mut EI: [epan::ei_register_info; 1] = unsafe { std::mem::zeroed() };
        EI[0] = epan::ei_register_info {
            ids: &raw mut EI_ORPHAN_REPLY,
            eiinfo: epan::expert_field_info {
                name: c"binderdump_reply.orphan_reply".as_ptr(),
                group: epan::PI_SEQUENCE as c_int,
                severity: epan::PI_NOTE as c_int,
                summary: c"Reply with no matching originating transaction".as_ptr(),
                id: 0,
                protocol: std::ptr::null(),
                orig_severity: 0,
                hf_info: std::mem::zeroed(),
            },
        };
        let em = epan::expert_register_protocol(proto_id);
        epan::expert_register_field_array(em, EI.as_mut_ptr(), EI.len() as c_int);
    }
}

pub fn register_handoff() {
    let proto_id = match PROTO_ID.get() {
        Some(&id) => id,
        None => return,
    };
    unsafe {
        let handle = epan::create_dissector_handle(Some(dissect), proto_id);
        epan::register_postdissector(handle);
    }
}

unsafe extern "C" fn dissect(
    tvb: *mut epan::tvbuff_t,
    pinfo: *mut epan::packet_info,
    tree: *mut epan::proto_tree,
    _data: *mut c_void,
) -> c_int {
    // only run on frames that the main binderdump dissector handled
    if !epan::proto_is_frame_protocol((*pinfo).layers, c"binderdump".as_ptr()) {
        return 0;
    }

    let frame = (*(*pinfo).fd).num;

    let meta = crate::reply_correlation::lookup_frame(frame);
    let complete_for = crate::txn_complete_tracker::lookup_frame(frame);
    let free_for = crate::txn_complete_tracker::lookup_free(frame);

    // bail if neither source has anything for this frame
    let meta_useful = meta
        .as_ref()
        .map(|m| m.debug_id != 0 || m.in_reply_to_debug_id != 0)
        .unwrap_or(false);
    if !meta_useful && complete_for.is_none() && free_for.is_none() {
        return 0;
    }

    // add a subtree root for the correlation fields
    let proto_id = match PROTO_ID.get() {
        Some(&id) => id,
        None => return 0,
    };
    let root = epan::proto_tree_add_item(tree, proto_id, tvb, 0, -1, epan::ENC_NA);
    epan::binderdump_proto_item_set_generated(root);
    let subtree = epan::proto_item_add_subtree(root, ETT_BINDERDUMP_REPLY);

    if let Some(meta) = meta {
        if meta.reply == 0 {
            dissect_request(subtree, tvb, &meta);
        } else {
            dissect_reply(subtree, tvb, pinfo, root, &meta);
        }
    }

    let stream_index = crate::reply_correlation::stream_index_for_frame(frame)
        .or_else(|| complete_for.and_then(crate::reply_correlation::stream_index_for_any_debug_id))
        .or_else(|| free_for.and_then(crate::reply_correlation::stream_index_for_any_debug_id));

    if let Some(idx) = stream_index {
        add_generated_uint(subtree, HF_TRANSACTION_STREAM_ID, tvb, idx);
    }

    epan::tvb_captured_length(tvb) as c_int
}

unsafe fn dissect_request(
    subtree: *mut epan::proto_tree,
    tvb: *mut epan::tvbuff_t,
    meta: &crate::reply_correlation::FrameMeta,
) {
    let Some(txn) = crate::reply_correlation::lookup_txn(meta.debug_id) else {
        return;
    };
    if txn.rep_frame == 0 {
        return;
    }
    add_generated_uint(subtree, HF_RESPONSE_IN, tvb, txn.rep_frame);
}

unsafe fn dissect_reply(
    subtree: *mut epan::proto_tree,
    tvb: *mut epan::tvbuff_t,
    pinfo: *mut epan::packet_info,
    root: *mut epan::proto_item,
    meta: &crate::reply_correlation::FrameMeta,
) {
    let key = meta.in_reply_to_debug_id;
    let txn = crate::reply_correlation::lookup_txn(key);
    if key != 0 && txn.is_none() {
        // capture started mid-flight or the request frame was lost — flag
        // it so users can see why no link is present.
        epan::expert_add_info(pinfo, root, &raw mut EI_ORPHAN_REPLY);
    }
    let Some(txn) = txn else { return };

    if txn.req_frame != 0 {
        add_generated_uint(subtree, HF_RESPONSE_TO, tvb, txn.req_frame);
    }

    if let Some(req_ts) = txn.req_time {
        let rep_ts = (*(*pinfo).fd).abs_ts;
        let mut delta = epan::nstime_t { secs: 0, nsecs: 0 };
        epan::nstime_delta(&mut delta, &rep_ts, &req_ts);
        add_generated_time(subtree, HF_RESPONSE_TIME, tvb, &delta);
    }

    if let Some(iface) = txn.interface.as_deref() {
        add_generated_string(subtree, HF_REQUEST_INTERFACE, tvb, iface);
    }
    if let Some(method) = txn.method_name.as_deref() {
        add_generated_string(subtree, HF_REQUEST_METHOD, tvb, method);
    }

    // Overwrite the bare "← reply" set by the main dissector with the
    // enriched form so users see what call this reply belongs to.
    if let Some(label) = reply_col_info(txn.interface.as_deref(), txn.method_name.as_deref()) {
        if let Ok(cs) = CString::new(label) {
            epan::col_add_str((*pinfo).cinfo, epan::COL_INFO as c_int, cs.as_ptr());
        }
    }
}

fn reply_col_info(iface: Option<&str>, method: Option<&str>) -> Option<String> {
    let method = method?;
    // Special transactions are interface-agnostic; show the bare name, matching
    // the request-side COL_INFO and the method_name field.
    let is_special = binderdump_aidl::registry::is_special_method_name(method);
    Some(match iface {
        Some(i) if !is_special => format!("\u{2190} reply to {}.{}()", i, method),
        _ => format!("\u{2190} reply to {}", method),
    })
}

#[cfg(test)]
mod tests {
    use super::reply_col_info;

    #[test]
    fn normal_method_with_interface() {
        assert_eq!(
            reply_col_info(Some("IServiceManager"), Some("checkService")).as_deref(),
            Some("\u{2190} reply to IServiceManager.checkService()")
        );
    }

    #[test]
    fn normal_method_without_interface_is_bare() {
        assert_eq!(
            reply_col_info(None, Some("checkService")).as_deref(),
            Some("\u{2190} reply to checkService")
        );
    }

    #[test]
    fn no_method_is_none() {
        assert_eq!(reply_col_info(Some("IFoo"), None), None);
    }

    // Special transactions inherit whatever interface the request carried
    // (None / "" / "<query>"); the reply label must show the bare name in all
    // three, never ".NAME()" or "<query>.NAME()".
    #[test]
    fn special_transaction_is_bare_regardless_of_interface() {
        for iface in [None, Some(""), Some("<query>")] {
            assert_eq!(
                reply_col_info(iface, Some("DUMP_TRANSACTION")).as_deref(),
                Some("\u{2190} reply to DUMP_TRANSACTION"),
                "iface = {iface:?}"
            );
        }
    }
}
