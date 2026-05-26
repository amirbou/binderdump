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
    static mut HF_INFO: [epan::hf_register_info; 5] = unsafe { std::mem::zeroed() };

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

    let meta = match crate::reply_correlation::lookup_frame(frame) {
        Some(m) => m,
        None => return 0,
    };

    if meta.debug_id == 0 && meta.in_reply_to_debug_id == 0 {
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

    if meta.reply == 0 {
        // this is a request — look up whether a reply was seen and add response_in
        if let Some(txn) = crate::reply_correlation::lookup_txn(meta.debug_id) {
            if txn.rep_frame != 0 {
                add_generated_uint(subtree, HF_RESPONSE_IN, tvb, txn.rep_frame);
            }
        }
    } else {
        // this is a reply — link back to the request
        let key = meta.in_reply_to_debug_id;
        let txn = crate::reply_correlation::lookup_txn(key);
        if key != 0 && txn.is_none() {
            // capture started mid-flight or the request frame was lost — flag
            // it so users can see why no link is present.
            epan::expert_add_info(pinfo, root, &raw mut EI_ORPHAN_REPLY);
        }
        if let Some(txn) = txn {
            if txn.req_frame != 0 {
                add_generated_uint(subtree, HF_RESPONSE_TO, tvb, txn.req_frame);
            }

            // response time: delta = reply_ts - req_ts
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
            if let Some(method) = txn.method_name.as_deref() {
                let label = match txn.interface.as_deref() {
                    Some(iface) => format!("\u{2190} reply to {}.{}()", iface, method),
                    None => format!("\u{2190} reply to {}", method),
                };
                if let Ok(cs) = CString::new(label) {
                    epan::col_add_str((*pinfo).cinfo, epan::COL_INFO as c_int, cs.as_ptr());
                }
            }
        }
    }

    epan::tvb_captured_length(tvb) as c_int
}
