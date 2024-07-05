mod header_fields;
use header_fields::{HeaderField, HeaderFieldArray};
use std::ptr::addr_of_mut;
use std::{
    ffi::{c_void, CStr, CString},
    os::raw::c_int,
    ptr::null_mut,
};

use bindump_epan_sys::epan;

use epan::EXP_PDU_TAG_PROTO_NAME;

const VERSION: &[u8] = b"0.0.1\0";
const PROTOCOL_NAME: &'static CStr = c"Android Binderdump";
const PROTOCOL_SHORT_NAME: &'static CStr = c"Binderdump";
const PROTOCOL_FILTER: &'static CStr = c"binderdump";

static mut HF_BINDERDUMP_PID: c_int = -1;
static mut HF_BINDERDUMP_TIMESTAMP: c_int = -1;
static mut ETT_BINDERDUMP: c_int = -1;
static mut ETT: [*mut c_int; 1] = unsafe { [addr_of_mut!(ETT_BINDERDUMP)] };

static mut HF_ARRAY: HeaderFieldArray<2> = unsafe {
    HeaderFieldArray::new([
        HeaderField::new(
            c"Timestamp",
            c"binderdump.timestamp",
            epan::ftenum::FT_RELATIVE_TIME,
            epan::field_display_e::BASE_NONE,
            vec![],
            addr_of_mut!(HF_BINDERDUMP_TIMESTAMP),
        ),
        HeaderField::new(
            c"PID",
            c"binderdump.pid",
            epan::ftenum::FT_UINT32,
            epan::field_display_e::BASE_DEC,
            vec![],
            addr_of_mut!(HF_BINDERDUMP_PID),
        ),
    ])
};

static mut BINDERDUMP_HANDLE: epan::dissector_handle_t = std::ptr::null_mut();
static mut PROTO_BINDERDUMP: c_int = -1;
static mut EXPORTED_PDU_TAP: c_int = -1;
static PLUG_BINDERDUMP: epan::proto_plugin = epan::proto_plugin {
    register_protoinfo: Some(proto_register_binderdump),
    register_handoff: (Some(proto_reg_handoff_binderdump)),
};

mod exported_symbols {
    use super::*;

    #[no_mangle]
    #[used]
    // TODO - figure out how to use env!("CARGO_PKG_VERSION") for that (maybe generate in build.rs and include here?)
    pub static plugin_version: [epan::gchar; VERSION.len()] = {
        let mut ver = [0; VERSION.len()];
        let mut i = 0;
        while i < VERSION.len() {
            ver[i] = VERSION[i] as epan::gchar;
            i += 1;
        }
        ver
    };

    #[no_mangle]
    #[used]
    pub static plugin_want_major: c_int = epan::VERSION_MAJOR as c_int;

    #[no_mangle]
    #[used]
    pub static plugin_want_minor: c_int = epan::VERSION_MINOR as c_int;

    #[no_mangle]
    pub extern "C" fn plugin_register() {
        unsafe { epan::proto_register_plugin(std::ptr::addr_of!(PLUG_BINDERDUMP)) };
    }
}

extern "C" fn proto_reg_handoff_binderdump() {
    let table = CString::new("wtap_encap").unwrap();

    unsafe {
        epan::dissector_add_uint(
            table.as_ptr(),
            epan::WTAP_ENCAP_USER0, // TODO - configure during compilation
            BINDERDUMP_HANDLE,
        )
    };
}

extern "C" fn proto_register_binderdump() {
    unsafe {
        PROTO_BINDERDUMP = epan::proto_register_protocol(
            PROTOCOL_NAME.as_ptr(),
            PROTOCOL_SHORT_NAME.as_ptr(),
            PROTOCOL_FILTER.as_ptr(),
        );

        BINDERDUMP_HANDLE = epan::register_dissector(
            PROTOCOL_FILTER.as_ptr(),
            Some(dissect_binderdump),
            PROTO_BINDERDUMP,
        );

        EXPORTED_PDU_TAP = epan::register_export_pdu_tap(PROTOCOL_NAME.as_ptr());

        HF_ARRAY.register(PROTO_BINDERDUMP);
        epan::proto_register_subtree_array(ETT.as_ptr(), ETT.len().try_into().unwrap());
    };
}

fn add_exported_pdu(tvb: *mut epan::tvbuff_t, pinfo: *mut epan::packet_info) {
    unsafe {
        if epan::have_tap_listener(EXPORTED_PDU_TAP) != 0 {
            let exp_pdu_data = epan::export_pdu_create_tags(
                pinfo,
                PROTOCOL_FILTER.as_ptr(),
                EXP_PDU_TAG_PROTO_NAME as u16,
                null_mut(),
            );

            (*exp_pdu_data).tvb_captured_length = epan::tvb_captured_length(tvb);
            (*exp_pdu_data).tvb_reported_length = epan::tvb_reported_length(tvb);
            (*exp_pdu_data).pdu_tvb = tvb;
            epan::tap_queue_packet(EXPORTED_PDU_TAP, pinfo, exp_pdu_data as *mut c_void);
        }
    };
}

extern "C" fn dissect_binderdump(
    tvb: *mut epan::tvbuff_t,
    pinfo: *mut epan::packet_info,
    tree: *mut epan::proto_tree,
    _data: *mut c_void,
) -> c_int {
    unsafe {
        epan::col_set_str(
            (*pinfo).cinfo,
            epan::COL_PROTOCOL as c_int,
            PROTOCOL_SHORT_NAME.as_ptr(),
        );
        epan::col_clear((*pinfo).cinfo, epan::COL_INFO as c_int);
        add_exported_pdu(tvb, pinfo);
        let ti = epan::proto_tree_add_item(tree, PROTO_BINDERDUMP, tvb, 0, -1, epan::ENC_NA);
        let binderdump_tree = epan::proto_item_add_subtree(ti, ETT_BINDERDUMP);
        epan::proto_tree_add_item(
            binderdump_tree,
            HF_BINDERDUMP_TIMESTAMP,
            tvb,
            0,
            8,
            epan::ENC_LITTLE_ENDIAN,
        );
        epan::proto_tree_add_item(
            binderdump_tree,
            HF_BINDERDUMP_PID,
            tvb,
            8,
            4,
            epan::ENC_LITTLE_ENDIAN,
        );
        epan::tvb_captured_length(tvb) as c_int
    }
}
