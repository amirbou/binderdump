use binderdump_epan_sys::epan;
use std::ffi::{c_int, CString};
use std::os::raw::c_void;

/// Build an `hf_register_info` with the HFILL-default tail filled in. The
/// `name` / `abbrev` `CStr`s must live for the process lifetime — typically
/// they come from `c"..."` literals.
pub unsafe fn make_hf_register_info(
    p_id: *mut c_int,
    name: &std::ffi::CStr,
    abbrev: &std::ffi::CStr,
    ftype: epan::ftenum,
    display: c_int,
    strings: *const c_void,
) -> epan::hf_register_info {
    epan::hf_register_info {
        p_id,
        hfinfo: epan::header_field_info {
            name: name.as_ptr(),
            abbrev: abbrev.as_ptr(),
            type_: ftype,
            display,
            strings,
            bitmask: 0,
            blurb: std::ptr::null(),
            id: -1,
            parent: 0,
            ref_type: 0,
            same_name_prev_id: -1,
            same_name_next: std::ptr::null_mut(),
        },
    }
}

/// Add a `FT_UINT*` proto-tree item at offset 0 / length 0 and mark it
/// generated. Used by post-dissectors that emit synthetic cross-frame
/// references (response_in / response_to / transaction_stream_id / ...).
pub unsafe fn add_generated_uint(
    tree: *mut epan::proto_tree,
    hf: c_int,
    tvb: *mut epan::tvbuff_t,
    value: u32,
) {
    let it = epan::proto_tree_add_uint(tree, hf, tvb, 0, 0, value);
    epan::binderdump_proto_item_set_generated(it);
}

/// Same as `add_generated_uint` but for `FT_RELATIVE_TIME` / `FT_ABSOLUTE_TIME`.
pub unsafe fn add_generated_time(
    tree: *mut epan::proto_tree,
    hf: c_int,
    tvb: *mut epan::tvbuff_t,
    value: &epan::nstime_t,
) {
    let it = epan::proto_tree_add_time(tree, hf, tvb, 0, 0, value);
    epan::binderdump_proto_item_set_generated(it);
}

/// Add a generated `FT_INT*` proto-tree item at offset 0 / length 0.
pub unsafe fn add_generated_int(
    tree: *mut epan::proto_tree,
    hf: c_int,
    tvb: *mut epan::tvbuff_t,
    value: i32,
) {
    let it = epan::proto_tree_add_int(tree, hf, tvb, 0, 0, value);
    epan::binderdump_proto_item_set_generated(it);
}

/// Add a generated `FT_STRING` item for the given `&str`. No-op (false
/// return) if the string contains an interior NUL byte.
pub unsafe fn add_generated_string(
    tree: *mut epan::proto_tree,
    hf: c_int,
    tvb: *mut epan::tvbuff_t,
    value: &str,
) -> bool {
    let Ok(cs) = CString::new(value) else {
        return false;
    };
    let it = epan::proto_tree_add_string(tree, hf, tvb, 0, 0, cs.as_ptr());
    epan::binderdump_proto_item_set_generated(it);
    true
}
