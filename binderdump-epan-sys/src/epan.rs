#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(improper_ctypes)]
// Suppress u128 warnings
// glib G_E / G_PI / G_LN2 etc. flow through bindgen as plain float consts;
// clippy flags them as approximate values of std::f64::consts::*. The
// generated file can't reach for std::f64::consts (it's a verbatim
// bindgen include), so allow the lint here. Same applies to
// useless_transmute on glib bitfield accessors.
#![allow(clippy::approx_constant)]
#![allow(clippy::useless_transmute)]
include!(concat!(env!("OUT_DIR"), "/wireshark_gen.rs"));

// g_direct_hash/equal are exported glib symbols but hidden from bindgen by -fvisibility=hidden;
// declare them manually so wmem_map_new callers can use them as GHashFunc/GEqualFunc.
unsafe extern "C" {
    pub fn g_direct_hash(v: gconstpointer) -> guint;
    pub fn g_direct_equal(v1: gconstpointer, v2: gconstpointer) -> gboolean;
    pub fn g_strdup(s: *const std::os::raw::c_char) -> *mut std::os::raw::c_char;
    pub fn g_byte_array_append(
        array: *mut GByteArray,
        data: *const u8,
        len: u32,
    ) -> *mut GByteArray;
    pub fn g_malloc0(n_bytes: usize) -> *mut std::os::raw::c_void;
    pub fn g_byte_array_new() -> *mut GByteArray;
    pub fn g_byte_array_free(array: *mut GByteArray, free_segment: gboolean) -> *mut u8;
    pub fn g_free(mem: *mut std::os::raw::c_void);
    pub fn g_list_prepend(list: *mut GList, data: *mut std::os::raw::c_void) -> *mut GList;
}
