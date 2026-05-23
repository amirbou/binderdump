#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(improper_ctypes)] // Suppress u128 warnings
include!(concat!(env!("OUT_DIR"), "/wireshark_gen.rs"));

// g_direct_hash/equal are exported glib symbols but hidden from bindgen by -fvisibility=hidden;
// declare them manually so wmem_map_new callers can use them as GHashFunc/GEqualFunc.
unsafe extern "C" {
    pub fn g_direct_hash(v: gconstpointer) -> guint;
    pub fn g_direct_equal(v1: gconstpointer, v2: gconstpointer) -> gboolean;
}
