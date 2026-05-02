// Reads Android system properties via bionic's `__system_property_get`.
// Used to stamp the active SDK version onto each captured event so the
// dissector picks the right per-version method table.

use std::ffi::CString;
use std::sync::OnceLock;

extern "C" {
    fn __system_property_get(
        name: *const std::os::raw::c_char,
        value: *mut std::os::raw::c_char,
    ) -> std::os::raw::c_int;
}

const PROP_VALUE_MAX: usize = 92;

// ro.build.version.sdk never changes for a running device, and the FFI
// hop into bionic is wasted work past the first read.
static SDK_INT: OnceLock<u32> = OnceLock::new();

pub fn read_sdk_int() -> u32 {
    *SDK_INT.get_or_init(query_sdk_int)
}

fn query_sdk_int() -> u32 {
    let name = CString::new("ro.build.version.sdk").expect("CString");
    let mut buf = vec![0i8; PROP_VALUE_MAX];
    let n = unsafe { __system_property_get(name.as_ptr(), buf.as_mut_ptr() as *mut _) };
    if n <= 0 {
        return 0;
    }
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const _) };
    s.to_str().ok().and_then(|t| t.parse().ok()).unwrap_or(0)
}
