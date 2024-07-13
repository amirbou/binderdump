mod dissect_offsets;
mod epan_plugin;
mod header_fields_manager;

use binderdump_epan_sys::epan;
use std::ffi::c_int;

const VERSION: &[u8] = b"0.0.1\0";

static G_PLUGIN: epan::proto_plugin = epan::proto_plugin {
    register_protoinfo: Some(epan_plugin::register_protoinfo),
    register_handoff: Some(epan_plugin::register_handoff),
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
        unsafe { epan::proto_register_plugin(std::ptr::addr_of!(G_PLUGIN)) };
    }
}
