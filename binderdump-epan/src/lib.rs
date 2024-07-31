pub mod dissector;
// pub mod epan_plugin;

pub use binderdump_epan_sys::epan;
pub use dissector::DissectorManager;

use std::ffi::c_int;

#[macro_export]
macro_rules! export_dissector {
    ($dissector:ident) => {
        mod _epan_internal {
            use super::*;
            static G_PLUGIN: crate::epan::proto_plugin = crate::epan::proto_plugin {
                register_protoinfo: Some(register_protoinfo),
                register_handoff: Some(register_handoff),
            };

            static G_DISSECTOR: std::sync::OnceLock<crate::DissectorManager<$dissector>> =
                std::sync::OnceLock::new();

            #[no_mangle]
            pub extern "C" fn plugin_register() {
                unsafe { crate::epan::proto_register_plugin(std::ptr::addr_of!(G_PLUGIN)) };
            }

            pub extern "C" fn register_protoinfo() {
                G_DISSECTOR.get_or_init(|| crate::DissectorManager::<$dissector>::new());
            }

            pub extern "C" fn register_handoff() {
                unsafe {
                    crate::epan::dissector_add_uint(
                        c"wtap_encap".as_ptr(),
                        crate::epan::WTAP_ENCAP_USER0, // TODO - configure during compilation
                        G_DISSECTOR.get().unwrap().get_handle(),
                    )
                };
            }
        }
    };
}

#[macro_export]
macro_rules! export_version {
    ($version:literal) => {
        mod _epan_internal_version {
            use binderdump_epan_sys::epan;
            #[no_mangle]
            #[used]
            // TODO - figure out how to use env!("CARGO_PKG_VERSION") for that (maybe generate in build.rs and include here?)
            pub static plugin_version: [epan::gchar; $version.len()] = {
                let mut ver = [0; $version.len()];
                let mut i = 0;
                while i < $version.len() {
                    ver[i] = $version[i] as epan::gchar;
                    i += 1;
                }
                ver
            };
        }
    };
}

mod exported_symbols {
    use super::*;

    #[no_mangle]
    #[used]
    pub static plugin_want_major: c_int = epan::VERSION_MAJOR as c_int;

    #[no_mangle]
    #[used]
    pub static plugin_want_minor: c_int = epan::VERSION_MINOR as c_int;
}

#[cfg(test)]
mod test {
    use crate::dissector::Dissector;
    use binderdump_derive::EpanProtocol;
    #[derive(EpanProtocol)]
    #[allow(unused)]
    struct TestProtocol {
        foo: i32,
    }

    struct TestDissector {}

    impl Dissector for TestDissector {
        const PROTOCOL_NAME: &'static std::ffi::CStr = c"Test";

        const PROTOCOL_SHORT_NAME: &'static std::ffi::CStr = c"Test";

        const PROTOCOL_FILTER: &'static std::ffi::CStr = c"test";

        type Protocol = TestProtocol;
        type Error = ();
    }

    export_version!(b"0.0.1");
    export_dissector!(TestDissector);

    #[test]
    fn test_compile() {}
}
