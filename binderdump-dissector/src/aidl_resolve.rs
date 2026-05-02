// Glue between the binderdump-aidl Registry and the dissector. Reads the
// transaction payload, peels the interface descriptor, looks up the method,
// and tags how the resolution happened (builtin / overlay / special / etc.)
// for the `binder.transaction.method_source` field.

use binderdump_aidl::token::{parse_aidl_token, parse_hidl_token};
use binderdump_aidl::{Lookup, Registry, Source};
use binderdump_structs::binder_types::BinderInterface;
use std::sync::OnceLock;

pub struct ResolvedTransaction {
    pub interface: Option<String>,
    pub method_name: Option<String>,
    // one of: "builtin", "overlay", "special", "unknown_iface", "unknown_code", "no_token"
    pub method_source: &'static str,
    pub overlay_path: Option<String>,
}

pub fn resolve(
    reg: &Registry,
    iface: BinderInterface,
    code: u32,
    android_sdk: u32,
    data_buf: &[u8],
) -> ResolvedTransaction {
    let interface = match iface {
        BinderInterface::BINDER | BinderInterface::VNDBINDER => {
            parse_aidl_token(data_buf, android_sdk)
        }
        BinderInterface::HWBINDER => parse_hidl_token(data_buf),
    };

    // Special codes are interface-agnostic - check first.
    if let Some(s) = binderdump_aidl::registry::lookup_special(code) {
        return ResolvedTransaction {
            interface,
            method_name: Some(binderdump_aidl::registry::special_method_name(s).to_string()),
            method_source: "special",
            overlay_path: None,
        };
    }

    let Some(fqn) = interface.as_deref() else {
        return ResolvedTransaction {
            interface: None,
            method_name: None,
            method_source: "no_token",
            overlay_path: None,
        };
    };

    match reg.resolve(android_sdk, fqn, code) {
        Lookup::Hit { method, source } => {
            let (src_label, overlay_path) = match source {
                Source::Builtin => ("builtin", None),
                Source::Overlay(p) => ("overlay", Some(p.display().to_string())),
            };
            ResolvedTransaction {
                interface: interface.clone(),
                method_name: Some(method.name.clone()),
                method_source: src_label,
                overlay_path,
            }
        }
        Lookup::UnknownInterface => ResolvedTransaction {
            interface: interface.clone(),
            method_name: None,
            method_source: "unknown_iface",
            overlay_path: None,
        },
        Lookup::UnknownCode { interface: _ } => ResolvedTransaction {
            interface: interface.clone(),
            method_name: None,
            method_source: "unknown_code",
            overlay_path: None,
        },
        Lookup::SpecialCode(_) => unreachable!("checked above"),
    }
}

// builtin-only stub for v1; init_registry replaces this in the next commit
static REGISTRY: OnceLock<Registry> = OnceLock::new();

pub fn registry() -> &'static Registry {
    REGISTRY.get_or_init(Registry::with_builtin)
}
