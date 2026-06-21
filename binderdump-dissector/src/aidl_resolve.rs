// Glue between the binderdump-aidl Registry and the dissector. Reads the
// transaction payload, peels the interface descriptor, looks up the method,
// and tags how the resolution happened (aosp / overlay / special / etc.)
// for the `binder.transaction.method_source` field.

use binderdump_aidl::token::{aidl_params_start, parse_aidl_token, parse_hidl_token};
use binderdump_aidl::{Lookup, Method, Registry, Source};
use binderdump_structs::binder_types::BinderInterface;
use std::sync::OnceLock;

pub struct ResolvedTransaction<'a> {
    pub interface: Option<String>,
    pub method_name: Option<String>,
    // one of: "aosp", "overlay", "special", "unknown_iface", "unknown_code", "no_token"
    pub method_source: &'static str,
    pub overlay_path: Option<String>,
    pub method: Option<&'a Method>, // resolved method, for param decode
    pub params_start: Option<usize>, // AIDL: offset where params begin
}

pub fn resolve<'a>(
    reg: &'a Registry,
    iface: BinderInterface,
    code: u32,
    android_sdk: u32,
    data_buf: &[u8],
) -> ResolvedTransaction<'a> {
    let (interface, params_start) = match iface {
        BinderInterface::BINDER | BinderInterface::VNDBINDER => {
            let iface = parse_aidl_token(data_buf, android_sdk);
            let start = aidl_params_start(data_buf, android_sdk);
            (iface, start)
        }
        BinderInterface::HWBINDER => (parse_hidl_token(data_buf), None),
    };

    // Special codes are interface-agnostic - check first.
    if let Some(s) = binderdump_aidl::registry::lookup_special(code) {
        let interface = match s {
            binderdump_aidl::registry::SpecialTxn::Interface if interface.is_none() => {
                Some("<query>".to_string())
            }
            _ => interface,
        };
        return ResolvedTransaction {
            interface,
            method_name: Some(binderdump_aidl::registry::special_method_name(s).to_string()),
            method_source: "special",
            overlay_path: None,
            method: None,
            params_start,
        };
    }

    let Some(fqn) = interface.as_deref() else {
        return ResolvedTransaction {
            interface: None,
            method_name: None,
            method_source: "no_token",
            overlay_path: None,
            method: None,
            params_start,
        };
    };

    match reg.resolve(android_sdk, fqn, code) {
        Lookup::Hit { method, source } => {
            let (src_label, overlay_path) = match source {
                Source::Overlay(p) => ("overlay", Some(p.display().to_string())),
                Source::Lazy => ("aosp", None),
                Source::Native => ("native", None),
            };
            ResolvedTransaction {
                interface: interface.clone(),
                method_name: Some(method.name.clone()),
                method_source: src_label,
                overlay_path,
                method: Some(method),
                params_start,
            }
        }
        Lookup::UnknownInterface => {
            let label = if let Some(fqn_str) = interface.as_deref() {
                if binderdump_aidl::native_interfaces::is_native(fqn_str) {
                    "native"
                } else {
                    "unknown_iface"
                }
            } else {
                "unknown_iface"
            };
            ResolvedTransaction {
                interface: interface.clone(),
                method_name: None,
                method_source: label,
                overlay_path: None,
                method: None,
                params_start,
            }
        }
        Lookup::UnknownCode { interface: _ } => ResolvedTransaction {
            interface: interface.clone(),
            method_name: None,
            method_source: "unknown_code",
            overlay_path: None,
            method: None,
            params_start,
        },
        Lookup::SpecialCode(_) => unreachable!("checked above"),
    }
}

// populated once at plugin load (init_registry); falls back to empty registry
// when callers (tests, Wireshark builds without prefs) skip init.
static REGISTRY: OnceLock<Registry> = OnceLock::new();

pub fn registry() -> &'static Registry {
    REGISTRY.get_or_init(Registry::empty)
}

pub fn init_registry(aosp_dir: &std::path::Path, overlay_dir: &std::path::Path) {
    let mut reg = Registry::with_aosp_dir(aosp_dir.to_path_buf());

    if let Some(native_dir) = aosp_dir.parent().map(|p| p.join("native")) {
        if native_dir.exists() {
            eprintln!(
                "binderdump: loading synthetic native AIDL corpus from {}",
                native_dir.display()
            );
            reg = reg.with_native_dir(&native_dir);
        }
    }

    if aosp_dir.exists() {
        eprintln!(
            "binderdump: AOSP corpus dir = {} (lazy)",
            aosp_dir.display()
        );
    } else {
        eprintln!(
            "binderdump: AOSP corpus dir {} does not exist; resolution will rely solely on overlays",
            aosp_dir.display()
        );
    }

    if overlay_dir.exists() {
        eprintln!(
            "binderdump: scanning AIDL overlay dir {}",
            overlay_dir.display()
        );
        let before = reg.overlay_count();
        if let Err(e) = reg.load_overlays_into(overlay_dir) {
            eprintln!(
                "binderdump: failed to scan AIDL overlay dir {}: {}",
                overlay_dir.display(),
                e
            );
        } else {
            eprintln!(
                "binderdump: loaded {} overlay file(s) from {}",
                reg.overlay_count() - before,
                overlay_dir.display()
            );
        }
    } else {
        eprintln!(
            "binderdump: AIDL overlay dir {} does not exist, skipping",
            overlay_dir.display()
        );
    }

    let _ = REGISTRY.set(reg);
}
