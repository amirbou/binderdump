use std::path::Path;
use std::sync::OnceLock;

use libbpf_rs::btf::Btf;

const KERNEL_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";

static SUPPORTED: OnceLock<bool> = OnceLock::new();

// returns true iff the running kernel exposes BTF and that BTF contains
// struct binder_transaction with `to_thread` + `debug_id` AND struct
// binder_thread with `transaction_stack`. cached after first call.
pub fn reply_correlation_supported() -> bool {
    *SUPPORTED.get_or_init(probe)
}

fn probe() -> bool {
    if !Path::new(KERNEL_BTF_PATH).exists() {
        log::info!(
            "kernel BTF not found at {}; reply correlation disabled",
            KERNEL_BTF_PATH
        );
        return false;
    }
    let btf = match Btf::from_path(KERNEL_BTF_PATH) {
        Ok(b) => b,
        Err(e) => {
            log::warn!("failed to parse kernel BTF: {e}; reply correlation disabled");
            return false;
        }
    };
    let has_transaction = struct_has_fields(&btf, "binder_transaction", &["to_thread", "debug_id"]);
    let has_thread = struct_has_fields(&btf, "binder_thread", &["transaction_stack"]);
    if !has_transaction || !has_thread {
        log::info!("kernel BTF missing required binder struct fields; reply correlation disabled");
        return false;
    }
    true
}

fn struct_has_fields(btf: &Btf, struct_name: &str, fields: &[&str]) -> bool {
    let ty = match btf.type_by_name::<libbpf_rs::btf::types::Struct>(struct_name) {
        Some(t) => t,
        None => return false,
    };
    fields.iter().all(|name| {
        ty.iter()
            .any(|m| m.name.and_then(|n| n.to_str()) == Some(*name))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_result_is_stable() {
        let first = reply_correlation_supported();
        let second = reply_correlation_supported();
        assert_eq!(first, second);
    }
}
