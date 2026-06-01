use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result};
use libbpf_rs::btf::Btf;

const KERNEL_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";

static SUPPORTED: OnceLock<bool> = OnceLock::new();

// True iff the running kernel exposes BTF at all. Cheaper and broader than
// reply_correlation_supported(): it ignores which fields the BTF contains and
// only asks whether libbpf can find a vmlinux BTF. Used to decide whether the
// object may carry CO-RE relocations through load(); see write_dummy_btf.
pub fn kernel_btf_present() -> bool {
    Path::new(KERNEL_BTF_PATH).exists()
}

// libbpf needs a vmlinux BTF whenever the object carries CO-RE relocations.
// Our only CO-RE program (raw_binder_transaction_core) is disabled when BTF is
// absent, but its relocs still live in the object, so on kernels built without
// CONFIG_DEBUG_INFO_BTF the load aborts trying to read /sys/kernel/btf/vmlinux:
//
//     libbpf: kernel BTF is missing at '/sys/kernel/btf/vmlinux'
//     libbpf: Error loading vmlinux BTF: -ESRCH
//
// Setting btf_custom_path makes libbpf use that file as the CO-RE target BTF
// instead of vmlinux. libbpf *parses* the file (an empty or non-BTF path such
// as /dev/null fails with -EIO), but its contents are irrelevant here: the only
// CO-RE relocations belong to the disabled program, so nothing is ever resolved
// against it. A minimal, types-free but structurally valid BTF blob is enough.
//
// Returns the path of the written blob.
pub fn write_dummy_btf() -> Result<PathBuf> {
    // btf_header (24 bytes) + a 1-byte string section holding the mandatory
    // leading '\0'. magic 0xeB9F, version 1, no types.
    const DUMMY_BTF: [u8; 25] = [
        0x9f, 0xeb, // magic (LE)
        0x01, // version
        0x00, // flags
        0x18, 0x00, 0x00, 0x00, // hdr_len = 24
        0x00, 0x00, 0x00, 0x00, // type_off = 0
        0x00, 0x00, 0x00, 0x00, // type_len = 0
        0x00, 0x00, 0x00, 0x00, // str_off = 0
        0x01, 0x00, 0x00, 0x00, // str_len = 1
        0x00, // strings: "\0"
    ];
    let path = std::env::temp_dir().join("binderdump_dummy.btf");
    std::fs::write(&path, DUMMY_BTF)
        .with_context(|| format!("failed to write dummy BTF to {}", path.display()))?;
    Ok(path)
}

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
