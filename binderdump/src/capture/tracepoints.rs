use std::mem::MaybeUninit;

use anyhow::{bail, Context, Result};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libc;

pub mod binder {
    include!(concat!(env!("OUT_DIR"), "/binder.skel.rs"));
}
use binder::*;

#[derive(Debug, Clone, Copy)]
pub enum ReplyCorrelationMode {
    /// Use CO-RE relocation against kernel BTF. Skip the program entirely
    /// if BTF is missing or doesn't describe the binder structs.
    Auto,
    /// Don't load the program at all.
    Disabled,
    /// Use the supplied raw byte offsets, bypassing CO-RE.
    ManualOffsets {
        to_thread: u32,
        transaction_stack: u32,
        debug_id: u32,
    },
}

// CLI-parsed manual offsets. Lives here next to ReplyCorrelationMode so the
// `From` impl below stays close. clap parses this via `FromStr`.
#[derive(Debug, Clone, Copy)]
pub struct ReplyOffsets {
    pub to_thread: u32,
    pub transaction_stack: u32,
    pub debug_id: u32,
}

impl std::str::FromStr for ReplyOffsets {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut to_thread = None;
        let mut transaction_stack = None;
        let mut debug_id = None;
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (key, value) = part
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("expected key=value pair, got '{part}'"))?;
            let key = key.trim();
            let value_str = value.trim();
            let parsed: u32 = if let Some(hex) = value_str.strip_prefix("0x") {
                u32::from_str_radix(hex, 16)
                    .map_err(|e| anyhow::anyhow!("offset '{value_str}': {e}"))?
            } else {
                value_str
                    .parse()
                    .map_err(|e| anyhow::anyhow!("offset '{value_str}': {e}"))?
            };
            match key {
                "to_thread" => to_thread = Some(parsed),
                "transaction_stack" => transaction_stack = Some(parsed),
                "debug_id" => debug_id = Some(parsed),
                _ => anyhow::bail!("unknown offset key '{key}'"),
            }
        }
        Ok(ReplyOffsets {
            to_thread: to_thread.ok_or_else(|| anyhow::anyhow!("missing 'to_thread' offset"))?,
            transaction_stack: transaction_stack
                .ok_or_else(|| anyhow::anyhow!("missing 'transaction_stack' offset"))?,
            debug_id: debug_id.ok_or_else(|| anyhow::anyhow!("missing 'debug_id' offset"))?,
        })
    }
}

impl From<ReplyOffsets> for ReplyCorrelationMode {
    fn from(o: ReplyOffsets) -> Self {
        ReplyCorrelationMode::ManualOffsets {
            to_thread: o.to_thread,
            transaction_stack: o.transaction_stack,
            debug_id: o.debug_id,
        }
    }
}

pub fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

// On android tracing is off by default
fn enable_bpf_printk_trace() -> Result<()> {
    std::fs::write("/sys/kernel/tracing/tracing_on", "1\n")
        .with_context(|| "failed to enable bpf_prink_trace")?;
    Ok(())
}

fn prepare_tracepoints() -> Result<()> {
    bump_memlock_rlimit()?;
    enable_bpf_printk_trace()?;
    Ok(())
}

fn configure_reply_correlation(
    open_skel: &mut OpenBinderSkel<'_>,
    mode: ReplyCorrelationMode,
) -> Result<()> {
    match mode {
        ReplyCorrelationMode::Disabled => {
            open_skel
                .progs
                .raw_binder_transaction_core
                .set_autoload(false);
            open_skel
                .progs
                .raw_binder_transaction_manual
                .set_autoload(false);
            log::info!("reply correlation disabled (--no-reply-correlation)");
        }
        ReplyCorrelationMode::ManualOffsets {
            to_thread,
            transaction_stack,
            debug_id,
        } => {
            open_skel
                .progs
                .raw_binder_transaction_core
                .set_autoload(false);
            let rodata = open_skel
                .maps
                .rodata_data
                .as_deref_mut()
                .context("BPF rodata section unavailable")?;
            rodata.cfg_off_to_thread = to_thread;
            rodata.cfg_off_transaction_stack = transaction_stack;
            rodata.cfg_off_debug_id = debug_id;
            log::info!(
                "reply correlation using manual offsets: to_thread={} transaction_stack={} debug_id={}",
                to_thread,
                transaction_stack,
                debug_id,
            );
        }
        ReplyCorrelationMode::Auto => {
            open_skel
                .progs
                .raw_binder_transaction_manual
                .set_autoload(false);
            if !crate::capture::btf_probe::reply_correlation_supported() {
                open_skel
                    .progs
                    .raw_binder_transaction_core
                    .set_autoload(false);
                log::info!("reply correlation disabled (no kernel BTF support)");
            }
        }
    }
    Ok(())
}

pub fn attach_tracepoints<'a>(mode: ReplyCorrelationMode) -> Result<BinderSkel<'a>> {
    prepare_tracepoints()?;

    let mut skel_builder = BinderSkelBuilder::default();
    // skel_builder.obj_builder.debug(true);

    // On kernels without BTF, hand libbpf a minimal custom BTF so it uses that
    // as the CO-RE target instead of aborting the load over a missing
    // /sys/kernel/btf/vmlinux. The reply-correlation program (the only CO-RE
    // user) is disabled below, so the blob's contents are never consulted -- but
    // libbpf does parse the file, so it must be valid BTF. See write_dummy_btf.
    if !crate::capture::btf_probe::kernel_btf_present() {
        let path = crate::capture::btf_probe::write_dummy_btf()?;
        skel_builder.obj_builder.btf_custom_path(&path)?;
    }

    let open_object = Box::leak(Box::new(MaybeUninit::uninit()));
    let mut open_skel = skel_builder.open(open_object)?;
    open_skel.maps.bss_data.as_deref_mut().unwrap().g_loader_pid = unsafe { libc::getpid() } as i32;

    configure_reply_correlation(&mut open_skel, mode)?;

    let mut skel = open_skel.load()?;
    skel.attach()?;

    Ok(skel)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn parses_decimal_offsets() {
        let o = ReplyOffsets::from_str("to_thread=64,transaction_stack=64,debug_id=0").unwrap();
        assert_eq!(o.to_thread, 64);
        assert_eq!(o.transaction_stack, 64);
        assert_eq!(o.debug_id, 0);
    }

    #[test]
    fn parses_hex_offsets() {
        let o =
            ReplyOffsets::from_str("to_thread=0x40,transaction_stack=0x40,debug_id=0x0").unwrap();
        assert_eq!(o.to_thread, 0x40);
        assert_eq!(o.transaction_stack, 0x40);
        assert_eq!(o.debug_id, 0);
    }

    #[test]
    fn rejects_missing_key() {
        let err = ReplyOffsets::from_str("to_thread=64,debug_id=0").unwrap_err();
        assert!(err.to_string().contains("transaction_stack"));
    }

    #[test]
    fn rejects_unknown_key() {
        let err = ReplyOffsets::from_str("to_thread=64,transaction_stack=64,debug_id=0,bogus=1")
            .unwrap_err();
        assert!(err.to_string().contains("bogus"));
    }

    #[test]
    fn rejects_malformed_pair() {
        let err =
            ReplyOffsets::from_str("to_thread:64,transaction_stack=64,debug_id=0").unwrap_err();
        assert!(err.to_string().contains("key=value"));
    }
}
