use anyhow::{bail, Context, Result};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libc;
use std::os::unix::fs::MetadataExt;

pub mod binder {
    include!(concat!(env!("OUT_DIR"), "/binder.skel.rs"));
}
use binder::*;

fn bump_memlock_rlimit() -> Result<()> {
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

pub fn attach_tracepoints<'a>() -> Result<BinderSkel<'a>> {
    prepare_tracepoints()?;

    let mut skel_builder = BinderSkelBuilder::default();
    skel_builder.obj_builder.debug(true);

    let open_skel = skel_builder.open()?;

    let mut skel = open_skel.load()?;
    skel.attach()?;

    Ok(skel)
}
