use std::os::unix::fs::MetadataExt;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libc;
use anyhow::{bail, Result};

mod binder {
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

fn get_pid_ns() -> Result<(u64, u64)> {
    let metadata = std::fs::metadata("/proc/self/ns/pid")?;
    let dev = metadata.dev();
    let ino = metadata.ino();

    Ok((dev, ino))
}

// On android tracing is off by default
fn enable_bpf_printk_trace() -> Result<()> {
    std::fs::write("/sys/kernel/tracing/tracing_on", "1\n")?;
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

    let mut open_skel = skel_builder.open()?;

    open_skel.rodata_mut().my_pid = std::process::id() as i32;
    
    if let Ok((dev, ino)) = get_pid_ns() {
        open_skel.rodata_mut().my_dev = dev;
        open_skel.rodata_mut().my_ino = ino;
        open_skel.rodata_mut().check_ns = 1;
    } else {
        open_skel.rodata_mut().check_ns = 0;
    }
    
    let mut skel = open_skel.load()?;
    skel.attach()?;

    Ok(skel)
}