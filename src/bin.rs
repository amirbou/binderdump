use std::os::unix::fs::MetadataExt;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use log::debug;
use libc;
use anyhow::{Result, bail};

mod minimal {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf-skel/minimal.skel.rs"));
}
use minimal::*;

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

pub fn main() -> Result<()> {
    #[cfg(target_os = "android")]
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("binderdump")
            .with_max_level(log::LevelFilter::Debug)
    );
    #[cfg(not(target_os = "android"))]
    env_logger::init();
    
    debug!("Hello");
    let pid = std::process::id();


    // println!("mypid: {} {} {}", pid, pid as i32, unsafe { libc::getpid()});

    bump_memlock_rlimit()?;
    enable_bpf_printk_trace()?;

    let mut skel_builder = MinimalSkelBuilder::default();
    skel_builder.obj_builder.debug(true);

    let mut open_skel = skel_builder.open()?;

    open_skel.rodata_mut().my_pid = pid as i32;
    
    if let Ok((dev, ino)) = get_pid_ns() {
        open_skel.rodata_mut().my_dev = dev;
        open_skel.rodata_mut().my_ino = ino;
        open_skel.rodata_mut().check_ns = 1;
    } else {
        open_skel.rodata_mut().check_ns = 0;
    }
    
    let mut skel = open_skel.load()?;
    skel.attach()?;

    println!("mypid: {}", pid);

    for _ in 0..10 {
        println!("Hi");
        unsafe {libc::syscall(libc::SYS_io_destroy, 0) };
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    Ok(())
}
