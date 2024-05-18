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
    println!("mypid: {} {} {}", pid, pid as i32, unsafe { libc::getpid()});

    bump_memlock_rlimit()?;

    let mut skel_builder = MinimalSkelBuilder::default();
    skel_builder.obj_builder.debug(true);

    let mut open_skel = skel_builder.open()?;

    open_skel.rodata_mut().my_pid = pid as i32;

    let mut skel = open_skel.load()?;
    skel.attach()?;

    println!("mypid: {}", pid);

    loop {
        println!("Hi");
        unsafe {libc::syscall(libc::SYS_io_destroy, 0) };
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    Ok(())
}
