use log::debug;
use libc;
use anyhow::{Result, bail};
use binderdump::capture::{self, tracepoints::attach_tracepoints};

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
    println!("mypid: {}", std::process::id());

    let binder_skel = attach_tracepoints()?;

    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
    Ok(())
}
