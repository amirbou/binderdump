use anyhow::Result;
use binderdump::capture::events::{BinderEvent, BinderEventData, BinderEventIoctl};
use binderdump::capture::process_cache::{ProcessCache, ProcessInfo};
use binderdump::capture::ringbuf::create_events_channel;
use binderdump::capture::tracepoints::attach_tracepoints;
use log::debug;

pub fn main() -> Result<()> {
    #[cfg(target_os = "android")]
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("binderdump")
            .with_max_level(log::LevelFilter::Debug),
    );
    #[cfg(not(target_os = "android"))]
    env_logger::init();

    debug!("Hello");
    println!("mypid: {}", std::process::id());

    let mut cache = ProcessCache::new();

    let mut binder_skel = attach_tracepoints()?;

    let event_channel = create_events_channel(&mut binder_skel)?;

    println!("waiting for events");
    for _ in 0..10 {
        let event = event_channel.get_channel().recv()?;
        println!("Got event {:?}", event);
        if let BinderEventData::BinderIoctl(ioctl_data) = event.data {
            // TODO - invalidate processes that exit
            let proc_info = cache.get_proc(
                event.pid,
                event.tid,
                Some(&ioctl_data.comm.to_string_lossy()),
            )?;
            println!(
                "Extra info: cmdline: {} device: {}",
                proc_info.get_cmdline(),
                proc_info
                    .get_binder_name(ioctl_data.fd)
                    .unwrap_or("<failed to translate>")
            );
        }
    }
    Ok(())
}
