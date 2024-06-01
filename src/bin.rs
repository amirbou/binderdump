use anyhow::Result;
use binderdump::capture::events::BinderEventData;
use binderdump::capture::process_cache::ProcessCache;
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
    loop {
        let event = event_channel.get_channel().recv()?;
        if !matches!(event.data, BinderEventData::BinderWriteRead(_)) {
            println!("Got event {:?}", event);
        }
        match event.data {
            BinderEventData::BinderInvalidate => (),
            BinderEventData::BinderIoctl(ioctl_data) => {
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
            BinderEventData::BinderInvalidateProcess => {
                let info = cache.invalidate_proc(event.pid, event.tid);
                if let Some(info) = info {
                    println!(
                        "Process '{}' ({}) exited and removed from cache",
                        info.get_cmdline(),
                        event.tid
                    );
                    break;
                }
            }
            BinderEventData::BinderWriteRead(bwr) => println!("{}", bwr),
            BinderEventData::BinderIoctlDone(_) => (),
        }
    }
    Ok(())
}
