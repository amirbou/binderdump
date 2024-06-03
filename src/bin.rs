use anyhow::Result;
use binderdump::capture::events::{
    BinderCommand, BinderEventData, BinderEventWriteRead, BinderEventWriteReadData,
};
use binderdump::capture::process_cache::ProcessCache;
use binderdump::capture::ringbuf::create_events_channel;
use binderdump::capture::tracepoints::attach_tracepoints;
use log::debug;

fn do_write(write: &BinderEventWriteReadData) -> Result<()> {
    let data = write.data();
    let mut pos = 0;
    while pos < data.len() {
        let bc = BinderCommand::try_from(&data[pos..])?;
        println!("bc: {:x?}", bc);
        pos += bc.command_size();
    }
    assert_eq!(pos, data.len());
    Ok(())
}

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
        if let Ok(proc_info) = cache.get_proc(event.pid, event.tid, None) {
            if proc_info.get_comm() != "service"
                && proc_info.get_comm() != "servicemanager"
                && proc_info.get_comm() != "dumpsys"
            {
                continue;
            }
        } else {
            continue;
        }
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
            BinderEventData::BinderWriteRead(bwr) => {
                println!("{}", bwr);
                if let BinderEventWriteRead::BinderEventWrite(write) = &bwr {
                    do_write(write)?;
                }
            }
            BinderEventData::BinderIoctlDone(_) => (),
        }
    }
    Ok(())
}
