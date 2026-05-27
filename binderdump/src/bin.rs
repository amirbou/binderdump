use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use binderdump::capture::events::{BinderEventData, BinderEventWriteRead};
use binderdump::capture::process_cache::ProcessCache;
use binderdump::capture::ringbuf::create_events_channel;
use binderdump::capture::tracepoints::{attach_tracepoints, ReplyCorrelationMode};
use binderdump::pcapng::packets;
use binderdump_structs::binder_types::{
    binder_command::BinderCommand, binder_return::BinderReturn,
};
use clap::Parser;
use libbpf_rs::ErrorExt;
use log::debug;
use yansi::Paint;

#[derive(Parser, Debug)]
#[command(about = "tcpdump for Android binder")]
struct Args {
    /// Stop after this many seconds of capture (omit for unbounded).
    #[arg(short = 't', long = "duration", value_name = "SECONDS")]
    duration_secs: Option<u64>,

    /// Don't load the reply-correlation BPF program at all. Use when you
    /// don't want it (debugging), or when kernel BTF advertises the right
    /// structs but the offsets it reports produce wrong data (e.g. vendor
    /// backport, out-of-tree binder).
    #[arg(long = "no-reply-correlation", conflicts_with = "reply_offsets")]
    no_reply_correlation: bool,
}

fn do_write(bwr: &BinderEventWriteRead) -> Result<()> {
    let bcs: Vec<BinderCommand> = bwr.try_into()?;
    for bc in bcs {
        println!("{:x?}", bc.green());
    }
    Ok(())
}

fn do_read(bwr: &BinderEventWriteRead) -> Result<()> {
    let brs: Vec<BinderReturn> = bwr.try_into()?;
    for br in brs {
        println!("{:x?}", br.blue());
    }
    Ok(())
}

fn run_pcap(path: &Path, duration: Option<Duration>, mode: ReplyCorrelationMode) -> Result<()> {
    let mut binder_skel = attach_tracepoints(mode)?;

    let event_channel = create_events_channel(&mut binder_skel)?;

    let output = std::fs::File::create(path)
        .context(format!("failed to open output file: {}", path.display()))?;
    match duration {
        Some(d) => println!("capturing events for {}s", d.as_secs()),
        None => println!("waiting for events"),
    }
    let mut packets = packets::PacketGenerator::new(event_channel, output)?;
    packets.capture(duration)?;
    Ok(())
}

#[allow(unused)]
fn run_print() -> Result<()> {
    let mut binder_skel = attach_tracepoints(ReplyCorrelationMode::Auto)?;

    let event_channel = create_events_channel(&mut binder_skel)?;
    let mut cache = ProcessCache::new();
    loop {
        let event = event_channel.get_channel().recv()?;
        if let Ok(proc_info) = cache.get_proc(event.pid, event.tid, None) {
            if proc_info.get_comm() != "service"
                && proc_info.get_comm() != "servicemanager"
                && proc_info.get_comm() != "dumpsys"
                && proc_info.get_comm() != "WifiHandlerThr"
            {
                continue;
            }
        } else {
            continue;
        }

        println!("Got event {:?}", event);
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
                match &bwr {
                    BinderEventWriteRead::BinderEventRead(_) => do_read(&bwr)?,
                    BinderEventWriteRead::BinderEventWrite(_) => do_write(&bwr)?,
                };
            }
            BinderEventData::BinderIoctlDone(_) => println!("{}", "----------".yellow()),
            BinderEventData::BinderTransaction(_) => (),
            BinderEventData::BinderTransactionReceived(_) => (),
            BinderEventData::BinderTransactionData(_) => (),
            BinderEventData::BinderTransactionStack(_) => (),
            BinderEventData::BinderTransactionPtrData(_) => (),
        }
    }

    Ok(())
}

pub fn main() -> Result<()> {
    // #[cfg(target_os = "android")]
    // android_logger::init_once(
    //     android_logger::Config::default()
    //         .with_tag("binderdump")
    //         .with_max_level(log::LevelFilter::Debug),
    // );
    // #[cfg(not(target_os = "android"))]
    // env_logger::init();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    debug!("Hello");
    println!("mypid: {}", std::process::id());

    let args = Args::parse();
    let duration = args.duration_secs.map(Duration::from_secs);
    let mode = if args.no_reply_correlation {
        ReplyCorrelationMode::Disabled
    } else {
        ReplyCorrelationMode::Auto
    };
    run_pcap(&PathBuf::from("/data/local/tmp/out.pcapng"), duration, mode)
}
