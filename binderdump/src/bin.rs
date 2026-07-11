use std::time::Duration;

use anyhow::Result;
use binderdump::capture::events::{BinderEventData, BinderEventWriteRead};
use binderdump::capture::process_cache::ProcessCache;
use binderdump::capture::ringbuf::create_events_channel;
use binderdump::capture::tracepoints::{attach_tracepoints, ReplyCorrelationMode, ReplyOffsets};
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

    /// Manually specify binder struct offsets, bypassing CO-RE. Format:
    /// 'to_thread=N,transaction_stack=N,debug_id=N'. Values accept
    /// decimal or 0x-prefixed hex. Use when kernel BTF is missing or
    /// describes a different struct layout than the running kernel's.
    #[arg(
        long = "reply-offsets",
        value_name = "OFFSETS",
        conflicts_with = "no_reply_correlation"
    )]
    reply_offsets: Option<ReplyOffsets>,

    /// Write the pcapng here. Use '-' to stream to stdout (pipe into
    /// `wireshark -k -i -`); the stream is flushed per packet and status
    /// output goes to stderr so it can't corrupt the capture.
    #[arg(
        short = 'w',
        long = "write",
        value_name = "PATH",
        default_value = "/data/local/tmp/out.pcapng"
    )]
    output: String,
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

fn run_pcap(output: &str, duration: Option<Duration>, mode: ReplyCorrelationMode) -> Result<()> {
    let mut binder_skel = attach_tracepoints(mode)?;

    let event_channel = create_events_channel(&mut binder_skel)?;

    // '-' streams pcapng to stdout (flushed per packet); anything else is a file.
    let (writer, flush_each): (Box<dyn std::io::Write>, bool) = if output == "-" {
        (Box::new(std::io::stdout().lock()), true)
    } else {
        let file = std::fs::File::create(output)
            .context(format!("failed to open output file: {}", output))?;
        (Box::new(file), false)
    };
    match duration {
        Some(d) => eprintln!("capturing events for {}s", d.as_secs()),
        None => eprintln!("waiting for events"),
    }
    let mut packets = packets::PacketGenerator::new(event_channel, writer, flush_each)?;
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
    eprintln!("mypid: {}", std::process::id());

    let args = Args::parse();
    let duration = args.duration_secs.map(Duration::from_secs);
    let mode = if args.no_reply_correlation {
        ReplyCorrelationMode::Disabled
    } else if let Some(o) = args.reply_offsets {
        o.into()
    } else {
        ReplyCorrelationMode::Auto
    };
    run_pcap(&args.output, duration, mode)
}
