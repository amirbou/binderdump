use std::time::Duration;

use anyhow::Result;
use binderdump::capture::ringbuf::create_events_channel;
use binderdump::capture::tracepoints::{attach_tracepoints, ReplyCorrelationMode, ReplyOffsets};
use binderdump::pcapng::packets;
use clap::Parser;
use libbpf_rs::ErrorExt;

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

pub fn main() -> Result<()> {
    // Diagnostics go to stderr; RUST_LOG overrides the default. Kept quiet by
    // default so it can't drown out capture status output.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

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
