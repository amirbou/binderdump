// End-to-end test: load BPF, capture for 1s, verify clean exit + non-empty pcapng.
// Requires running on a device with binder + BPF tracing privileges (root).
// Pure-host targets cannot exercise this code path, so the test is android-only.
#![cfg(target_os = "android")]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use binderdump::capture::ringbuf::create_events_channel;
use binderdump::capture::tracepoints::attach_tracepoints;
use binderdump::pcapng::packets::PacketGenerator;

#[test]
fn capture_for_one_second_terminates() -> Result<()> {
    let mut binder_skel = attach_tracepoints()?;
    let event_channel = create_events_channel(&mut binder_skel)?;

    let path = PathBuf::from("/data/local/tmp/binderdump_capture_test.pcapng");
    let output = std::fs::File::create(&path)?;

    let mut packets = PacketGenerator::new(event_channel, output)?;

    let start = Instant::now();
    packets.capture(Some(Duration::from_secs(1)))?;
    let elapsed = start.elapsed();

    assert!(
        elapsed >= Duration::from_millis(900),
        "capture exited too early: {:?}",
        elapsed
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "capture didn't terminate within bound: {:?}",
        elapsed
    );

    let metadata = std::fs::metadata(&path)?;
    assert!(metadata.len() > 0, "pcapng output is empty");

    let _ = std::fs::remove_file(&path);
    Ok(())
}
