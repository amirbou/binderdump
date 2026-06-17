// Standalone tool: derive binder reply-correlation offsets at runtime on a
// BTF-less 64-bit kernel by calibrating against live transactions, then print
// the string for `binderdump --reply-offsets`. Nudges binder traffic itself.

use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use binderdump::capture::offset_solver::{solve, Deref, Sample, DEREF_WIN, STRUCT_WIN};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;

mod offsets {
    include!(concat!(env!("OUT_DIR"), "/offsets.skel.rs"));
}
use offsets::*;

// long enough to collect >= MIN_REPLY_CONFIRMATIONS replies on a quiet device
const CALIBRATION_SECS: u64 = 4;

#[derive(Default)]
struct Collector {
    by_ptr: HashMap<u64, usize>,
    samples: Vec<Sample>,
}

impl Collector {
    fn ingest(&mut self, data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        // lengths checked above
        let kind = u32::from_le_bytes(data[0..4].try_into().unwrap());
        match kind {
            0 => {
                // struct finder_txn: kind, reply, txn_ptr, debug_id, window[STRUCT_WIN]
                if data.len() < 20 + STRUCT_WIN {
                    return;
                }
                let reply = u32::from_le_bytes(data[4..8].try_into().unwrap()) != 0;
                let txn_ptr = u64::from_le_bytes(data[8..16].try_into().unwrap());
                let debug_id = u32::from_le_bytes(data[16..20].try_into().unwrap());
                let window = data[20..20 + STRUCT_WIN].to_vec();
                let idx = self.samples.len();
                self.samples.push(Sample {
                    txn_ptr,
                    reply,
                    debug_id,
                    struct_window: window,
                    derefs: vec![],
                });
                // if a binder_transaction address is reused within the calibration window
                // (allocate/free/realloc — rare), the newer sample wins. harmless: a sample
                // with no derefs just contributes no votes.
                self.by_ptr.insert(txn_ptr, idx);
            }
            1 => {
                if data.len() < 16 + DEREF_WIN {
                    return;
                }
                let src_off = u32::from_le_bytes(data[4..8].try_into().unwrap());
                let txn_ptr = u64::from_le_bytes(data[8..16].try_into().unwrap());
                let window = data[16..16 + DEREF_WIN].to_vec();
                if let Some(&idx) = self.by_ptr.get(&txn_ptr) {
                    self.samples[idx].derefs.push(Deref { src_off, window });
                }
            }
            _ => {}
        }
    }

    fn into_samples(self) -> Vec<Sample> {
        self.samples
    }
}

fn nudge(stop: Arc<AtomicBool>) {
    // well-known services that are always registered, to drive request+reply traffic
    let services = ["activity", "package", "window", "power", "audio"];
    while !stop.load(Ordering::Relaxed) {
        let _ = Command::new("service").arg("list").output();
        for s in &services {
            let _ = Command::new("service").args(["check", s]).output();
        }
        let _ = Command::new("dumpsys").arg("meminfo").output();
        // rate-limit so we don't flood the ring buffer
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    binderdump::capture::tracepoints::bump_memlock_rlimit()?;

    let skel_builder = OffsetsSkelBuilder::default();
    let open_object = Box::leak(Box::new(MaybeUninit::uninit()));
    let open_skel = skel_builder.open(open_object)?;
    let mut skel = open_skel
        .load()
        .context("failed to load calibration skeleton")?;
    skel.attach()
        .context("failed to attach calibration program")?;

    let collector = Arc::new(Mutex::new(Collector::default()));
    let collector_cb = collector.clone();
    let mut rbb = RingBufferBuilder::new();
    rbb.add(&skel.maps.finder_events, move |data| -> i32 {
        // a poisoned lock is fatal for this short-lived tool
        collector_cb.lock().unwrap().ingest(data);
        0
    })?;
    let rb = rbb.build()?;

    let stop = Arc::new(AtomicBool::new(false));
    let nudger = {
        let stop = stop.clone();
        std::thread::spawn(move || nudge(stop))
    };

    println!("calibrating for {CALIBRATION_SECS}s (nudging binder traffic)...");
    let deadline = std::time::Instant::now() + Duration::from_secs(CALIBRATION_SECS);
    while std::time::Instant::now() < deadline {
        match rb.poll(Duration::from_millis(50)) {
            Ok(_) => {}
            Err(e) if e.kind() == libbpf_rs::ErrorKind::Interrupted => {}
            Err(e) => return Err(e).context("ringbuf poll failed"),
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = nudger.join();

    // release the ringbuf's borrow of skel.maps and the collector's Arc clone
    drop(rb);

    // records the calibration ring dropped under load — distinguishes a quiet
    // device from one whose traffic overran the buffer
    let drops = skel
        .maps
        .bss_data
        .as_deref()
        .map_or(0, |b| b.g_ringbuf_drops);

    // a poisoned lock is fatal for this short-lived tool
    let samples = std::mem::take(&mut *collector.lock().unwrap()).into_samples();
    let txns = samples.len();
    let replies = samples.iter().filter(|s| s.reply).count();
    println!("samples: {txns} txns, {replies} replies");
    if drops > 0 {
        println!("warning: {drops} calibration records dropped (ring full)");
    }

    match solve(&samples) {
        Ok(d) => {
            println!("debug_id  = {}", d.debug_id);
            println!("to_thread = {}", d.to_thread);
            println!("txn_stack = {}", d.transaction_stack);
            println!("\n--reply-offsets {}", d.to_reply_offsets_arg());
            Ok(())
        }
        Err(e) => {
            eprintln!("failed to derive offsets: {e:#}");
            if drops > 0 {
                eprintln!("note: {drops} records were dropped — the ring overran; this is not a quiet device");
            }
            eprintln!(
                "note: assumes a 64-bit arm64 kernel with 48-bit VA; a different VA size needs a code change"
            );
            std::process::exit(1);
        }
    }
}
