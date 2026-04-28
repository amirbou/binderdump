// End-to-end test: feed a binderdump-generated pcapng through tshark and
// verify that our dissector parses the binder fields out correctly.
//
// Requires:
//   * `tshark` on PATH (apt install tshark / wireshark-common)
//   * `libbinderdump.so` installed at
//     ~/.local/lib/wireshark/plugins/<wireshark-version>/epan/
//     (build with `cargo build -p binderdump-dissector` and copy)
//
// Regenerating tests/fixtures/sample.pcapng:
//   1. Connect a rooted Android device (`adb devices` shows it).
//   2. From the repo root, kick off a short capture and trigger binder
//      traffic concurrently so the pcapng isn't empty:
//
//        cargo run --release -p binderdump -- -t 2 &
//        sleep 0.5 && adb shell 'service list >/dev/null 2>&1'
//        wait
//
//      The cargo runner (scripts/run.sh) adb-pushes the binary, runs it
//      on the device, and pulls /data/local/tmp/out.pcapng back to
//      $OUT_DIR (currently /mnt/d/pcaps).
//   3. Copy the pulled file in:
//
//        cp /mnt/d/pcaps/out.pcapng \
//           binderdump-dissector/tests/fixtures/sample.pcapng
//
//   Keep the fixture small (a few KB). If it balloons, shorten -t or skip
//   the trigger command — the pcapng is committed to the repo.

use std::path::PathBuf;
use std::process::Command;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.pcapng")
}

fn tshark(args: &[&str]) -> String {
    let output = Command::new("tshark")
        .args(args)
        .output()
        .expect("failed to spawn tshark (install wireshark/tshark to run this test)");
    assert!(
        output.status.success(),
        "tshark failed (status: {})\nstderr: {}\nargs: {:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
        args,
    );
    String::from_utf8(output.stdout).expect("tshark stdout not utf-8")
}

fn ensure_dissector_loaded() {
    let out = tshark(&["-G", "protocols"]);
    assert!(
        out.lines().any(|l| l.contains("\tbinderdump")),
        "binderdump dissector is not registered with tshark.\n\
         Build it (`cargo build -p binderdump-dissector`) and copy the \
         resulting libbinderdump_dissector.so to \
         ~/.local/lib/wireshark/plugins/<version>/epan/libbinderdump.so"
    );
}

#[test]
fn dissector_tree_contains_event_protocol() {
    ensure_dissector_loaded();
    let fixture = fixture_path();
    let out = tshark(&["-r", fixture.to_str().unwrap(), "-V"]);

    assert!(
        out.contains("Android Binderdump"),
        "expected protocol header missing from -V output"
    );
    assert!(
        out.contains("EventProtocol"),
        "expected EventProtocol subtree missing"
    );
    assert!(
        out.contains("binder_interface"),
        "expected binder_interface field missing"
    );
}

#[test]
fn binderdump_filter_matches_every_frame() {
    ensure_dissector_loaded();
    let fixture = fixture_path();
    let path = fixture.to_str().unwrap();

    let total = tshark(&["-r", path, "-T", "fields", "-e", "frame.number"]);
    let filtered = tshark(&[
        "-r",
        path,
        "-Y",
        "binderdump",
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]);

    let total_count = total.lines().filter(|l| !l.is_empty()).count();
    let filtered_count = filtered.lines().filter(|l| !l.is_empty()).count();

    assert!(total_count > 0, "fixture has no frames");
    assert_eq!(
        filtered_count, total_count,
        "every frame in the fixture should match the `binderdump` display filter"
    );
}

#[test]
fn event_type_field_extracts_known_values() {
    ensure_dissector_loaded();
    let fixture = fixture_path();
    let out = tshark(&[
        "-r",
        fixture.to_str().unwrap(),
        "-T",
        "fields",
        "-e",
        "binderdump.event_type",
    ]);

    let values: Vec<&str> = out.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        !values.is_empty(),
        "binderdump.event_type extracted no values"
    );

    // EventType discriminants from event_layer.rs:
    //   0 FinishedIoctl, 1 SplitIoctl, 2 DeadProcess, 3 DeadThread, 4 Invalid
    for v in &values {
        let n: u32 = v
            .parse()
            .unwrap_or_else(|_| panic!("event_type not numeric: {:?}", v));
        assert!(n <= 4, "event_type out of range: {}", n);
    }
}

#[test]
fn transaction_re_exports_command_fields() {
    // The TransactionProtocol layer re-exports BC_/BR_ TRANSACTION wire fields
    // (target.handle, cookie, sender_pid, ...) so users do not have to dig into
    // the Commands array. Verify the fields exist and that at least one frame
    // has a non-zero sender_pid (kernel-filled on the BR_TRANSACTION side).
    ensure_dissector_loaded();
    let fixture = fixture_path();
    let path = fixture.to_str().unwrap();

    let prefix = "binderdump.ioctl_data.bwr.transaction";
    for suffix in &[
        "target_handle",
        "target_ptr",
        "cookie",
        "sender_pid",
        "sender_euid",
    ] {
        let abbrev = format!("{}.{}", prefix, suffix);
        let out = tshark(&["-r", path, "-T", "fields", "-e", &abbrev]);
        assert!(
            out.lines().any(|l| !l.is_empty()),
            "{} not extractable from any frame",
            abbrev
        );
    }

    // The kernel fills sender_pid on the BR_TRANSACTION (receiver) side; if our
    // re-export plumbing works at all, at least one frame in the fixture must
    // have a non-zero value.
    let pids = tshark(&[
        "-r",
        path,
        "-T",
        "fields",
        "-e",
        &format!("{}.sender_pid", prefix),
    ]);
    let any_nonzero = pids
        .lines()
        .flat_map(|l| l.split(','))
        .any(|v| v.trim().parse::<i64>().ok().map_or(false, |n| n != 0));
    assert!(
        any_nonzero,
        "expected at least one frame with sender_pid != 0 (BR_TRANSACTION receiver side)"
    );
}

#[test]
fn ioctl_data_dissected_for_at_least_one_frame() {
    ensure_dissector_loaded();
    let fixture = fixture_path();
    let out = tshark(&[
        "-r",
        fixture.to_str().unwrap(),
        "-Y",
        "binderdump.ioctl_data.cmd",
        "-T",
        "fields",
        "-e",
        "binderdump.ioctl_data.cmd",
    ]);

    let frames: Vec<&str> = out.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        !frames.is_empty(),
        "no frame had a dissected ioctl_data.cmd field"
    );
}
