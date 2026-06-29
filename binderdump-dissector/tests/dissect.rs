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
//      on the device, and (when $OUT_DIR is set) adb-pulls
//      /data/local/tmp/out.pcapng back to $OUT_DIR.
//   3. Copy the pulled file in:
//
//        cp "$OUT_DIR/out.pcapng" \
//           binderdump-dissector/tests/fixtures/sample.pcapng
//
//   Keep the fixture small (a few KB). If it balloons, shorten -t or skip
//   the trigger command — the pcapng is committed to the repo.

use std::path::PathBuf;
use std::process::Command;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.pcapng")
}

fn set_transaction_state_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/set_transaction_state.pcapng")
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

#[test]
fn dissector_resolves_iservicemanager_method() {
    ensure_dissector_loaded();
    let fixture = fixture_path();
    let path = fixture.to_str().unwrap();

    let out = tshark(&[
        "-r",
        path,
        "-T",
        "fields",
        "-e",
        "binderdump.ioctl_data.bwr.transaction.interface",
        "-e",
        "binderdump.ioctl_data.bwr.transaction.method_name",
        "-Y",
        "binderdump.ioctl_data.bwr.transaction.interface == \"android.os.IServiceManager\"",
    ]);

    let any_resolved = out.lines().any(|l| {
        let mut parts = l.splitn(2, '\t');
        let iface = parts.next().unwrap_or("");
        let method = parts.next().unwrap_or("");
        iface.contains("android.os.IServiceManager") && !method.trim().is_empty()
    });
    assert!(
        any_resolved,
        "expected at least one IServiceManager packet with a resolved method, got:\n{}",
        out,
    );
}

#[test]
fn dissector_recognizes_special_transaction() {
    ensure_dissector_loaded();
    let fixture = fixture_path();
    let path = fixture.to_str().unwrap();

    // Filter on the resolved method name. The transaction code field is
    // registered as FT_BYTES so a `== 0x...` numeric compare doesn't work
    // — instead, ensure that whenever the method-resolution machinery
    // labels something PING_TRANSACTION, it also marks it as `special`.
    let out = tshark(&[
        "-r",
        path,
        "-T",
        "fields",
        "-e",
        "binderdump.ioctl_data.bwr.transaction.method_name",
        "-e",
        "binderdump.ioctl_data.bwr.transaction.method_source",
        "-Y",
        "binderdump.ioctl_data.bwr.transaction.method_name == \"PING_TRANSACTION\"",
    ]);

    let lines: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();
    for line in &lines {
        let mut parts = line.splitn(2, '\t');
        let method = parts.next().unwrap_or("");
        let source = parts.next().unwrap_or("");
        assert_eq!(method, "PING_TRANSACTION", "row: {:?}", line);
        assert_eq!(
            source.trim(),
            "special",
            "expected method_source=special for PING; row: {:?}",
            line,
        );
    }
}

#[test]
fn follow_handler_registered() {
    ensure_dissector_loaded();

    // 1. -G plugins must list binderdump (cdylib loaded).
    let plugins = tshark(&["-G", "plugins"]);
    assert!(
        plugins
            .lines()
            .any(|l| l.to_lowercase().contains("binderdump")),
        "tshark -G plugins missing binderdump:\n{}",
        plugins
    );

    // 2. -z follow,binderdump,0 must not be rejected as "invalid". a valid
    // (but empty) follow query for a non-existent stream id is fine. tshark
    // rejects unknown follow tap names with an "invalid -z argument" error
    // on stderr.
    let output = std::process::Command::new("tshark")
        .args([
            "-r",
            fixture_path().to_str().unwrap(),
            "-z",
            "follow,binderdump,0",
        ])
        .output()
        .expect("failed to spawn tshark");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.to_lowercase().contains("invalid -z argument")
            && !stderr
                .to_lowercase()
                .contains("invalid argument for option"),
        "tshark rejected '-z follow,binderdump,0' — follow handler likely not \
         registered. stderr:\n{}",
        stderr
    );
}

#[test]
fn dissector_resolves_method_on_br_transaction() {
    // BC_/BR_TRANSACTIONs should resolve their method names. The fixture
    // contains transactions for android.os.IServiceManager. Assert that
    // at least one row with `transaction.reply == 0` (kernel-native:
    // 0 == transaction, 1 == reply) carries a resolved method_name.
    ensure_dissector_loaded();
    let fixture = fixture_path();
    let out = tshark(&[
        "-r",
        fixture.to_str().unwrap(),
        "-T",
        "fields",
        "-e",
        "binderdump.ioctl_data.bwr.transaction.reply",
        "-e",
        "binderdump.ioctl_data.bwr.transaction.method_name",
        "-e",
        "binderdump.ioctl_data.bwr.transaction.method_source",
        "-Y",
        "binderdump.ioctl_data.bwr.transaction.reply == 0",
    ]);

    let any_tx_row_with_method = out.lines().filter(|l| !l.trim().is_empty()).any(|l| {
        let mut parts = l.splitn(3, '\t');
        let _ = parts.next();
        let m = parts.next().unwrap_or("");
        !m.is_empty()
    });

    assert!(
        any_tx_row_with_method,
        "expected at least one BR_TRANSACTION row with a resolved method_name; full output:\n{}",
        out
    );
}

#[test]
fn matching_version_fixture_dissects_cleanly() {
    // fixture is regenerated under the same crate version as the dissector,
    // so dissection must not error out on the version-mismatch guard.
    ensure_dissector_loaded();
    let fixture = fixture_path();
    let output = Command::new("tshark")
        .args([
            "-r",
            fixture.to_str().unwrap(),
            "-T",
            "fields",
            "-e",
            "frame.number",
        ])
        .output()
        .expect("failed to spawn tshark");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "tshark failed:\nstderr: {}",
        stderr
    );
    assert!(
        !stderr.contains("binderdump version mismatch"),
        "unexpected version-mismatch error on matching fixture:\nstderr: {}",
        stderr,
    );
}

#[test]
fn col_info_shows_request_arrow_for_at_least_one_frame() {
    ensure_dissector_loaded();
    let fixture = fixture_path();
    let out = tshark(&[
        "-r",
        fixture.to_str().unwrap(),
        "-T",
        "fields",
        "-e",
        "_ws.col.Info",
    ]);
    assert!(
        out.lines().any(|l| l.contains('\u{2192}')),
        "expected at least one frame with a \u{2192} (request arrow) in COL_INFO\nfull output:\n{}",
        out
    );
}

// Regression: interface-agnostic special transactions resolve a method_name but
// inherit whatever interface the target binder fd carried -- None, "" or the
// "<query>" placeholder. COL_INFO used to render them three different ways
// ("<unknown interface>::<code>", ".NAME()", "<query>.NAME()"); it must show the
// bare name in every case, matching the method_name field. The committed fixture
// contains PING (no interface) and INTERFACE (the "<query>" case).
#[test]
fn col_info_shows_special_transaction_name() {
    ensure_dissector_loaded();
    let fixture = fixture_path();
    let pfx = "binderdump.ioctl_data.bwr.transaction";
    // PING, DUMP, INTERFACE, SYSPROPS, SHELL_COMMAND.
    let filter = "0x5f504e47, 0x5f444d50, 0x5f4e5446, 0x5f535052, 0x5f434d44";
    let out = tshark(&[
        "-r",
        fixture.to_str().unwrap(),
        "-Y",
        &format!("{pfx}.code in {{{filter}}} && {pfx}.reply == 0"),
        "-T",
        "fields",
        "-e",
        &format!("{pfx}.method_name"),
        "-e",
        "_ws.col.Info",
    ]);

    let mut checked = 0usize;
    for line in out.lines() {
        let (name, info) = line.split_once('\t').unwrap_or(("", ""));
        if name.is_empty() {
            continue;
        }
        assert_eq!(
            info,
            format!("\u{2192} {name}"),
            "special transaction COL_INFO must be the bare name"
        );
        checked += 1;
    }
    assert!(
        checked > 0,
        "fixture has no special-transaction request to check"
    );
}

#[test]
fn col_info_shows_reply_marker_for_at_least_one_frame() {
    ensure_dissector_loaded();
    let fixture = fixture_path();
    let out = tshark(&[
        "-r",
        fixture.to_str().unwrap(),
        "-T",
        "fields",
        "-e",
        "_ws.col.Info",
    ]);
    assert!(
        out.lines().any(|l| l.contains("\u{2190} reply")),
        "expected at least one frame with '\u{2190} reply' in COL_INFO\nfull output:\n{}",
        out
    );
}

#[test]
fn response_in_field_present_on_requests() {
    // `-2` forces two-pass dissection so requests can see their later replies.
    // Without it the reply-correlation cache is empty when the request frame
    // is first dissected, so response_in never gets attached.
    ensure_dissector_loaded();
    let fixture = fixture_path();
    let out = tshark(&[
        "-2",
        "-r",
        fixture.to_str().unwrap(),
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "binderdump_reply.response_in",
        "-Y",
        "binderdump_reply.response_in",
    ]);
    assert!(
        out.lines().any(|l| !l.trim().is_empty()),
        "expected at least one request frame with a response_in cross-ref\nfull output:\n{}",
        out
    );
}

#[test]
fn response_to_and_request_method_present_on_replies() {
    ensure_dissector_loaded();
    let fixture = fixture_path();
    let out = tshark(&[
        "-r",
        fixture.to_str().unwrap(),
        "-T",
        "fields",
        "-e",
        "binderdump_reply.response_to",
        "-e",
        "binderdump_reply.response_time",
        "-e",
        "binderdump_reply.request_method",
        "-Y",
        "binderdump_reply.response_to",
    ]);
    let lines: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(
        !lines.is_empty(),
        "expected at least one reply frame with response_to\nfull output:\n{}",
        out
    );
    let any_with_method = lines.iter().any(|l| {
        let parts: Vec<&str> = l.split('\t').collect();
        parts.get(2).map(|s| !s.is_empty()).unwrap_or(false)
    });
    assert!(
        any_with_method,
        "expected at least one reply to carry request_method\nfull output:\n{}",
        out
    );
}

#[test]
fn at_least_one_frame_has_a_frame_link() {
    // tshark dissects in a single pass, so only the BR frame sees its BC partner
    // (BC is recorded first, BR looks it up). Accept either direction populated.
    ensure_dissector_loaded();
    let fixture = fixture_path();
    let out = tshark(&[
        "-r",
        fixture.to_str().unwrap(),
        "-T",
        "fields",
        "-e",
        "binderdump.ioctl_data.bwr.transaction.bc_frame",
        "-e",
        "binderdump.ioctl_data.bwr.transaction.br_frame",
        "-E",
        "separator=,",
    ]);
    let any_link = out.lines().any(|l| {
        let parts: Vec<&str> = l.split(',').collect();
        parts.len() == 2 && (!parts[0].is_empty() || !parts[1].is_empty())
    });
    assert!(
        any_link,
        "expected at least one frame with bc_frame or br_frame populated\nfull output:\n{}",
        out
    );
}

#[test]
fn follow_stream_produces_text() {
    ensure_dissector_loaded();
    let fixture = fixture_path();

    // probe for a transaction_stream_id whose follow output contains a hex-dump
    // line (some trivial calls have zero-byte payloads and produce no hex section).
    //
    // tshark 3.6 requires a display mode in -z follow,<proto>,<mode>,<id>.
    // in "ascii" mode, non-ASCII bytes (including the UTF-8 → arrow) are
    // replaced by '.', so the frame marker line appears as "... frame N".
    let probe = tshark(&[
        "-2",
        "-r",
        fixture.to_str().unwrap(),
        "-T",
        "fields",
        "-e",
        "binderdump_reply.transaction_stream_id",
        "-Y",
        "binderdump_reply.transaction_stream_id",
    ]);
    let stream_index: u32 = probe
        .lines()
        .filter_map(|l| l.trim().parse::<u32>().ok())
        .find(|&n| {
            let out = tshark(&[
                "-2",
                "-r",
                fixture.to_str().unwrap(),
                "-z",
                &format!("follow,binderdump,ascii,{}", n),
            ]);
            out.contains("0000  ")
        })
        .expect("no transaction_stream_id had a hex-dump rendered");

    let follow = tshark(&[
        "-2",
        "-r",
        fixture.to_str().unwrap(),
        "-z",
        &format!("follow,binderdump,ascii,{}", stream_index),
    ]);

    // tshark ascii mode renders the UTF-8 → (e2 86 92) as three '.' chars;
    // "... frame N" is the actual tshark 3.6 ascii-mode rendering of our
    // "→ frame N" record header.
    assert!(
        follow.contains("... frame"),
        "follow output missing request frame marker (expected '... frame' from \
         ascii-mode rendering of \u{2192} frame):\n{}",
        follow
    );
    assert!(
        follow.contains("0000  "),
        "follow output missing hex-dump line marker:\n{}",
        follow
    );
}

#[test]
fn follow_stream_includes_br_reply() {
    ensure_dissector_loaded();
    let fixture = fixture_path();

    // find a stream that contains a BC_REPLY (reply == 1) by probing for
    // transaction_stream_id on reply frames and picking the first hit.
    let probe = tshark(&[
        "-2",
        "-r",
        fixture.to_str().unwrap(),
        "-T",
        "fields",
        "-e",
        "binderdump_reply.transaction_stream_id",
        "-Y",
        "binderdump.ioctl_data.bwr.transaction.reply == 1 \
         && binderdump_reply.transaction_stream_id",
    ]);
    let stream_index: u32 = probe
        .lines()
        .filter_map(|l| l.trim().parse::<u32>().ok())
        .next()
        .expect("fixture has no BC_REPLY frame with a transaction_stream_id");

    let follow = tshark(&[
        "-2",
        "-r",
        fixture.to_str().unwrap(),
        "-z",
        &format!("follow,binderdump,ascii,{}", stream_index),
    ]);

    // count `frame N` markers in the follow output; a complete exchange
    // (BC_TXN + BR_TXN + BC_REPLY + ...) must contribute >= 3 records.
    let frame_lines: Vec<&str> = follow.lines().filter(|l| l.contains(" frame ")).collect();
    assert!(
        frame_lines.len() >= 3,
        "expected >= 3 frame records (BC_TXN + BR_TXN + BC_REPLY + ...), got {}.\nfull output:\n{}",
        frame_lines.len(),
        follow
    );
}

#[test]
fn follow_stream_filter_via_stream_id_matches_free_buffer_frames() {
    // Display filter via transaction_stream_id must select FREE_BUFFER frames
    // in addition to the BC/BR transaction halves.
    ensure_dissector_loaded();
    let fixture = fixture_path();

    let probe = tshark(&[
        "-2",
        "-r",
        fixture.to_str().unwrap(),
        "-T",
        "fields",
        "-e",
        "binderdump_reply.transaction_stream_id",
        "-Y",
        "binderdump_reply.transaction_stream_id",
    ]);
    let stream_index: u32 = probe
        .lines()
        .filter_map(|l| l.trim().parse::<u32>().ok())
        .next()
        .expect("fixture has no transaction_stream_id assigned");

    let filter = format!("binderdump_reply.transaction_stream_id == {}", stream_index);
    let out = tshark(&[
        "-2",
        "-r",
        fixture.to_str().unwrap(),
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-Y",
        &filter,
    ]);
    let count = out.lines().filter(|l| !l.trim().is_empty()).count();
    assert!(
        count >= 3,
        "expected >= 3 frames matched by stream_id filter, got {}.\nfull output:\n{}",
        count,
        out
    );
}

#[test]
fn follow_stream_offsets_summary_appears() {
    ensure_dissector_loaded();
    let fixture = fixture_path();

    // find the first request frame with a non-empty offsets array and extract
    // its transaction_stream_id (the index the follow handler keys on).
    // offsets_len (FT_UINT32) is used as the filter because the offsets field
    // itself is FT_BYTES and tshark emits an empty column even when bytes are present.
    let probe = tshark(&[
        "-2",
        "-r",
        fixture.to_str().unwrap(),
        "-T",
        "fields",
        "-e",
        "binderdump_reply.transaction_stream_id",
        "-Y",
        "binderdump.ioctl_data.bwr.transaction.reply == 0 \
         && binderdump.ioctl_data.bwr.transaction.offsets_len > 0",
    ]);
    let stream_index: u32 = probe
        .lines()
        .filter_map(|l| l.trim().parse::<u32>().ok())
        .next()
        .expect("fixture has no request with non-empty offsets array");

    let follow = tshark(&[
        "-2",
        "-r",
        fixture.to_str().unwrap(),
        "-z",
        &format!("follow,binderdump,ascii,{}", stream_index),
    ]);

    assert!(
        follow.contains("offsets:"),
        "follow output for stream {} missing 'offsets:' block.\nfull output:\n{}",
        stream_index,
        follow
    );
}

#[test]
fn transaction_stream_id_starts_at_zero() {
    ensure_dissector_loaded();
    let fixture = fixture_path();
    let out = tshark(&[
        "-2",
        "-r",
        fixture.to_str().unwrap(),
        "-T",
        "fields",
        "-e",
        "binderdump_reply.transaction_stream_id",
    ]);
    let has_zero = out.lines().any(|l| l.trim() == "0");
    assert!(
        has_zero,
        "expected at least one frame with transaction_stream_id == 0"
    );
}

#[test]
fn transaction_stream_id_is_dense() {
    ensure_dissector_loaded();
    let fixture = fixture_path();
    let out = tshark(&[
        "-2",
        "-r",
        fixture.to_str().unwrap(),
        "-T",
        "fields",
        "-e",
        "binderdump_reply.transaction_stream_id",
    ]);
    let mut indices: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    for line in out.lines() {
        if let Ok(n) = line.trim().parse::<u32>() {
            indices.insert(n);
        }
    }
    let max = *indices.iter().last().expect("no stream ids in fixture");
    for k in 0..=max {
        assert!(
            indices.contains(&k),
            "missing stream_id {} (max seen {}); set: {:?}",
            k,
            max,
            indices
        );
    }
}

// Regression test for the flat-object offset miscalculation: the dissector
// back-computes the tvb position of `txn.data` from the `offsets` field, and
// once assumed a 2-byte length prefix where binder_serde actually writes a
// u32. That shifted every rendered flat_binder_object field by 2 bytes, so the
// "Object Type" came out as garbage (e.g. 0x7368) and a HANDLE's value read as
// the next object's bytes — e.g. a checkService reply installing handle 0
// instead of 1. Assert every rendered object type is a real binder type id.
#[test]
fn flat_object_types_are_valid_binder_types() {
    use binderdump_structs::binder_types::binder_type;

    ensure_dissector_loaded();
    let fixture = fixture_path();

    let valid: std::collections::HashSet<u32> = [
        binder_type::BINDER,
        binder_type::WEAK_BINDER,
        binder_type::HANDLE,
        binder_type::WEAK_HANDLE,
        binder_type::FD,
        binder_type::FDA,
        binder_type::PTR,
    ]
    .into_iter()
    .map(|t| t as u32)
    .collect();

    let out = tshark(&[
        "-r",
        fixture.to_str().unwrap(),
        "-T",
        "fields",
        "-e",
        "binderdump.ioctl_data.bwr.transaction.offsets.entry.type",
    ]);

    let mut seen = 0usize;
    for line in out.lines() {
        for tok in line.split(',') {
            let tok = tok.trim();
            if tok.is_empty() {
                continue;
            }
            let ty: u32 = tok.parse().expect("type field should be a u32");
            assert!(
                valid.contains(&ty),
                "rendered flat object type {:#x} is not a known binder type \
                 (offset miscalculation regressed?)",
                ty
            );
            seen += 1;
        }
    }
    assert!(
        seen > 0,
        "fixture has no flat_binder_object entries to check"
    );
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let s = s.trim();
    assert!(s.len() % 2 == 0, "odd-length hex string: {:?}", s);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

// Stronger regression for the flat-object offset miscalculation: cross-check
// the rendered HANDLE value against the raw `data` bytes, using the data buffer
// itself as ground truth. The raw offsets array isn't exposed as an extractable
// field (the custom handler builds an anonymous subtree), so instead we locate
// the flat_binder_object directly: a BINDER_TYPE_HANDLE object begins with the
// 4-byte type magic at a 4-byte-aligned offset, and its handle is the u32 at
// offset+8. For frames with exactly one HANDLE object whose magic appears once
// at an aligned position in the captured data, the rendered handle must equal
// data[pos+8]. The off-by-2 base shifted the read to data[pos+10], so a
// checkService reply rendered handle 0 instead of 1; this test fails on that.
#[test]
fn handle_values_match_raw_data() {
    use binderdump_structs::binder_types::binder_type;

    ensure_dissector_loaded();
    let fixture = fixture_path();
    let magic = (binder_type::HANDLE as u32).to_le_bytes();

    let pfx = "binderdump.ioctl_data.bwr.transaction";
    let out = tshark(&[
        "-r",
        fixture.to_str().unwrap(),
        "-Y",
        &format!("{pfx}.offsets.entry.handle.handle"),
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        &format!("{pfx}.data"),
        "-e",
        &format!("{pfx}.offsets.entry.type"),
        "-e",
        &format!("{pfx}.offsets.entry.handle.handle"),
    ]);

    let mut checked = 0usize;
    for line in out.lines() {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 4 {
            continue;
        }
        let frame = cols[0];
        let data = hex_to_bytes(cols[1]);
        let handle_entries = cols[2]
            .split(',')
            .filter(|s| !s.is_empty())
            .filter(|s| s.parse::<u32>().ok() == Some(binder_type::HANDLE as u32))
            .count();
        let handles: Vec<u32> = cols[3]
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).expect("handle hex"))
            .collect();

        // Restrict to the unambiguous case: exactly one HANDLE object in the
        // frame, with the magic occurring exactly once at an aligned position
        // within the captured data.
        if handle_entries != 1 || handles.len() != 1 {
            continue;
        }
        let positions: Vec<usize> = (0..data.len().saturating_sub(12))
            .step_by(4)
            .filter(|&p| data[p..p + 4] == magic)
            .collect();
        if positions.len() != 1 {
            continue;
        }
        let pos = positions[0];
        let raw = u32::from_le_bytes(data[pos + 8..pos + 12].try_into().unwrap());
        assert_eq!(
            handles[0], raw,
            "frame {frame}: rendered handle {:#x} != data[{}+8] {:#x} \
             (flat object offset miscalculation regressed?)",
            handles[0], pos, raw
        );
        checked += 1;
    }

    assert!(
        checked > 0,
        "no single-HANDLE frames available to cross-check"
    );
}

#[test]
fn convenience_filter_fields_extract() {
    ensure_dissector_loaded();
    let fixture = fixture_path();
    let path = fixture.to_str().unwrap();

    // src.pid is set on every binderdump frame (local proc as fallback), so
    // it must extract at least one non-empty value.
    let src_pids = tshark(&["-r", path, "-T", "fields", "-e", "binderdump.src.pid"]);
    assert!(
        src_pids.lines().any(|l| !l.trim().is_empty()),
        "binderdump.src.pid extracted no values"
    );

    // dst.cmdline is only set on transaction frames; the fixture contains
    // transactions, so at least one frame should carry it.
    let dst_cmds = tshark(&["-r", path, "-T", "fields", "-e", "binderdump.dst.cmdline"]);
    assert!(
        dst_cmds.lines().any(|l| !l.trim().is_empty()),
        "binderdump.dst.cmdline extracted no values (expected on transaction frames)"
    );

    // bc/br must be filterable by substring. the fixture's traffic includes
    // BC_* commands on write frames; at least one frame matches a BC.
    let bc_frames = tshark(&[
        "-r",
        path,
        "-Y",
        "binderdump.bc contains \"BC_\"",
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]);
    assert!(
        bc_frames.lines().any(|l| !l.trim().is_empty()),
        "no frame matched `binderdump.bc contains \"BC_\"`"
    );

    // iface: the resolved AIDL interface token, filterable without the deep
    // struct path. the fixture has IServiceManager traffic.
    let iface_frames = tshark(&[
        "-r",
        path,
        "-Y",
        "binderdump.iface contains \"IServiceManager\"",
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]);
    assert!(
        iface_frames.lines().any(|l| !l.trim().is_empty()),
        "no frame matched `binderdump.iface contains \"IServiceManager\"`"
    );

    // regression: on the send (BC_TRANSACTION) frame the kernel leaves the wire
    // sender_pid == 0, so src.pid must come from the local process (event.pid),
    // not the wire sender_pid. extract both together and assert they agree.
    // the event.pid==0 guard below is defensive — a current-code capture sets
    // pid on every event, so it should not trigger on this fixture.
    let send_pairs = tshark(&[
        "-r",
        path,
        "-Y",
        "binderdump.bc contains \"BC_TRANSACTION\"",
        "-T",
        "fields",
        "-e",
        "binderdump.pid",
        "-e",
        "binderdump.src.pid",
    ]);
    let mut checked = 0usize;
    for line in send_pairs.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 2 {
            continue;
        }
        let event_pid: i64 = parts[0].trim().parse().unwrap_or(0);
        let src_pid: i64 = parts[1].trim().parse().unwrap_or(-1);
        if event_pid == 0 {
            continue;
        } // legitimately pid-less SplitIoctl write
        assert_eq!(
            src_pid, event_pid,
            "BC_TRANSACTION send frame: src.pid ({}) != event.pid ({}) \
             (wire sender_pid is 0 on send frames; the local pid must be used)",
            src_pid, event_pid
        );
        checked += 1;
    }
    assert!(
        checked > 0,
        "no BC_TRANSACTION send frames with a known event.pid in fixture"
    );
}

// Regression: AIDL parcel decode must render decoded parameter nodes for known
// interfaces using the committed AOSP corpus, not just fall back to raw nodes.
//
// Decoded params render through per-(interface, method, param) fields registered
// dynamically at dissection time; tshark can't reference those in -e/-Y (filters
// compile before dissection), so this asserts against the rendered tree (-V),
// which exercises the full decode + render path.
//
// getMemory (android.hardware.memtrack.IMemtrack, sdk 35): first param `pid`
// (int) decodes to 1362. onDnsEvent (android.net.metrics.INetdEventListener)
// carries a String16 hostname.
#[test]
fn parcel_params_decode_from_committed_corpus() {
    ensure_dissector_loaded();
    let fixture = fixture_path();
    let path = fixture.to_str().unwrap();
    let corpus_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../binderdump-aidl/data/aosp");
    let corpus_pref = format!(
        "binderdump.aosp_corpus_dir:{}",
        corpus_dir.to_str().unwrap()
    );
    let pfx = "binderdump.ioctl_data.bwr.transaction";

    // String16 decode: onDnsEvent carries a hostname rendered under Parameters.
    let strings = tshark(&[
        "-r",
        path,
        "-o",
        &corpus_pref,
        "-Y",
        &format!("{pfx}.interface==\"android.net.metrics.INetdEventListener\""),
        "-V",
    ]);
    assert!(
        strings.contains("chrome.cloudflare-dns.com"),
        "expected a decoded String16 param 'chrome.cloudflare-dns.com' in the tree; got:\n{}",
        strings
    );

    // Primitive decode: getMemory first param renders as "pid: 1362".
    let ints = tshark(&[
        "-r",
        path,
        "-o",
        &corpus_pref,
        "-Y",
        &format!("{pfx}.method_name==\"getMemory\""),
        "-V",
    ]);
    assert!(
        ints.contains("pid: 1362"),
        "expected decoded 'pid: 1362' (getMemory) in the tree; got tree without it",
    );
}

// Asserts the array-subtree render path: parser captured the array param →
// decoder produced Array{len:0} → dissector rendered the subtree title.
// onDnsEvent's `ipAddresses` is an empty String[] in the fixture; the title
// "ipAddresses: 0 items" exercises the full 2a array path even at len==0.
#[test]
fn parcel_array_renders_from_committed_corpus() {
    ensure_dissector_loaded();
    let fixture = fixture_path();
    let path = fixture.to_str().unwrap();
    let corpus_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../binderdump-aidl/data/aosp");
    let corpus_pref = format!(
        "binderdump.aosp_corpus_dir:{}",
        corpus_dir.to_str().unwrap()
    );
    let pfx = "binderdump.ioctl_data.bwr.transaction";

    let out = tshark(&[
        "-r",
        path,
        "-o",
        &corpus_pref,
        "-Y",
        &format!("{pfx}.interface==\"android.net.metrics.INetdEventListener\""),
        "-V",
    ]);
    assert!(
        out.contains("ipAddresses: 0 items"),
        "expected 'ipAddresses: 0 items' subtree title (array-decode render path); got tree without it"
    );
}

// Asserts the structured-parcelable render path against a dedicated fixture.
// parcelable.pcapng captures IDnsResolver.setResolverConfiguration(ResolverParamsParcel)
// transactions (driven via `service call dnsresolver 3 ...`); the dissector reads the
// parcelable size header, decodes the int fields in declaration order, and renders a
// subtree. Kept separate from sample.pcapng so the other tests' hardcoded values stay
// stable. Regenerate with binderdump-dissector/tests/regen_parcelable_fixture.sh.
#[test]
fn parcel_struct_renders_from_committed_corpus() {
    ensure_dissector_loaded();
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/parcelable.pcapng");
    let path = fixture.to_str().unwrap();
    let corpus_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../binderdump-aidl/data/aosp");
    let corpus_pref = format!(
        "binderdump.aosp_corpus_dir:{}",
        corpus_dir.to_str().unwrap()
    );
    let pfx = "binderdump.ioctl_data.bwr.transaction";

    let out = tshark(&[
        "-r",
        path,
        "-o",
        &corpus_pref,
        "-Y",
        &format!("{pfx}.interface==\"android.net.IDnsResolver\""),
        "-V",
    ]);
    // the parcelable subtree title and a decoded scalar field (netId = 100, the
    // first ResolverParamsParcel field) prove the size-header + field walk.
    assert!(
        out.contains("resolverParams: android.net.ResolverParamsParcel"),
        "expected ResolverParamsParcel subtree; got tree without it"
    );
    assert!(
        out.contains("resolverParams.netId: 100"),
        "expected decoded 'resolverParams.netId: 100' field; got tree without it"
    );
}

// Asserts the union render path against a dedicated fixture. union.pcapng captures
// IAudioFlingerService.getInputBufferSize(..., in AudioChannelLayout channelMask)
// calls (driven via `service call media.audio_flinger 24 ... i32 <tag> i32 <val>`);
// the dissector reads the union tag, decodes the selected member, and renders it as a
// subtree. Kept separate from the other fixtures so their values stay stable.
// Regenerate with binderdump-dissector/tests/regen_union_fixture.sh.
#[test]
fn parcel_union_renders_from_committed_corpus() {
    ensure_dissector_loaded();
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/union.pcapng");
    let path = fixture.to_str().unwrap();
    let corpus_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../binderdump-aidl/data/aosp");
    let corpus_pref = format!(
        "binderdump.aosp_corpus_dir:{}",
        corpus_dir.to_str().unwrap()
    );
    let pfx = "binderdump.ioctl_data.bwr.transaction";

    let out = tshark(&[
        "-r",
        path,
        "-o",
        &corpus_pref,
        "-Y",
        &format!("{pfx}.interface==\"android.media.IAudioFlingerService\""),
        "-V",
    ]);
    // the union subtree title + its active member (layoutMask = tag 3) prove the
    // tag read + member decode.
    assert!(
        out.contains("channelMask: android.media.audio.common.AudioChannelLayout"),
        "expected AudioChannelLayout union subtree; got tree without it"
    );
    assert!(
        out.contains("channelMask.layoutMask: 12"),
        "expected decoded union member 'channelMask.layoutMask: 12'; got tree without it"
    );
}

// Asserts the map render path against a dedicated fixture. map.pcapng captures
// IPackageManager.notifyDexLoad(String, in Map<String,String> classLoaderContextMap,
// String) calls (driven via `service call package 110 ... i32 <count> i32 0 s16 key
// i32 0 s16 value ...`); the dissector reads the self-describing writeMap (count +
// VAL_*-tagged key/value) and renders each entry as a key/value subtree. Kept separate
// from the other fixtures so their values stay stable.
// Regenerate with binderdump-dissector/tests/regen_map_fixture.sh.
#[test]
fn parcel_map_renders_from_committed_corpus() {
    ensure_dissector_loaded();
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/map.pcapng");
    let path = fixture.to_str().unwrap();
    let corpus_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../binderdump-aidl/data/aosp");
    let corpus_pref = format!(
        "binderdump.aosp_corpus_dir:{}",
        corpus_dir.to_str().unwrap()
    );
    let pfx = "binderdump.ioctl_data.bwr.transaction";

    let out = tshark(&[
        "-r",
        path,
        "-o",
        &corpus_pref,
        "-Y",
        &format!("{pfx}.interface==\"android.content.pm.IPackageManager\""),
        "-V",
    ]);
    // the map subtree title + a decoded entry (key "ck" -> value "cv") prove the
    // writeMap count + per-entry VAL_STRING key/value decode.
    assert!(
        out.contains("classLoaderContextMap: 1 entry"),
        "expected Map<String,String> subtree title; got tree without it"
    );
    assert!(
        out.contains("classLoaderContextMap.key: ck")
            && out.contains("classLoaderContextMap.value: cv"),
        "expected decoded map entry 'ck' -> 'cv'; got tree without it"
    );
}

// Asserts the Bundle render path against a dedicated fixture. bundle.pcapng captures
// IAppWidgetService.updateAppWidgetOptions(String callingPackage, int appWidgetId,
// in Bundle extras) calls (driven via `service call appwidget 12 ...`); the dissector
// reads the Bundle length+magic+count+entries and renders each entry as a key-named
// child. The Bundle carries four entries covering every new Java-only value type:
//   "n"   (VAL_INTEGER=1):          int 42
//   "cs"  (VAL_CHARSEQUENCE=10):    plain String "hi" (kind=1 + String8)
//   "pb"  (VAL_PERSISTABLEBUNDLE=25): nested PersistableBundle {"x": 7}
//   "ser" (VAL_SERIALIZABLE=21):    java.lang.Integer with 4-byte Java object stream
// Kept separate from the other fixtures so their values stay stable.
// Regenerate with binderdump-dissector/tests/regen_bundle_fixture.sh.
#[test]
fn parcel_bundle_renders_from_committed_corpus() {
    ensure_dissector_loaded();
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bundle.pcapng");
    let path = fixture.to_str().unwrap();
    let corpus_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../binderdump-aidl/data/aosp");
    let corpus_pref = format!(
        "binderdump.aosp_corpus_dir:{}",
        corpus_dir.to_str().unwrap()
    );
    let pfx = "binderdump.ioctl_data.bwr.transaction";

    // Fixture: a real IApplicationThread.setCoreSettings(Bundle) frame captured
    // while system_server propagated a debug_view_attributes settings change to
    // a running Java process.  Bundle is the only AIDL parameter — nothing
    // before it can block decode — and the bytes were written by real framework
    // Java (not service call hand-crafting).
    let out = tshark(&[
        "-r",
        path,
        "-o",
        &corpus_pref,
        "-Y",
        &format!("{pfx}.interface==\"android.app.IApplicationThread\""),
        "-V",
    ]);
    // Method resolved and Bundle parameter decoded.
    assert!(
        out.contains("Method: setCoreSettings"),
        "expected method name 'setCoreSettings'; got:\n{out}"
    );
    // Bundle header: at least one entry (actual count is device-dependent;
    // the fixture was captured with 14 entries but do not hard-code that).
    assert!(
        out.contains("coreSettings:"),
        "expected Bundle parameter 'coreSettings:'; got:\n{out}"
    );
    // debug_view_attributes is always present in coreSettings; we toggled it
    // to 1 to trigger the capture, so the value is guaranteed to be 1.
    assert!(
        out.contains("coreSettings.debug_view_attributes: 1"),
        "expected Bundle entry 'coreSettings.debug_view_attributes: 1'; got:\n{out}"
    );
    // long_press_timeout is a stable system default (400 ms) present in every
    // coreSettings Bundle regardless of which settings were recently changed.
    assert!(
        out.contains("coreSettings.long_press_timeout: 400"),
        "expected Bundle entry 'coreSettings.long_press_timeout: 400'; got:\n{out}"
    );
}

// Asserts the reply-decode path against a dedicated fixture. reply.pcapng captures
// IInputManager.getMousePointerSpeed (code 9, no params) calls driven via
// `service call input 9`. The pointer_speed setting is set to 3 before capture so
// the reply carries a non-zero int return value. The fixture includes the request
// frames and both reply halves (BC_REPLY write side and BR_REPLY read side), filtered
// to the complete transaction streams via a two-pass tshark run. The dissector resolves
// the method on the request frame, stores it in reply_correlation, then on each reply
// frame looks it up (the BR_REPLY read side via the reply's own debug_id) and calls
// decode_aidl_reply, rendering a "Reply" subtree with "return: 3" under it.
// Regenerate with binderdump-dissector/tests/regen_reply_fixture.sh.
#[test]
fn parcel_reply_renders_from_committed_corpus() {
    ensure_dissector_loaded();
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/reply.pcapng");
    let path = fixture.to_str().unwrap();
    let corpus_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../binderdump-aidl/data/aosp");
    let corpus_pref = format!(
        "binderdump.aosp_corpus_dir:{}",
        corpus_dir.to_str().unwrap()
    );

    // two-pass so reply_correlation is populated before the reply frame is dissected.
    let out = tshark(&["-2", "-r", path, "-o", &corpus_pref, "-V"]);
    // the reply is decoded on BOTH halves of the round-trip: the BC_REPLY (write) frame
    // (in_reply_to_debug_id stamped) and the BR_REPLY (read) frame (in_reply_to_debug_id
    // == 0, resolved via the reply's own debug_id). pointer_speed was set to 3 before
    // capture, so the int return value is 3. Split per frame so each side is checked
    // against its own command/return marker, not the whole capture.
    let frames: Vec<&str> = out.split("Frame ").collect();
    assert!(
        frames
            .iter()
            .any(|f| f.contains("BC_REPLY") && f.contains("return: 3")),
        "expected the BC_REPLY (write side) frame to decode 'return: 3'; got:\n{out}"
    );
    assert!(
        frames
            .iter()
            .any(|f| f.contains("BR_REPLY") && f.contains("return: 3")),
        "expected the BR_REPLY (read side) frame to decode 'return: 3'; got:\n{out}"
    );
}

#[test]
fn follow_via_stream_id_zero() {
    ensure_dissector_loaded();
    let fixture = fixture_path();
    let follow = tshark(&[
        "-2",
        "-r",
        fixture.to_str().unwrap(),
        "-z",
        "follow,binderdump,ascii,0",
    ]);
    let body = follow.lines().filter(|l| !l.trim().is_empty()).count();
    assert!(
        body > 0,
        "follow,binderdump,ascii,0 produced empty output:\n{}",
        follow
    );
}

// Verify that setTransactionState decodes the front half of layer_state_t and
// raw-tails the build-variant back half. Fixture: real android15-QPR capture of a
// single-layer setTransactionState transaction. Assertions cover only the verified
// front half (offsets 0-211 from layer_state_t start): method name, layerId=12,
// what=0x400000106e, and the raw tail. Fields after crop (field 11) are
// build-variant and therefore not asserted.
#[test]
fn set_transaction_state_decodes_layer_state() {
    ensure_dissector_loaded();
    let fixture = set_transaction_state_fixture();
    let out = tshark(&["-r", fixture.to_str().unwrap(), "-V"]);

    // method resolved from the android-35 native corpus
    assert!(
        out.contains("Method: setTransactionState"),
        "setTransactionState method not decoded:\n{}",
        &out[..out.len().min(2000)]
    );

    // layer identity fields — both BC_TRANSACTION and BR_TRANSACTION frames carry the
    // same front-half body; these are verified against the real capture hex
    assert!(
        out.contains("state.layerId: 12"),
        "layerId=12 not found in tshark output"
    );
    // what=0x000000400000106e = 274877911150 decimal (capture value confirmed in diagnosis)
    assert!(
        out.contains("state.what: 274877911150"),
        "state.what not decoded correctly"
    );

    // raw tail must be present after crop (confirms safe-partial boundary at field 12)
    assert!(
        out.contains("Parameter (raw)"),
        "raw tail missing after crop — safe-partial boundary not emitted"
    );
}
