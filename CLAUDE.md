# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`binderdump` is "tcpdump for Android's binder" — a binary that runs on Android, attaches eBPF tracepoints to the binder driver, and writes binder transactions to a pcapng file. The pcapng can then be opened in Wireshark using the bundled epan plugin (`binderdump-dissector`), which renders binder commands/returns as a normal protocol tree.

The tool deliberately spans three execution environments: a BPF program (kernel), an Android-side userspace capture binary, and a host-side Wireshark plugin. Code in the same struct often needs to be valid in all three, which drives much of the architecture below.

## Repository layout

Cargo workspace (see root `Cargo.toml`). Key crates:

| Crate | Purpose |
|---|---|
| `binderdump` | The Android capture binary. Owns the BPF source under `src/bpf/`, the ringbuf reader, the per-process metadata cache, and the pcapng writer. |
| `binderdump-sys` | bindgen wrapper around `<linux/android/binder.h>` (`src/binder_wrapper.h` → `binder_gen.rs`). |
| `binderdump-structs` | The shared protocol model used by both the capture binary and the dissector: `binder_command`, `binder_return`, `transaction`, plus the layered wire format (`link_layer`, `event_layer`, `bwr_layer`, `transaction_layer`) and a custom `binder_serde` (de)serializer. |
| `binderdump-trait` | The data model the dissector builds Wireshark fields from (`FtEnum`, `FieldDisplay`, etc.) — kept dependency-free so it can be shared. |
| `binderdump-derive` | `#[derive(EpanProtocol)]` proc macro. Walks struct fields and emits Wireshark header-field registration + dissection code from struct definitions. |
| `binderdump-epan-sys` | bindgen against the system Wireshark/epan and glib headers (requires `libwireshark-dev`, `libglib2.0-dev`). |
| `binderdump-dissector` | The `cdylib` Wireshark plugin. Combines `binderdump-structs` with `EpanProtocol`-derived registration to dissect captured pcapng files. |

The two leaf crates that link host libraries (`binderdump-epan-sys`, `binderdump-dissector`) are pinned to `forced-target = "x86_64-unknown-linux-gnu"` via `cargo-features = ["per-package-target"]`. The default cargo target (set in `.cargo/config.toml`) is `aarch64-linux-android`, so the workspace cross-compiles by default.

## Style guide

Use the `binderdump-style` skill before writing or editing any code in this workspace — Rust, BPF C, build scripts, tests, commit messages, or PR bodies. It documents the project's commit-message form, Rust idioms, error handling, comment voice, BPF C rules, dissector field registration, serde/wire-format invariants, and hard don'ts (no `unwrap` outside tests, no doc-comment ceremony, no file-header banners, etc.). Read it once at the start of a coding session and consult it whenever introducing a new file, helper, or dependency.

## Approach Verification

- Before implementing data structure changes (especially adding fields to structs/BPF maps), verify the field is not redundant with existing data
- Before adding any new field to a struct or BPF map, list every existing field that contains overlapping information and explain why the new field is necessary. If it can be derived from existing data, derive it instead
- When making assumptions about ABI, protocol, or kernel behavior, state the assumption explicitly and ask for confirmation before coding
- Prefer proper state tracking (e.g., sequence numbers) over fragile heuristics (e.g., 'check the last field')

## Build / run

The Android-side build depends on statically linked `libbpf` and `libelf` cross-compiled for Android via the NDK. **`make` builds those static libs and generates `.cargo/config.toml` from `.cargo/config_template.toml`.** Without running `make` first, cargo builds will fail because `config.toml` is gitignored and not present.

```sh
git submodule update --init --recursive          # libbpf + aosp-elfutils
export ANDROID_NDK_ROOT=.../android-ndk-r26d     # required by Makefile
make                                             # one-time: builds static libs, writes .cargo/config.toml
cargo build --release -p binderdump              # default target = aarch64-linux-android
cargo build --release -p binderdump-dissector    # forced to x86_64-unknown-linux-gnu (host)
```

Other useful cargo invocations:

```sh
cargo build -p binderdump --target x86_64-linux-android   # alternate Android arch
cargo build --no-default-features -p binderdump           # disables the `transaction-stack` feature
cargo run -p binderdump                                   # uses scripts/run.sh as the cargo runner — pushes to device via adb and execs
cargo test -p binderdump-structs                          # most tests live here and in binderdump-derive
```

`scripts/run.sh` is wired in as the cargo `runner` for both Android targets: `cargo run` will `adb push` the binary to `/data/local/tmp`, run it on the device, and (for the `binderdump` bin specifically) `adb pull` the resulting `out.pcapng` back to `$OUT_DIR` (currently hardcoded to `/mnt/d/pcaps`).

The dissector `.so` must be installed at `~/.local/lib/wireshark/plugins/<wireshark-version>/epan/libbinderdump.so` to be picked up by Wireshark.

`make clean` removes `static_libs/` and `.cargo/config.toml`. Re-run `make` after touching submodules.

### Dissector test fixture

`binderdump-dissector/tests/dissect.rs` runs `tshark` against a committed pcapng fixture at `binderdump-dissector/tests/fixtures/sample.pcapng`. Regenerate the fixture with:

```sh
binderdump-dissector/tests/regen_fixture.sh
```

When to run it:
- The wire format produced by `binderdump` changed — fields added/removed/reordered in `binderdump-structs` (`TransactionProtocol`, `EventProtocol`, `IoctlProtocol`, etc.). Old fixtures stop deserializing cleanly.
- The capture-side logic that populates protocol fields changed — e.g. new fields plumbed through from BPF events, or builder logic flipped.
- Dissector field abbrevs changed in a way that the test asserts against extracted values.

The script needs a rooted Android device on `adb` and uses `scripts/run.sh`'s hardcoded `/mnt/d/pcaps` pull dir. Don't regenerate the fixture for unrelated changes — keeping it stable means smaller diffs and reproducible test runs.

Pre-commit hooks (`.pre-commit-config.yaml`) run `cargo fmt`, `cargo check`, and `clang-format` on BPF C sources.

## Capture pipeline (the load-bearing flow)

End-to-end data flow when running on a device:

1. `binderdump/src/capture/tracepoints.rs::attach_tracepoints` opens, loads, and attaches the BPF skeleton generated by `libbpf-cargo` from `src/bpf/binder.bpf.c`. The skeleton is generated at build time by `binderdump/build.rs`, which also runs bindgen on `src/bpf/common_types.h` so the kernel-side struct definitions are visible to Rust.
2. The BPF program writes `struct binder_event` records (header + payload) to a ring buffer for: ioctl entry/exit, the inner `BINDER_WRITE_READ` write/read halves, transaction send/receive, transaction-data chunks, and process-exit invalidation. State is keyed on tid in BPF maps (see `src/bpf/maps.h`, `process_state.h`).
3. `capture/ringbuf.rs` reads the ring buffer on a thread and forwards events through an `EventChannel` (mpsc).
4. `pcapng/events_aggregator.rs` joins related events for the same ioctl into a single logical event before they reach the writer (e.g. ioctl + write + read + done).
5. `pcapng/packets.rs::PacketGenerator` consults `capture/process_cache.rs` (lazily reads `/proc/<pid>/comm`, `cmdline`, and the binder-fd → device-name mapping from `/proc/<pid>/fdinfo`) and emits enhanced packet blocks via the `pcap-file` crate.
6. The packet payload is the layered binder protocol: `link_layer` → `event_layer` → `bwr_layer` → `transaction_layer`, each serialized with the workspace's own `binder_serde` (the shapes need to round-trip into the dissector, not into a generic format).

Userspace does **not** read raw kernel binder structs directly — the BPF program normalizes everything into the `binder_event_*` structs in `common_types.h`, which are the contract between the two halves.

The `transaction-stack` cargo feature (default-on) toggles `-DFEATURE_TRANSACTION_STACK` in the BPF build (`build.rs`) and adds `BINDER_TXN_STACK` events that record `in_reply_to` for reply transactions. Disabling it removes both the BPF code path and the corresponding Rust handling.

## Dissector pipeline

`binderdump-dissector` is a Wireshark plugin (`cdylib`) loaded by `epan`. The interesting bit is that header fields and dissection code are generated from the same `binderdump-structs` types used by the writer:

- Structs in `binderdump-structs` derive `EpanProtocol` (from `binderdump-derive`).
- `binderdump-derive` parses `#[epan(...)]` attributes (display, ftype, name, abbrev, skip, …) and emits both registration code (a flat list of `header_field_info` entries Wireshark requires up front) and dissection code (walking the bytes back into a tree).
- `header_fields_manager.rs` owns the registration; `dissect_offsets.rs` and `binderdump.rs` wire the generated dissection into the epan callbacks declared in `epan_plugin.rs`.

This is why touching a field in `binderdump-structs` typically requires no change in the dissector — both ends rebuild from the same declaration. It's also why the `binderdump-trait` crate exists: the derive macro needs to reference field-type/display enums from a crate the trait-owner can depend on without pulling in `binderdump-sys` or `epan-sys`.

## Cross-cutting gotchas

- **Three compilation contexts for the same struct.** A type in `common_types.h` may be consumed by (a) the BPF program, (b) bindgen-generated Rust on the Android side, and (c) hand-written Rust in `binderdump-structs` whose layout must match the BPF program's writes. Don't change field order or sizes without checking all three.
- **Two cargo targets in one workspace.** Top-level `cargo build` cross-compiles to aarch64-android. The dissector and its sys crate force themselves to the host target. `cargo build --workspace` therefore builds for *both* targets in one invocation; expect long first builds.
- **Compat (32-bit) tracking.** The BPF program tracks per-task compat-syscall state (`raw_tp/sys_enter` + `sys_exit` set `in_compat_syscall_map`) so it can correctly interpret 32-bit binder structs on 64-bit kernels. The `g_loader_pid` global is set to the loader's pid from userspace at attach time (`tracepoints.rs`) and used to skip events from the loader itself.
- **Test execution requires a device.** Tests for `binderdump` run on-device through `scripts/run.sh`. Pure-logic crates (`binderdump-structs`, `binderdump-derive`, `binderdump-trait`) test fine on the host.
- **The `binder2.c` file in `src/bpf/` is currently untracked scratch work** (see `git status`) and is not part of the build — `build.rs` only compiles files matching `*.bpf.c`.
