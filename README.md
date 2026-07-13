# binderdump

[![CI](https://github.com/amirbou/binderdump/actions/workflows/ci.yml/badge.svg)](https://github.com/amirbou/binderdump/actions/workflows/ci.yml)

> tcpdump for Android's binder.

`binderdump` runs on an Android device, attaches eBPF tracepoints to the
binder driver, and writes binder transactions to a pcapng file. Open
the pcapng in Wireshark with the bundled dissector plugin and you get a
normal protocol tree for every binder ioctl, write, read, transaction,
and reply.

## Quickstart

### Use prebuilt binaries

Grab the latest release: <https://github.com/amirbou/binderdump/releases>. Each
release ships a `SHA256SUMS`; verify the downloads before running (the capture
binary runs as root):

```sh
sha256sum -c SHA256SUMS   # in the directory holding the downloaded artifacts
```

```sh
# 1. on a host with adb access to a rooted device
adb push binderdump-<tag>-aarch64-linux-android /data/local/tmp/binderdump
adb shell chmod +x /data/local/tmp/binderdump
adb shell /data/local/tmp/binderdump -t 5      # 5-second capture
adb pull /data/local/tmp/out.pcapng .

# 2. install the dissector, AIDL/HIDL corpus, and column profile (Linux host).
#    The corpus is required for method/param decoding — install_dissector.sh
#    places all three in the right Wireshark directories.
tar xzf binderdump-wireshark-profile-<tag>.tgz          # -> binderdump/
./install_dissector.sh \
    --so libbinderdump-<tag>-ws<X.Y>-x86_64-linux-gnu.so \
    --corpus binderdump-aidl-corpus-<tag>-all.tgz \
    --profile binderdump

# 3. open the pcapng in Wireshark, then switch to the "binderdump" profile
#    (bottom-right of the status bar) for the preset columns.
wireshark out.pcapng
```

The dissector `.so` is named for the Wireshark version it was built against
(`ws<X.Y>`). An epan plugin is ABI-locked to a Wireshark major.minor and will not
load into a different one — pick the artifact matching `wireshark --version`, or
build from source against your installed `libwireshark-dev`.

From a source checkout, `scripts/install_dissector.sh` needs no arguments —
it installs the just-built `.so`, the in-tree corpus, the profile, and the extcap.

### Live capture in the Wireshark UI

`install_dissector.sh` also installs an [extcap](https://www.wireshark.org/docs/man-pages/extcap.html)
helper (`binderdump-extcap`). With `adb` on `PATH` and the `binderdump` binary
pushed to the device (`/data/local/tmp/binderdump` by default), each connected
device shows up in Wireshark's interface list as **"Android binder (&lt;serial&gt;)"**
— pick it to capture live, no adb-pull needed. The gear icon exposes the duration
and reply-correlation options. Under the hood it runs
`adb exec-out binderdump -w -` and streams the pcapng into Wireshark.

binderdump needs root on the device. On a `userdebug` build with `adb root`
that is automatic. On a **production build rooted with Magisk**, set the gear
icon's **Root wrapper** field (or the `BINDERDUMP_SU` env var before launching
Wireshark) to the full command that runs a shell command as root on the device
— `adb exec-out su -c`. The extcap exports `ANDROID_SERIAL` for the selected
device and runs the capture through it.

### Live capture

`binderdump -w -` streams the pcapng to stdout (flushed per packet), so you can
pipe it straight into Wireshark instead of pulling a file afterwards:

```sh
adb exec-out /data/local/tmp/binderdump -w - | wireshark -k -i -
# or headless: ... | tshark -i -

# On a production build (root via Magisk), wrap the on-device run in `su -c`.
# Silence binderdump's stderr on the device: su folds it into stdout, which
# would corrupt the pcapng stream.
adb exec-out su -c '/data/local/tmp/binderdump -w - 2>/dev/null' | wireshark -k -i -
```

`-w <path>` (default `/data/local/tmp/out.pcapng`) still writes a file. When
streaming, status output goes to stderr so it can't corrupt the capture.

`scripts/run.sh` (the `cargo run` runner) takes the same `BINDERDUMP_SU`
env var, so `BINDERDUMP_SU="adb exec-out su -c" cargo run -p binderdump -- -t 5`
captures on a Magisk device and reads the root-owned pcapng back through the
wrapper.

### Build from source

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full setup. Shortest path
using the bundled Dockerfile:

```sh
git submodule update --init --recursive
docker build -t binderdump-build .
docker run --rm -v "$PWD":/work -w /work binderdump-build bash -c '
    make && cargo build --release -p binderdump && cargo build --release -p binderdump-dissector
'
```

## How it works

- The BPF program (`binderdump/src/bpf/binder.bpf.c`) hooks binder
  tracepoints and emits structured events to a ring buffer.
- The Android-side capture binary reads the ring buffer, joins related
  events into logical transactions, looks up `/proc/<pid>` metadata,
  and writes pcapng enhanced packet blocks containing a layered binder
  wire format.
- The host-side Wireshark plugin (`binderdump-dissector`) generates
  its `header_field_info` registration and dissection code at compile
  time via a `#[derive(EpanProtocol)]` proc-macro, from the **same**
  Rust structs the capture binary serializes. Touch a field, both
  ends rebuild.

For more detail on the pipeline and the trade-offs, see
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Reply correlation across kernels

`binderdump` cross-links each binder reply with its originating request
(see the `binderdump_reply` post-dissector and the `in_reply_to_debug_id`
column). The capture-side program that emits this metadata reads three
fields out of `struct binder_transaction` and `struct binder_thread`,
which are private kernel structs whose layout shifts between releases.

To stay portable the BPF program uses CO-RE: it declares minimal stubs
of those structs with `__attribute__((preserve_access_index))`, and
libbpf relocates each field access to the target kernel's offset at
load time using `/sys/kernel/btf/vmlinux`.

Requirements:

- Kernel >= 5.8 (already required for ring buffers).
- For the zero-config CO-RE path, `CONFIG_DEBUG_INFO_BTF=y` (Android GKI
  ships this by default from 5.15; 5.10 GKI usually builds without it).
- Binder driver compiled into the kernel (default on Android).

BTF is not required. If `/sys/kernel/btf/vmlinux` is missing or doesn't
include the binder structs, `binderdump` logs a one-line notice at startup
and keeps capturing everything else; you can still get reply correlation by
supplying the offsets manually with `--reply-offsets` (see below) — derive
them on-device with `offset_finder` or read them from kernel sources /
`pahole`.

CLI overrides:

- `--no-reply-correlation` — force-disable the BPF program even when
  BTF is present (escape hatch for "BTF lies").
- `--reply-offsets to_thread=N,transaction_stack=N,debug_id=N` — supply
  the three byte offsets manually (decimal or `0x`-prefixed hex), bypassing
  CO-RE entirely. Use when BTF is missing on-device but you have the
  offsets from kernel sources or `pahole`. Mutually exclusive with
  `--no-reply-correlation`.

### Deriving the offsets on-device (`offset_finder`)

When BTF is missing and you have no kernel sources, the bundled
`offset_finder` binary derives the `--reply-offsets` values at runtime
with no prior knowledge of the device. It loads a short calibration BPF
program, nudges some binder traffic, and solves the three offsets from
the live struct bytes, then prints the ready-to-use string:

```sh
cargo run --release --bin offset_finder           # pushes + runs via adb
# ...
# --reply-offsets to_thread=64,transaction_stack=64,debug_id=0
```

Paste that into `binderdump --reply-offsets ...`. It assumes a 64-bit
arm64 kernel with a 48-bit virtual address space (Android GKI 5.10/6.x);
a different VA size or a 32-bit kernel would need a code change. No BTF
is required. If it reports too few samples, re-run with more device
activity.

## Project status / known limitations

- **Partial transactions.** If a transaction was sent to a thread that
  was blocked on `binder_thread_read` before tracing started, only the
  `sys_exit` + `transaction_received` events will be visible. We
  currently only handle whole-transaction captures.
- **hwbinder** support has not been thoroughly tested.
- **Corpus version skew.** The bundled AIDL/HIDL corpus is synced from the base
  yearly AOSP release for each SDK (see
  [binderdump-aidl/data/PROVENANCE.md](binderdump-aidl/data/PROVENANCE.md)).
  Devices on later builds (Pixel QPRs) may add transaction codes or grow method
  signatures; the dissector surfaces these in `binderdump.decode_status` rather
  than mislabeling — a resolved method that leaves trailing bytes is flagged as
  "trailing bytes … possibly a newer signature than the corpus".

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). PRs welcome.

## License

See [LICENSE](LICENSE).
