# Contributing

Thanks for taking a look. `binderdump` is a small project but it cross-
compiles into three different execution contexts (BPF kernel program,
Android userspace binary, host-side Wireshark plugin), so the build
setup is a bit fiddly. This guide is the short path.

## TL;DR — build environment

Easiest way: use the bundled Docker image.

```sh
git submodule update --init --recursive
docker build -t binderdump-build .
docker run --rm -it -v "$PWD":/work -w /work binderdump-build bash
# inside the container:
make
cargo build --release -p binderdump
cargo build --release -p binderdump-dissector
```

Or open the repo in VS Code with the "Dev Containers" extension and it
will pick up `.devcontainer/devcontainer.json` automatically.

## Native build (no Docker)

You'll need:

- Rust **nightly** (the workspace uses unstable
  `cargo-features = ["per-package-target"]` and `forced-target`).
- Android Rust targets:
  `rustup target add aarch64-linux-android x86_64-linux-android`.
- Android NDK **r26d** (other versions may work; r26d is what CI uses).
- Native toolchain: `m4 make autoconf automake autopoint pkg-config gawk gcc-multilib g++-multilib bison flex`.
- Host libbpf / libelf for `libbpf-sys`'s host build:
  `libelf-dev libbpf-dev zlib1g-dev libzstd-dev`.
- LLVM/Clang **19+** (`clang-19 clang-format-19 lld-19 llvm-19`).
  Older versions hit a known
  `emmintrin.h` error when compiling the dissector.
- Wireshark **4.6** dev headers (host): `libwireshark-dev libglib2.0-dev`.
  Ubuntu 24.04 still ships 4.2; pull 4.6 from
  `ppa:wireshark-dev/stable` or build from source.
- For the dissector integration test: `tshark` on `PATH`.

Set `ANDROID_NDK_ROOT` to the extracted NDK directory and run `make`
once. From then on, plain `cargo build` works.

```sh
export ANDROID_NDK_ROOT=/path/to/android-ndk-r26d
git submodule update --init --recursive
make
cargo build --release -p binderdump            # cross-compiles to aarch64-android by default
cargo build --release -p binderdump-dissector  # host (x86_64-linux-gnu) — forced by Cargo.toml
```

`make clean` removes `static_libs/` and `.cargo/config.toml`. Re-run
`make` after touching submodules.

## Running on a device

`scripts/run.sh` is wired in as the cargo `runner` for both Android
targets, so `cargo run -p binderdump` will `adb push` the binary to
`/data/local/tmp`, run it on the device, and `adb pull` the resulting
`out.pcapng` back to `$OUT_DIR`. The script's pull dir is hardcoded —
edit `scripts/run.sh` to match your local layout.

## Tests

Pure-logic crates test on the host:

```sh
cargo test -p binderdump-structs
cargo test -p binderdump-derive
cargo test -p binderdump-trait
```

The dissector has a tshark integration test driven from
`binderdump-dissector/tests/dissect.rs`. It feeds a committed pcapng
fixture (`tests/fixtures/sample.pcapng`) through `tshark` with the
plugin loaded. Build and install the plugin once, then run the test:

```sh
cargo build --release -p binderdump-dissector
PLUGIN_DIR=$(tshark -G folders | awk -F'\t' '/^Personal Plugins:/ {print $2; exit}')
mkdir -p "$PLUGIN_DIR/epan"
cp target/x86_64-unknown-linux-gnu/release/libbinderdump_dissector.so \
   "$PLUGIN_DIR/epan/libbinderdump.so"
cargo test -p binderdump-dissector --release
```

Regenerating the fixture (needs a rooted Android device on `adb`):

```sh
binderdump-dissector/tests/regen_fixture.sh
```

Only regenerate when the wire format or capture-side field population
actually changed — keeping it stable means smaller diffs.

## Pre-commit hooks

```sh
pipx install pre-commit   # or: python3 -m pip install --user pre-commit
pre-commit install
```

(Plain `pip install pre-commit` fails on Ubuntu 24.04 / Debian 12 /
Fedora 40 hosts because of PEP 668 — use `pipx` or a venv.)

The hooks run `cargo fmt`, `cargo check`, and `clang-format` on C
sources (BPF + the `binderdump-{sys,epan-sys}` bindgen wrappers). CI
runs the same hooks except `cargo-check`, which the `cross-build` job
covers end-to-end.

## Commit messages

We use a `subsystem: short description` form, e.g.
`capture: skip events from loader pid` or `dissector: register hf for
reply offsets`. Keep the subject line under ~70 characters. PR
descriptions should explain *why*, not just *what* — the diff already
shows what.

## Architecture

For a tour of the three execution environments and how the layered
wire format flows between them, see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Reporting bugs / asking questions

Please include:

- Device + Android version + kernel version (`uname -r`).
- Whether `/sys/kernel/btf/vmlinux` exists on the device (relevant for
  reply correlation).
- The `binderdump` command line and any non-default flags.
- For dissector bugs: the `tshark`/Wireshark version
  (`tshark -v | head -1`).
