# Binderdump

tcpdump for Android's binder

The goal is to produce pcap files containing binder transactions, that can be viewed with WireShark with a provided dissector



## Development Setup

* Initialize the libelf and libbpf submodules with `git submodule update --init --recursive`

* Install Rust using rustup

* Add Android build targets with `rustup target add x86_64-linux-android` and `rustup target add aarch64-linux-android`

* Download Android's latest NDK (I use r26d)

* Install `m4 make autotools clang gcc-multilib gawk clang-format` and maybe more things that I missed

* The dissector requires an updated `llvm` and `clang` installation otherwise some weird error related to `emmintrin.h` happens during compilation (I used llvm-19 and clang-19)

* Set the envrionment variable `ANDROID_NDK_ROOT` to point to the extracted NDK (`.../android-ndk-r26d`).

    You may skip this step and pass `ANDROID_NDK_ROOT=...` to `make` instead.

* Run `make` to build libelf and libbpf, and configure cargo with the correct toolchain.

    You should only have to call `make` once (unless updating the submodules). From that point, use `cargo` to build the project.

## Dissector setup

After building the dissector, you should copy it to `~/.local/lib/wireshark/plugins/3.6/epan/libbinderdump.so` (replace 3.6 with your Wireshark version)
