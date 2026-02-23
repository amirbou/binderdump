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


## TODO

Handle seeing only one side of the transaction:
    if a transaction was sent to a thread that was blocked on `binder_thread_read` before we started tracing, we will only see the `sys_exit` and `transaction_received` events. We would then try to create a packet for the received transaction, but won't have the `binder_write_read` event for that syscall.
    to solve this we could change `tp/` to `raw_tp/` in the tracepoint section to receive the raw arguments to the tracepoint - in `transaction_received` - the transaction object itself, and in `sys_exit`, the `pt_regs` of captured upon syscall entry. Using both should be enough to generate the data we need, but we would probably have to depend on the layout of `struct transaction`

    We are going to only handle cases where we see the whole transaction, so we can know at which offsets there are TXN/REPLY returns,


Make sure we correctly handle hwbinder
    I see no hwbinder requests in my captures...
