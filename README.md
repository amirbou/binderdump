# Binderdump

tcpdump for Android's binder

The goal is to produce pcap files containing binder transactions, that can be viewed with WireShark with a provided dissector



## Development Setup

* Initialize the libelf submodule with `git submodule update --init --recursive`

* Install Rust using rustup

* Add Android build targets with `rustup target add x86_64-linux-android` and `rustup target add aarch64-linux-android`

* Download Android's latest NDK (I use r26d)

* Add a cargo config file to `~/.cargo/config.toml`, with the following content:
    ```toml
    [target.aarch64-linux-android]
    linker = "<NDK_HOME>/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang"

    [target.x86_64-linux-android]
    linker = "<NDK_HOME>/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android30-clang"

    [env]
    # needed for some dependancies that use the `cc` crate.
    CC_aarch64_linux_android = "<NDK_HOME>/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang"
    CC_x86_64_linux_android = "<NDK_HOME>/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android30-clang"
    ```

    `<NDK_HOME>` must be manually expanded to the root of the extracted NDK.
