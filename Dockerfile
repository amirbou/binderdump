# Reproducible build env for binderdump.
# Build:  docker build -t binderdump-build .
# Use:    docker run --rm -it -v "$PWD":/work -w /work binderdump-build bash
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV ANDROID_NDK_VERSION=r26d
ENV ANDROID_NDK_ROOT=/opt/android-ndk-${ANDROID_NDK_VERSION}
ENV PATH=/root/.cargo/bin:${PATH}

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip git make m4 autoconf automake autopoint \
        pkg-config gawk \
        gcc-multilib g++-multilib \
        bison flex \
        libelf-dev libbpf-dev zlib1g-dev libzstd-dev \
        clang-19 clang-format-19 lld-19 llvm-19 \
        software-properties-common \
        python3 python3-pip \
    && add-apt-repository -y ppa:wireshark-dev/stable \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        libwireshark-dev libglib2.0-dev tshark \
    && rm -rf /var/lib/apt/lists/*

RUN update-alternatives --install /usr/bin/clang        clang        /usr/bin/clang-19        100 \
 && update-alternatives --install /usr/bin/clang++      clang++      /usr/bin/clang++-19      100 \
 && update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-19 100 \
 && update-alternatives --install /usr/bin/llvm-strip   llvm-strip   /usr/bin/llvm-strip-19   100

RUN curl -fsSL -o /tmp/ndk.zip \
        https://dl.google.com/android/repository/android-ndk-${ANDROID_NDK_VERSION}-linux.zip \
 && unzip -q /tmp/ndk.zip -d /opt \
 && rm /tmp/ndk.zip

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- --default-toolchain nightly -y \
 && rustup target add aarch64-linux-android x86_64-linux-android x86_64-unknown-linux-gnu

RUN pip3 install --break-system-packages pre-commit

WORKDIR /work
CMD ["bash"]
