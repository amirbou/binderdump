#!/bin/bash
set -e
EXE="$1"

if [ $# -ne 1 ]; then
    echo "Usage: $0 <exe>"
    exit 1
fi

adb push $EXE /data/local/tmp
trap "adb pull /data/local/tmp/out.pcapng /mnt/d/pcaps" EXIT
adb shell RUST_BACKTRACE=$RUST_BACKTRACE /data/local/tmp/$(basename $1)
