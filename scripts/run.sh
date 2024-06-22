#!/bin/bash
set -e
EXE="$1"
shift

adb push $EXE /data/local/tmp
trap "[ -d /mnt/d/pcaps ] && adb pull /data/local/tmp/out.pcapng /mnt/d/pcaps" EXIT
adb shell RUST_BACKTRACE=$RUST_BACKTRACE /data/local/tmp/$(basename $EXE) $@
