#!/bin/bash
set -e
OUT_DIR=/mnt/d/pcaps
RESULT_FILE=/data/local/tmp/out.pcapng
EXE="$1"
shift

adb push $EXE /data/local/tmp
if [ $(basename $EXE) = "binderdump" ]; then
    trap "[ -d $OUT_DIR ] && adb shell [ -f $RESULT_FILE ] && adb pull $RESULT_FILE $OUT_DIR" EXIT
fi
adb shell RUST_BACKTRACE=$RUST_BACKTRACE /data/local/tmp/$(basename $EXE) $@
