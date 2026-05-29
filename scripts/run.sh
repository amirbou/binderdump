#!/bin/bash
set -e
# OUT_DIR: where to adb pull the resulting out.pcapng back to. If
# unset, the pull is skipped — useful when running on-device tests
# that produce no pcapng. Override per invocation:
#     OUT_DIR=/path/to/pcaps cargo run -p binderdump -- -t 5
OUT_DIR="${OUT_DIR:-}"
RESULT_FILE=/data/local/tmp/out.pcapng
EXE="$1"
shift

adb push "$EXE" /data/local/tmp
if [ "$(basename "$EXE")" = "binderdump" ] && [ -n "$OUT_DIR" ]; then
    trap '[ -d "$OUT_DIR" ] && adb shell [ -f "$RESULT_FILE" ] && adb pull "$RESULT_FILE" "$OUT_DIR"' EXIT
fi
adb shell RUST_BACKTRACE=$RUST_BACKTRACE /data/local/tmp/$(basename "$EXE") "$@"
