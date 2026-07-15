#!/bin/bash
set -e
# OUT_DIR: where to adb pull the resulting out.pcapng back to. If
# unset, the pull is skipped — useful when running on-device tests
# that produce no pcapng. Override per invocation:
#     OUT_DIR=/path/to/pcaps cargo run -p binderdump -- -t 5
#
# BINDERDUMP_SU: root wrapper for the on-device run. binderdump needs root.
# On a userdebug build with `adb root`, leave it unset (adbd is already root).
# On a production build rooted with Magisk, set it to the full command that runs
# a shell command as root on the device (ANDROID_SERIAL / the default device
# selects which), e.g.:
#     BINDERDUMP_SU="adb exec-out su -c" cargo run -p binderdump -- -t 5
OUT_DIR="${OUT_DIR:-}"
SU="${BINDERDUMP_SU:-}"
RESULT_FILE=/data/local/tmp/out.pcapng
EXE="$1"
shift
DEV_EXE="/data/local/tmp/$(basename "$EXE")"

# Pull the captured pcapng back. Run as root writes a root-owned file, so on a
# Magisk device read it through the wrapper (cat, stderr silenced because the
# wrapper folds it into stdout) rather than `adb pull` as the shell user.
pull_result() {
    [ -d "$OUT_DIR" ] || return 0
    local dst="$OUT_DIR/$(basename "$RESULT_FILE")"
    if [ -n "$SU" ]; then
        $SU "cat $RESULT_FILE 2>/dev/null" > "$dst" || true
        [ -s "$dst" ] || rm -f "$dst"
    else
        adb shell "[ -f $RESULT_FILE ]" && adb pull "$RESULT_FILE" "$OUT_DIR" || true
    fi
}

adb push "$EXE" /data/local/tmp
if [ "$(basename "$EXE")" = "binderdump" ] && [ -n "$OUT_DIR" ]; then
    trap pull_result EXIT
fi

# SU is left unquoted so a multi-word command splits into its own argv; the whole
# invocation is then one shell-command string the wrapper runs as root.
if [ -n "$SU" ]; then
    $SU "RUST_BACKTRACE=${RUST_BACKTRACE:-} $DEV_EXE $*"
else
    adb shell RUST_BACKTRACE="${RUST_BACKTRACE:-}" "$DEV_EXE" "$@"
fi
