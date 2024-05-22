#!/bin/sh
set -e
EXE="$1"

if [ $# -ne 1 ]; then
    echo "Usage: $0 <exe>"
    exit 1
fi

adb push $EXE /data/local/tmp
exec adb shell /data/local/tmp/$(basename $1)