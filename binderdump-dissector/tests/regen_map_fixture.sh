#!/bin/bash
# Regenerate binderdump-dissector/tests/fixtures/map.pcapng — a small capture
# exercising the self-describing Map<String,V> decode. Requires a rooted Android
# device on adb whose AIDL is covered by the committed corpus (sdk in data/aosp).
#
# It drives IPackageManager.notifyDexLoad(String loadingPackageName,
# in Map<String,String> classLoaderContextMap, String loaderIsa) — a oneway method
# (transaction code 110 on the captured device; recompute if the corpus method order
# changes). The Map<String,String> is written by Parcel.writeMap: int32 count, then
# per entry writeValue(key)+writeValue(value), each = int32 VAL_STRING(0) tag + a
# String16. So the args are: s16 <pkg>, i32 <count>, then per entry (i32 0, s16 key,
# i32 0, s16 value), then s16 <isa>. The request reaches the binder driver and is
# captured regardless of whether the server rejects it. The capture is then filtered
# to just the IPackageManager frames to keep the fixture small.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FIXTURE="${SCRIPT_DIR}/fixtures/map.pcapng"

adb root >/dev/null 2>&1 || true
adb wait-for-device
adb shell rm -f /data/local/tmp/out.pcapng

OUT_DIR="$(mktemp -d -t binderdump-mfix.XXXXXX)"
trap 'rm -rf "$OUT_DIR"' EXIT
export OUT_DIR
LOG="${OUT_DIR}/cap.log"

(cd "$REPO_ROOT" && cargo run --release --bin binderdump -p binderdump -- -t 5 >"$LOG" 2>&1) &
CAPTURE_PID=$!
# wait until the binary is actually capturing before driving traffic
for _ in $(seq 1 40); do grep -q 'capturing events' "$LOG" && break; sleep 0.3; done
adb shell 'for i in 1 2 3 4 5; do
  service call package 110 s16 pkg i32 1 i32 0 s16 ck i32 0 s16 cv s16 arm64 >/dev/null 2>&1
  sleep 0.2
done'
wait "$CAPTURE_PID"

adb pull /data/local/tmp/out.pcapng "${OUT_DIR}/out.pcapng"
# keep only the IPackageManager frames so the committed fixture stays small.
tshark -r "${OUT_DIR}/out.pcapng" \
  -Y 'binderdump.ioctl_data.bwr.transaction.interface=="android.content.pm.IPackageManager"' \
  -w "$FIXTURE"
ls -la "$FIXTURE"
