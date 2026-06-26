#!/bin/bash
# Regenerate binderdump-dissector/tests/fixtures/union.pcapng — a small capture
# exercising union decode. Requires a rooted Android device on adb whose AIDL is
# covered by the committed corpus (sdk in data/aosp).
#
# It drives IAudioFlingerService.getInputBufferSize (transaction code 24), whose
# last param is `in AudioChannelLayout channelMask` (a union). The args are:
# sampleRate (int), AudioFormatDescription (a short parcelable: just its int32 size
# header, so its fields read as absent), then the union as `i32 <tag> i32 <value>`
# (tag 3 = layoutMask). The request reaches the binder driver and is captured
# regardless of whether audioflinger rejects it. The capture is then filtered to
# just the IAudioFlingerService frames to keep the fixture small.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FIXTURE="${SCRIPT_DIR}/fixtures/union.pcapng"

adb root >/dev/null 2>&1 || true
adb wait-for-device
adb shell rm -f /data/local/tmp/out.pcapng

OUT_DIR="$(mktemp -d -t binderdump-ufix.XXXXXX)"
trap 'rm -rf "$OUT_DIR"' EXIT
export OUT_DIR
LOG="${OUT_DIR}/cap.log"

(cd "$REPO_ROOT" && cargo run --release --bin binderdump -p binderdump -- -t 2 >"$LOG" 2>&1) &
CAPTURE_PID=$!
# wait until the binary is actually capturing before driving traffic
for _ in $(seq 1 40); do grep -q 'capturing events' "$LOG" && break; sleep 0.3; done
adb shell 'for i in 1 2 3 4; do
  service call media.audio_flinger 24 i32 48000 i32 4 i32 3 i32 12 >/dev/null 2>&1
  sleep 0.2
done'
wait "$CAPTURE_PID"

adb pull /data/local/tmp/out.pcapng "${OUT_DIR}/out.pcapng"
# keep only the IAudioFlingerService frames so the committed fixture stays small.
tshark -r "${OUT_DIR}/out.pcapng" \
  -Y 'binderdump.ioctl_data.bwr.transaction.interface=="android.media.IAudioFlingerService"' \
  -w "$FIXTURE"
ls -la "$FIXTURE"
