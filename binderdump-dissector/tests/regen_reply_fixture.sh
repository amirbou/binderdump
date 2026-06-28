#!/bin/bash
# Regenerate binderdump-dissector/tests/fixtures/reply.pcapng — a small capture
# exercising AIDL reply decode. Requires a rooted Android device on adb whose
# AIDL is covered by the committed corpus (sdk in data/aosp).
#
# It drives IInputManager.getMousePointerSpeed (transaction code 9, no params),
# which replies with: status=0 (OK), then an int32 return value.
# The pointer_speed system setting is temporarily set to 3 so the reply carries
# a stable non-zero return value. The fixture is filtered to the complete
# transaction streams for getMousePointerSpeed (request + BC_REPLY + BR_REPLY)
# using a two-pass tshark run so the reply correlation stream IDs are available.
#
# Interface:  android.hardware.input.IInputManager
# Method:     getMousePointerSpeed (code 9)
# Signature:  int getMousePointerSpeed()
# Return:     int 3 (pointer_speed setting forced to 3 before capture)
#
# Note: the transaction code and corpus resolution are device/corpus-specific;
# the fixture depends on the AOSP android-35 corpus in binderdump-aidl/data/aosp.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FIXTURE="${SCRIPT_DIR}/fixtures/reply.pcapng"
CORPUS_DIR="${REPO_ROOT}/binderdump-aidl/data/aosp"

adb root >/dev/null 2>&1 || true
adb wait-for-device
adb shell rm -f /data/local/tmp/out.pcapng

OUT_DIR="$(mktemp -d -t binderdump-rfix.XXXXXX)"
trap 'rm -rf "$OUT_DIR"' EXIT
export OUT_DIR
LOG="${OUT_DIR}/cap.log"

# set pointer_speed to 3 so the reply carries a non-zero return value.
ORIG_SPEED="$(adb shell settings get system pointer_speed 2>/dev/null || echo 0)"
adb shell settings put system pointer_speed 3

(cd "$REPO_ROOT" && cargo run --release --bin binderdump -p binderdump -- -t 4 >"$LOG" 2>&1) &
CAPTURE_PID=$!
# wait until the binary is actually capturing before driving traffic
for _ in $(seq 1 40); do grep -q 'capturing events' "$LOG" && break; sleep 0.3; done

adb shell 'for i in 1 2 3; do
  service call input 9 >/dev/null 2>&1
  sleep 0.2
done'

wait "$CAPTURE_PID"

# restore the original pointer speed
adb shell settings put system pointer_speed "${ORIG_SPEED}" >/dev/null 2>&1 || true

adb pull /data/local/tmp/out.pcapng "${OUT_DIR}/out.pcapng"

# first pass: resolve which transaction_stream_ids belong to getMousePointerSpeed
# calls (two-pass so the reply correlation is available during filtering).
STREAM_IDS="$(tshark -2 -r "${OUT_DIR}/out.pcapng" \
  -o "binderdump.aosp_corpus_dir:${CORPUS_DIR}" \
  -Y 'binderdump.ioctl_data.bwr.transaction.method_name=="getMousePointerSpeed"' \
  -T fields -e "binderdump_reply.transaction_stream_id" \
  2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')"

if [ -z "$STREAM_IDS" ]; then
  echo "ERROR: no getMousePointerSpeed frames found in capture." >&2
  echo "  Check the device has the input service available (service list | grep input)." >&2
  exit 1
fi

# second pass: write all frames from those streams (request + reply + free_buffer)
# to the fixture. -2 is required so the stream_id fields are populated.
tshark -2 -r "${OUT_DIR}/out.pcapng" \
  -o "binderdump.aosp_corpus_dir:${CORPUS_DIR}" \
  -Y "binderdump_reply.transaction_stream_id in {${STREAM_IDS}}" \
  -w "$FIXTURE"

ls -la "$FIXTURE"
