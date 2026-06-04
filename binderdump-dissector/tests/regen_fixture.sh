#!/bin/bash
# Regenerate binderdump-dissector/tests/fixtures/sample.pcapng.
# Requires: rooted Android device on adb. Allocates its own tmpdir
# for the pcapng that scripts/run.sh adb-pulls back; nothing for the
# caller to configure.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FIXTURE="${SCRIPT_DIR}/fixtures/sample.pcapng"

# BPF attach needs root.
adb root >/dev/null 2>&1 || true
adb wait-for-device

OUT_DIR="$(mktemp -d -t binderdump-fixture.XXXXXX)"
trap 'rm -rf "$OUT_DIR"' EXIT
export OUT_DIR
PULLED="${OUT_DIR}/out.pcapng"

# Capture for a few seconds while driving binder traffic on the device so the
# pcapng has real transactions even when the device is otherwise idle:
#   - `service check <name>`: an IServiceManager checkService whose reply carries
#     a HANDLE flat object (exercises offsets / flat-object dissection).
#   - `service list`: INTERFACE_TRANSACTION specials across many services.
#   - `dumpsys <svc>`: DUMP_TRANSACTION specials with sizeable payloads.
(cd "$REPO_ROOT" && cargo run --release -p binderdump -- -t 4) &
CAPTURE_PID=$!
sleep 1 # let the binary build/push/attach before generating traffic
adb shell 'end=$((SECONDS+3)); while [ $SECONDS -lt $end ]; do
  service check activity >/dev/null 2>&1
  service list >/dev/null 2>&1
  dumpsys meminfo system_server >/dev/null 2>&1
done' &
wait "$CAPTURE_PID"

cp "$PULLED" "$FIXTURE"
ls -la "$FIXTURE"
