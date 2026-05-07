#!/bin/bash
# Regenerate binderdump-dissector/tests/fixtures/sample.pcapng.
# Requires: rooted Android device on adb, and the cargo runner script
# (scripts/run.sh) configured to pull /data/local/tmp/out.pcapng to
# /mnt/d/pcaps after a binderdump run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FIXTURE="${SCRIPT_DIR}/fixtures/sample.pcapng"
PULLED="/mnt/d/pcaps/out.pcapng"

# Capture for 2s; trigger a binder transaction halfway through so the pcapng
# has at least one BC_TRANSACTION / BR_TRANSACTION_SEC_CTX pair.
(cd "$REPO_ROOT" && cargo run --release -p binderdump -- -t 2) &
CAP_PID=$!
sleep 1.5
adb shell 'service check activity >/dev/null 2>&1' &
wait

cp "$PULLED" "$FIXTURE"
ls -la "$FIXTURE"
