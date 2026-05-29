#!/bin/bash
# Regenerate binderdump-dissector/tests/fixtures/sample.pcapng.
# Requires: rooted Android device on adb. Allocates its own tmpdir
# for the pcapng that scripts/run.sh adb-pulls back; nothing for the
# caller to configure.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FIXTURE="${SCRIPT_DIR}/fixtures/sample.pcapng"

OUT_DIR="$(mktemp -d -t binderdump-fixture.XXXXXX)"
trap 'rm -rf "$OUT_DIR"' EXIT
export OUT_DIR
PULLED="${OUT_DIR}/out.pcapng"

# Capture for 2s; trigger a binder transaction halfway through so the pcapng
# has at least one BC_TRANSACTION / BR_TRANSACTION_SEC_CTX pair.
(cd "$REPO_ROOT" && cargo run --release -p binderdump -- -t 2) &
sleep 1.5
adb shell 'service check activity >/dev/null 2>&1' &
wait

cp "$PULLED" "$FIXTURE"
ls -la "$FIXTURE"
