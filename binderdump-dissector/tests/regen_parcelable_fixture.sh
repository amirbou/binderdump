#!/bin/bash
# Regenerate binderdump-dissector/tests/fixtures/parcelable.pcapng — a small
# capture exercising structured-parcelable decode. Requires a rooted Android
# device on adb whose AIDL is covered by the committed corpus (sdk in data/aosp).
#
# It drives IDnsResolver.setResolverConfiguration (transaction code 3) with a
# hand-encoded short ResolverParamsParcel: the first arg is the parcelable size
# header, followed by the leading int fields (netId, sampleValiditySeconds, ...).
# The request reaches the binder driver (and is captured) regardless of whether
# dnsresolver rejects it on permission, so no special privileges are needed
# beyond root for the BPF attach.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FIXTURE="${SCRIPT_DIR}/fixtures/parcelable.pcapng"

adb root >/dev/null 2>&1 || true
adb wait-for-device
adb shell rm -f /data/local/tmp/out.pcapng

OUT_DIR="$(mktemp -d -t binderdump-pfix.XXXXXX)"
trap 'rm -rf "$OUT_DIR"' EXIT
export OUT_DIR

(cd "$REPO_ROOT" && cargo run --release --bin binderdump -p binderdump -- -t 3) &
CAPTURE_PID=$!
sleep 4 # let the binary build/push/attach before generating traffic
adb shell 'for i in 1 2 3; do
  service call dnsresolver 3 i32 32 i32 100 i32 1800 i32 25 i32 8 i32 8 i32 5000 i32 1 >/dev/null 2>&1
  sleep 0.3
done'
wait "$CAPTURE_PID"

adb pull /data/local/tmp/out.pcapng "$FIXTURE"
ls -la "$FIXTURE"
