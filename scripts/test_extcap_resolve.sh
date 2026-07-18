#!/usr/bin/env bash
# Offline smoke test: with a version-stamped dissector installed and a matching
# capture binary present, the extcap auto-selects and pushes that binary.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

tag="v9.9.9"
export WS_PLUGIN="$work/ws/plugins"
export WS_CONFIG="$work/ws/config"
export WS_EXTCAP="$work/ws/extcap"
mkdir -p "$WS_PLUGIN/epan" "$WS_CONFIG/binderdump/bin" "$WS_EXTCAP"
echo so  > "$WS_PLUGIN/epan/libbinderdump-$tag.so"
cap="$WS_CONFIG/binderdump/bin/binderdump-$tag-aarch64-linux-android"
echo cap > "$cap"

export PUSH_LOG="$work/push.log"
: > "$PUSH_LOG"

stub="$work/stub"; mkdir -p "$stub"
cat > "$stub/tshark" <<'EOF'
#!/usr/bin/env bash
[ "${1:-}" = "-G" ] || exit 0
printf 'Personal Plugins:\t%s\n' "$WS_PLUGIN"
printf 'Personal configuration:\t%s\n' "$WS_CONFIG"
printf 'Personal Extcap path:\t%s\n' "$WS_EXTCAP"
EOF
cat > "$stub/adb" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  shell) shift;
    if [ "$*" = "getprop ro.product.cpu.abi" ]; then
      if [ "${ABI_FAIL:-0}" = "1" ]; then
        exit 1
      fi
      echo arm64-v8a
    fi
    exit 0
    ;;
  push) echo "$2" >> "$PUSH_LOG"; exit 0 ;;
  exec-out) shift; cmd="$*"
    case "$cmd" in
      *"id -u"*) echo 0 ;;
      *"[ -x"*) exit 0 ;;
      *) printf 'pcapbytes' ;;
    esac ;;
esac
EOF
chmod +x "$stub/tshark" "$stub/adb"

# Scenario 1: Successful auto-resolve with version-matched binary
fifo="$work/fifo"   # a plain file is fine; the extcap only writes to it.
PATH="$stub:$PATH" "$repo_root/extcap/binderdump-extcap" \
    --capture --extcap-interface binder-emu --fifo "$fifo" || true

if grep -qF "$cap" "$PUSH_LOG"; then
    pass1=1
else
    echo "FAIL: extcap did not push the version-matched binary"; echo "push log:"; cat "$PUSH_LOG"; exit 1
fi

# Scenario 2: adb shell getprop fails; extcap should fail loud with a clear message
: > "$PUSH_LOG"  # reset the log
stderr_file="$work/stderr"
if ABI_FAIL=1 PATH="$stub:$PATH" "$repo_root/extcap/binderdump-extcap" \
    --capture --extcap-interface binder-emu --fifo "$fifo" 2>"$stderr_file"; then
    echo "FAIL: extcap should have exited non-zero when adb getprop fails"; exit 1
fi
if grep -qF "could not read the device CPU ABI" "$stderr_file"; then
    pass2=1
else
    echo "FAIL: extcap did not print the expected error message"; echo "stderr:"; cat "$stderr_file"; exit 1
fi

if [ "${pass1:-0}" = 1 ] && [ "${pass2:-0}" = 1 ]; then
    echo "PASS"
else
    echo "FAIL: one or more scenarios did not pass"; exit 1
fi
