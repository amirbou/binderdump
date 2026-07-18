#!/usr/bin/env bash
# Offline smoke test for install.sh / install_dissector.sh --bundle.
# Builds a fake bundle tree, stubs tshark + pkg-config, runs the installer,
# and asserts every component lands at its tshark-derived destination.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

tag="v9.9.9"
bundle="$work/binderdump-$tag"
mkdir -p "$bundle"/{dissector,corpus/aosp,corpus/native,profile/binderdump,extcap,android}

# Real scripts under test.
cp "$repo_root/scripts/install.sh" "$repo_root/scripts/install_dissector.sh" "$bundle/"
chmod +x "$bundle/install.sh" "$bundle/install_dissector.sh"

# Fake payload files.
echo fake-so   > "$bundle/dissector/libbinderdump-$tag-ws4.4-x86_64-linux-gnu.so"
echo fake-aosp > "$bundle/corpus/aosp/marker"
echo fake-nat  > "$bundle/corpus/native/marker"
printf 'x\n'   > "$bundle/profile/binderdump/preferences"
echo extcap    > "$bundle/extcap/binderdump-extcap"
echo capbin    > "$bundle/android/binderdump-$tag-aarch64-linux-android"
echo offbin    > "$bundle/android/offset_finder-$tag-aarch64-linux-android"

# Wireshark dirs the stub tshark will advertise.
export WS_PLUGIN="$work/ws/plugins"
export WS_CONFIG="$work/ws/config"
export WS_EXTCAP="$work/ws/extcap"
mkdir -p "$WS_PLUGIN/epan" "$WS_CONFIG" "$WS_EXTCAP"
# A stale plugin that must be removed by the install.
echo stale > "$WS_PLUGIN/epan/libbinderdump-vOLD.so"

# Stubs on PATH (prepended, so real cp/tar/awk/rsync still resolve).
stub="$work/stub"
mkdir -p "$stub"
cat > "$stub/tshark" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  -G) printf 'Personal Plugins:\t%s\n' "$WS_PLUGIN"
      printf 'Personal configuration:\t%s\n' "$WS_CONFIG"
      printf 'Personal Extcap path:\t%s\n' "$WS_EXTCAP" ;;
  --version) echo "TShark (Wireshark) 4.4.1" ;;
esac
EOF
cat > "$stub/pkg-config" <<'EOF'
#!/usr/bin/env bash
[ "${1:-}" = "--modversion" ] && [ "${2:-}" = "wireshark" ] && echo "4.4.1"
EOF
chmod +x "$stub/tshark" "$stub/pkg-config"

PATH="$stub:$PATH" "$bundle/install.sh"

fail=0
check() { if [ -e "$1" ]; then echo "ok   $1"; else echo "MISS $1"; fail=1; fi; }
check "$WS_PLUGIN/epan/libbinderdump-$tag.so"
check "$WS_CONFIG/binderdump/aosp/marker"
check "$WS_CONFIG/binderdump/native/marker"
check "$WS_CONFIG/profiles/binderdump/preferences"
check "$WS_EXTCAP/binderdump-extcap"
check "$WS_CONFIG/binderdump/bin/binderdump-$tag-aarch64-linux-android"
# offset_finder is NOT installed (only the capture binary is).
if [ -e "$WS_CONFIG/binderdump/bin/offset_finder-$tag-aarch64-linux-android" ]; then
  echo "UNEXPECTED offset_finder installed"; fail=1
fi
# Stale plugin removed.
if [ -e "$WS_PLUGIN/epan/libbinderdump-vOLD.so" ]; then
  echo "stale libbinderdump-vOLD.so not removed"; fail=1
fi
# Capture binary is executable.
[ -x "$WS_CONFIG/binderdump/bin/binderdump-$tag-aarch64-linux-android" ] || { echo "capture binary not executable"; fail=1; }

# Loose install (no --bundle, all sources given explicitly): the .so filename still
# carries a release tag, but the installer must NOT version-stamp it, and must NOT
# install a capture binary, since a loose install has no step-5 android/ payload.
export WS_PLUGIN="$work/ws2/plugins"
export WS_CONFIG="$work/ws2/config"
export WS_EXTCAP="$work/ws2/extcap"
mkdir -p "$WS_PLUGIN/epan" "$WS_CONFIG" "$WS_EXTCAP"

PATH="$stub:$PATH" "$bundle/install_dissector.sh" \
    --so "$bundle/dissector/libbinderdump-$tag-ws4.4-x86_64-linux-gnu.so" \
    --corpus "$bundle/corpus" \
    --profile "$bundle/profile/binderdump" \
    --extcap "$bundle/extcap/binderdump-extcap"

check "$WS_PLUGIN/epan/libbinderdump.so"
if [ -e "$WS_PLUGIN/epan/libbinderdump-$tag.so" ]; then
  echo "UNEXPECTED version-stamped plugin in loose install"; fail=1
fi
if [ -e "$WS_CONFIG/binderdump/bin/binderdump-$tag-aarch64-linux-android" ]; then
  echo "UNEXPECTED capture binary installed by loose install"; fail=1
fi

if [ "$fail" = 0 ]; then echo "PASS"; else echo "FAIL"; exit 1; fi
