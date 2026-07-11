#!/usr/bin/env bash
# Install the binderdump Wireshark dissector on a Linux host: the plugin .so, the
# AIDL/HIDL corpus, the column profile, and the extcap (live-capture helper). Run
# with no arguments from a repo checkout, or point the flags at release artifacts.
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: install_dissector.sh [--so PATH] [--corpus PATH] [--profile DIR] [--extcap PATH]

With no arguments, installs from the current repo checkout (a built dissector plus
binderdump-aidl/data). To install from release downloads, pass:

  --so PATH        the libbinderdump-<tag>-ws<X.Y>-x86_64-linux-gnu.so (or a built .so)
  --corpus PATH    the corpus: either a directory containing aosp/ and native/,
                   or a binderdump-aidl-corpus-<tag>-all.tgz
  --profile DIR    the wireshark/profiles/binderdump directory
  --extcap PATH    the binderdump-extcap script (live capture over adb)

Installs into the Wireshark personal config (respects XDG_CONFIG_HOME).
USAGE
}

SO="" CORPUS="" PROFILE="" EXTCAP=""
while [ $# -gt 0 ]; do
    case "$1" in
        --so) [ $# -ge 2 ] || { echo "missing value for --so" >&2; exit 2; }; SO="$2"; shift 2 ;;
        --corpus) [ $# -ge 2 ] || { echo "missing value for --corpus" >&2; exit 2; }; CORPUS="$2"; shift 2 ;;
        --profile) [ $# -ge 2 ] || { echo "missing value for --profile" >&2; exit 2; }; PROFILE="$2"; shift 2 ;;
        --extcap) [ $# -ge 2 ] || { echo "missing value for --extcap" >&2; exit 2; }; EXTCAP="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)

# Defaults from the repo layout when a flag wasn't given.
if [ -z "$SO" ]; then
    SO="$repo_root/target/x86_64-unknown-linux-gnu/release/libbinderdump_dissector.so"
fi
[ -n "$CORPUS" ] || CORPUS="$repo_root/binderdump-aidl/data"
[ -n "$PROFILE" ] || PROFILE="$repo_root/wireshark/profiles/binderdump"
[ -n "$EXTCAP" ] || EXTCAP="$repo_root/extcap/binderdump-extcap"

[ -f "$SO" ] || { echo "dissector .so not found: $SO" >&2; echo "build it first: cargo build --release -p binderdump-dissector" >&2; exit 1; }
command -v tshark >/dev/null || { echo "tshark not found; install Wireshark first" >&2; exit 1; }

# Derive both the plugin dir and the config root from the same authoritative source,
# so the .so and the data it loads always land under the same Wireshark installation.
folders=$(tshark -G folders)
plugin_dir=$(echo "$folders" | awk -F'\t' '/^Personal Plugins:/ {print $2; exit}')
config_dir=$(echo "$folders" | awk -F'\t' '/^Personal configuration:/ {print $2; exit}')
extcap_dir=$(echo "$folders" | awk -F'\t' '/^Personal Extcap path:/ {print $2; exit}')
[ -n "$config_dir" ] || config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/wireshark"

# 1. plugin .so -> Wireshark personal epan plugin dir (version-specific path).
[ -n "$plugin_dir" ] || { echo "could not determine the Wireshark personal plugin dir from 'tshark -G folders'" >&2; exit 1; }
mkdir -p "$plugin_dir/epan"
install -m 0644 "$SO" "$plugin_dir/epan/libbinderdump.so"
echo "installed dissector -> $plugin_dir/epan/libbinderdump.so"

# 2. corpus -> $config_dir/binderdump/{aosp,native}
dest_corpus="$config_dir/binderdump"
mkdir -p "$dest_corpus"
if [ -d "$CORPUS" ]; then
    for sub in aosp native; do
        [ -d "$CORPUS/$sub" ] || { echo "corpus dir missing $sub/: $CORPUS" >&2; exit 1; }
        # rsync keeps the install idempotent and prunes removed files; fall back to cp.
        if command -v rsync >/dev/null; then
            rsync -a --delete "$CORPUS/$sub/" "$dest_corpus/$sub/"
        else
            rm -rf "${dest_corpus:?}/$sub"; cp -r "$CORPUS/$sub" "$dest_corpus/$sub"
        fi
    done
elif [ -f "$CORPUS" ]; then
    tar xzf "$CORPUS" -C "$dest_corpus"   # all.tgz expands to aosp/ native/
    [ -d "$dest_corpus/aosp" ] || { echo "corpus tarball did not contain aosp/: $CORPUS" >&2; exit 1; }
else
    echo "corpus not found (dir or .tgz): $CORPUS" >&2; exit 1
fi
echo "installed corpus  -> $dest_corpus/{aosp,native}"

# 3. column profile -> $config_dir/profiles/binderdump
if [ -d "$PROFILE" ] && [ -f "$PROFILE/preferences" ]; then
    dest_profile="$config_dir/profiles/binderdump"
    mkdir -p "$dest_profile"
    install -m 0644 "$PROFILE"/* "$dest_profile/"
    echo "installed profile -> $dest_profile"
else
    echo "profile not found (need $PROFILE/preferences), skipping" >&2
fi

# 4. extcap -> personal extcap dir (executable), for live capture over adb.
if [ -f "$EXTCAP" ] && [ -n "$extcap_dir" ]; then
    mkdir -p "$extcap_dir"
    install -m 0755 "$EXTCAP" "$extcap_dir/binderdump-extcap"
    echo "installed extcap  -> $extcap_dir/binderdump-extcap"
else
    echo "extcap not installed (script $EXTCAP or extcap dir missing)" >&2
fi

echo
echo "Done. Open a capture, then switch to the 'binderdump' profile"
echo "(bottom-right of the Wireshark status bar) for the preset columns."
echo "For live capture, pick an 'Android binder (<serial>)' interface in Wireshark."
