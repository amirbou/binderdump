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

SO="" CORPUS="" PROFILE="" EXTCAP="" BUNDLE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --so) [ $# -ge 2 ] || { echo "missing value for --so" >&2; exit 2; }; SO="$2"; shift 2 ;;
        --corpus) [ $# -ge 2 ] || { echo "missing value for --corpus" >&2; exit 2; }; CORPUS="$2"; shift 2 ;;
        --profile) [ $# -ge 2 ] || { echo "missing value for --profile" >&2; exit 2; }; PROFILE="$2"; shift 2 ;;
        --extcap) [ $# -ge 2 ] || { echo "missing value for --extcap" >&2; exit 2; }; EXTCAP="$2"; shift 2 ;;
        --bundle) BUNDLE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)

if [ "$BUNDLE" = 1 ]; then
    # Bundle layout is rooted at this script's own directory.
    bundle_dir="$script_dir"
    # Pick the .so matching the installed Wireshark major.minor.
    ws=$(pkg-config --modversion wireshark 2>/dev/null | cut -d. -f1,2 || true)
    [ -n "$ws" ] || ws=$(tshark --version 2>/dev/null | sed -n '1s/.*Wireshark[^0-9]*\([0-9]\{1,\}\.[0-9]\{1,\}\).*/\1/p' || true)
    [ -n "$ws" ] || { echo "could not determine the installed Wireshark version" >&2; exit 1; }
    # shellcheck disable=SC2012
    SO=$(ls "$bundle_dir"/dissector/*-ws"$ws"-*.so 2>/dev/null | head -n1 || true)
    if [ -z "$SO" ]; then
        echo "no bundled dissector for Wireshark $ws. Bundle carries:" >&2
        ls "$bundle_dir"/dissector/ >&2 || true
        echo "install a matching Wireshark, or build the dissector from source against your libwireshark-dev." >&2
        exit 1
    fi
    CORPUS="$bundle_dir/corpus"
    PROFILE="$bundle_dir/profile/binderdump"
    EXTCAP="$bundle_dir/extcap/binderdump-extcap"
else
    # Defaults from the repo layout when a flag wasn't given.
    if [ -z "$SO" ]; then
        SO="$repo_root/target/x86_64-unknown-linux-gnu/release/libbinderdump_dissector.so"
    fi
    [ -n "$CORPUS" ] || CORPUS="$repo_root/binderdump-aidl/data"
    [ -n "$PROFILE" ] || PROFILE="$repo_root/wireshark/profiles/binderdump"
    [ -n "$EXTCAP" ] || EXTCAP="$repo_root/extcap/binderdump-extcap"
fi

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
# Version-stamp only in bundle mode: a stamped name signals to the extcap that a
# matching capture binary was installed alongside (step 5). Loose/repo installs
# stay unversioned so the extcap keeps its device-side fallback.
if [ "$BUNDLE" = 1 ]; then
    so_base=$(basename "$SO")
    case "$so_base" in
        libbinderdump-*-ws*) tag=${so_base#libbinderdump-}; tag=${tag%%-ws*} ;;
        *) tag="" ;;
    esac
else
    tag=""
fi
if [ -n "$tag" ]; then dest_so="libbinderdump-$tag.so"; else dest_so="libbinderdump.so"; fi
# Only one binderdump plugin may be present; two -> duplicate hf registration.
rm -f "$plugin_dir/epan/"libbinderdump*.so
install -m 0644 "$SO" "$plugin_dir/epan/$dest_so"
echo "installed dissector -> $plugin_dir/epan/$dest_so"

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

# 5. android capture binary -> $config_dir/binderdump/bin (bundle mode only).
# Kept under its full version-stamped name so the extcap can select the build
# that matches the installed dissector; existing versions are left in place.
if [ "$BUNDLE" = 1 ]; then
    dest_bin="$config_dir/binderdump/bin"
    mkdir -p "$dest_bin"
    for b in "$bundle_dir"/android/binderdump-*-linux-android; do
        [ -f "$b" ] || continue
        install -m 0755 "$b" "$dest_bin/$(basename "$b")"
        echo "installed capture  -> $dest_bin/$(basename "$b")"
    done
fi

echo
echo "Done. Open a capture, then switch to the 'binderdump' profile"
echo "(bottom-right of the Wireshark status bar) for the preset columns."
echo "For live capture, pick an 'Android binder (<serial>)' interface in Wireshark."
