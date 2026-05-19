#!/usr/bin/env bash
# Sync AOSP AIDL/HAL files into binderdump-aidl/data/aosp/.
#
# Pulls per-subtree tarballs from the AOSP gitiles +archive endpoint
# (no `repo` tool, no full AOSP checkout) and lays them out as:
#
#   binderdump-aidl/data/aosp/android-<sdk>/aidl/<source-relative-path>
#   binderdump-aidl/data/aosp/android-<sdk>/hal/<source-relative-path>
#
# Source mapping (see PATH_TABLE below for the authoritative list):
#   frameworks/base/{core/java,services,telephony,wifi,media,telecomm,
#                    location,packages/*,libs/WindowManager,apex,
#                    keystore,graphics,omapi,mms,native,cmds/*,nfc-non-updatable}
#   frameworks/native/{libs/*,services/{inputflinger,surfaceflinger,
#                      sensorservice},cmds/{installd,dumpstate}/binder,aidl}
#   frameworks/av/                          (repo root)
#   frameworks/hardware/interfaces/         (repo root — IStats etc.)
#   frameworks/libs/modules-utils/java      (AndroidFuture, ParceledListSlice)
#   frameworks/opt/{net/voip,telephony}/src
#   packages/modules/*                      (mainline — Bluetooth, Wifi,
#                                            Connectivity, Nfc, Uwb,
#                                            Permission, NetworkStack,
#                                            DnsResolver, Virtualization,
#                                            AdServices, Bluetooth, etc.)
#   hardware/interfaces/                    (aidl + hal)
#   hardware/google/{av,gchips,interfaces,pixel}  (Pixel HALs)
#   hardware/nxp/nfc                        (Pixel NFC)
#   system/{apex,connectivity/wificond,core,extras,gsid,hardware/interfaces,
#           libhidl,logging,memory/mmd,netd,security,sepolicy,update_engine,
#           vold}
#   art/{artd,dexopt_chroot_setup}/binder   (ART mainline)
#   external/libtextclassifier/java/src     (TextClassifier model downloader)
#
# Usage:
#   scripts/sync_aosp_aidl.sh             # all configured versions
#   scripts/sync_aosp_aidl.sh 14 15       # subset by android release number

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
DATA_DIR="$REPO_ROOT/binderdump-aidl/data/aosp"
AOSP_BASE="https://android.googlesource.com/platform"

# release -> "<sdk> <branch>"
declare -A VERSIONS=(
    [13]="33 android13-release"
    [14]="34 android14-release"
    [15]="35 android15-release"
    [16]="36 android16-release"
)

# Format: "<repo>:<subdir>:<ext>:<dest>[:<rel-prefix>]"
# Empty subdir = root tarball of the repo.
# <rel-prefix> (optional) is prepended to each copied file's stage-relative
# path. Use it when the fetched subtree's top maps to a deeper package than
# its source-tree root — e.g. libs/gui/android/gui/X.aidl, fetched as
# libs/gui/android, has stage-relative path "gui/X.aidl" but its package is
# "android.gui" so it must land at aidl_root/android/gui/X.aidl.
PATH_TABLE=(
    # frameworks/base
    "frameworks/base:core/java:aidl:aidl"
    "frameworks/base:services:aidl:aidl"
    "frameworks/base:telephony:aidl:aidl"
    "frameworks/base:wifi:aidl:aidl"
    "frameworks/base:media:aidl:aidl"
    "frameworks/base:packages/SystemUI:aidl:aidl"
    "frameworks/base:libs/WindowManager:aidl:aidl"
    "frameworks/base:telecomm:aidl:aidl"
    "frameworks/base:location:aidl:aidl"
    "frameworks/base:packages/NeuralNetworks:aidl:aidl"
    "frameworks/base:apex:aidl:aidl"
    "frameworks/base:omapi/aidl/android:aidl:aidl:android"
    "frameworks/base:packages/SettingsLib:aidl:aidl"
    "frameworks/base:graphics:aidl:aidl"
    "frameworks/base:keystore:aidl:aidl"
    "frameworks/base:cmds/idmap2:aidl:aidl"
    "frameworks/base:packages/Vcn:aidl:aidl"
    "frameworks/base:nfc-non-updatable:aidl:aidl"
    "frameworks/base:packages/services:aidl:aidl"
    "frameworks/base:packages/PrintSpooler:aidl:aidl"
    "frameworks/base:cmds/uinput:aidl:aidl"
    "frameworks/base:mms:aidl:aidl"
    "frameworks/base:native/android/aidl:aidl:aidl"

    # frameworks/native
    "frameworks/native:libs/binder/aidl:aidl:aidl"
    "frameworks/native:libs/gui/aidl:aidl:aidl"
    "frameworks/native:libs/gui/android:aidl:aidl:android"
    "frameworks/native:libs/sensor/aidl:aidl:aidl"
    "frameworks/native:libs/permission/aidl:aidl:aidl"
    "frameworks/native:libs/input:aidl:aidl"
    "frameworks/native:libs/bufferstreams/aidl:aidl:aidl"
    "frameworks/native:libs/incidentcompanion/binder:aidl:aidl"
    "frameworks/native:libs/sensorprivacy/aidl:aidl:aidl"
    "frameworks/native:services/inputflinger:aidl:aidl"
    "frameworks/native:services/surfaceflinger:aidl:aidl"
    "frameworks/native:services/sensorservice:aidl:aidl"
    "frameworks/native:cmds/installd/binder:aidl:aidl"
    "frameworks/native:cmds/dumpstate/binder:aidl:aidl"
    "frameworks/native:aidl:aidl:aidl"

    # frameworks/{av, hardware, libs/*, opt/*}
    "frameworks/av::aidl:aidl"
    "frameworks/hardware/interfaces::aidl:aidl"
    "frameworks/libs/modules-utils:java:aidl:aidl"
    "frameworks/opt/net/voip:src:aidl:aidl"
    "frameworks/opt/telephony:src/java:aidl:aidl"

    # packages/modules (mainline)
    "packages/modules/AdServices:adservices/framework:aidl:aidl"
    "packages/modules/AdServices:sdksandbox/framework:aidl:aidl"
    "packages/modules/AdServices:sdksandbox/SdkSandbox:aidl:aidl"
    "packages/modules/AppSearch:framework:aidl:aidl"
    "packages/modules/AppSearch:apk/aidl:aidl:aidl"
    "packages/modules/Bluetooth:android/app/aidl:aidl:aidl"
    "packages/modules/Bluetooth:common/bluetooth/constants:aidl:aidl"
    "packages/modules/Bluetooth:offload/leaudio/aidl:aidl:aidl"
    "packages/modules/Bluetooth:service/aidl:aidl:aidl"
    "packages/modules/CaptivePortalLogin:src:aidl:aidl"
    "packages/modules/CellBroadcastService:src:aidl:aidl"
    "packages/modules/ConfigInfrastructure:framework:aidl:aidl"
    "packages/modules/Connectivity:framework:aidl:aidl"
    "packages/modules/Connectivity:framework-t:aidl:aidl"
    "packages/modules/Connectivity:service:aidl:aidl"
    "packages/modules/Connectivity:Tethering/common/TetheringLib/src:aidl:aidl"
    "packages/modules/Connectivity:nearby/framework:aidl:aidl"
    "packages/modules/Connectivity:networksecurity/framework/src:aidl:aidl"
    "packages/modules/Connectivity:remoteauth/framework:aidl:aidl"
    "packages/modules/Connectivity:staticlibs/device:aidl:aidl"
    "packages/modules/Connectivity:staticlibs/netd:aidl:aidl"
    "packages/modules/Connectivity:thread/framework:aidl:aidl"
    "packages/modules/CrashRecovery:framework:aidl:aidl"
    "packages/modules/DeviceLock:framework:aidl:aidl"
    "packages/modules/DeviceLock:DeviceLockController/src/com/android/devicelockcontroller:aidl:aidl"
    "packages/modules/DnsResolver:aidl_api/dnsresolver_aidl_interface:aidl:aidl"
    "packages/modules/DnsResolver:binder/android/net:aidl:aidl"
    "packages/modules/HealthFitness:framework:aidl:aidl"
    "packages/modules/ImsMedia:framework:aidl:aidl"
    "packages/modules/IntentResolver:java/aidl:aidl:aidl"
    "packages/modules/Media:apex/aidl:aidl:aidl"
    "packages/modules/NetworkStack:common/networkstackclient:aidl:aidl"
    "packages/modules/Nfc:framework:aidl:aidl"
    "packages/modules/OnDevicePersonalization:framework:aidl:aidl"
    "packages/modules/OnDevicePersonalization:federatedcompute/src:aidl:aidl"
    "packages/modules/OnDevicePersonalization:pluginlib/src:aidl:aidl"
    "packages/modules/Permission:framework:aidl:aidl"
    "packages/modules/Permission:framework-s:aidl:aidl"
    "packages/modules/Profiling:aidl:aidl:aidl"
    "packages/modules/RemoteKeyProvisioning:app/aidl:aidl:aidl"
    "packages/modules/Scheduling:framework:aidl:aidl"
    "packages/modules/StatsD:aidl:aidl:aidl"
    "packages/modules/Uwb:framework:aidl:aidl"
    "packages/modules/Uwb:androidx_backend:aidl:aidl"
    "packages/modules/Uwb:ranging/framework:aidl:aidl"
    "packages/modules/Virtualization:android:aidl:aidl"
    "packages/modules/Virtualization:guest/microdroid_manager/aidl:aidl:aidl"
    "packages/modules/Virtualization:libs:aidl:aidl"
    "packages/modules/Virtualization:microfuchsia/microfuchsiad/aidl:aidl:aidl"
    "packages/modules/Wifi:framework:aidl:aidl"
    "packages/modules/Wifi:aidl/mainline_supplicant:aidl:aidl"

    # hardware/interfaces (HIDL + AIDL combined repo)
    "hardware/interfaces::aidl:aidl"
    "hardware/interfaces::hal:hal"

    # hardware/google/* (Pixel HALs)
    "hardware/google/av:media/eco/aidl:aidl:aidl"
    "hardware/google/gchips:gralloc4/interfaces/aidl:aidl:aidl"
    "hardware/google/interfaces::aidl:aidl"
    "hardware/google/pixel:perfstatsd/binder:aidl:aidl"
    "hardware/google/pixel:powerstats/aidl:aidl:aidl"
    "hardware/nxp/nfc:intf/nxpnfc/aidl:aidl:aidl"

    # system/*
    "system/apex:apexd/aidl:aidl:aidl"
    "system/connectivity/wificond:aidl:aidl:aidl"
    "system/core:gatekeeperd/binder:aidl:aidl"
    "system/core:storaged/binder:aidl:aidl"
    "system/core:trusty/stats/aidl:aidl:aidl"
    "system/extras:partition_tools/aidl:aidl:aidl"
    "system/extras:profcollectd/binder:aidl:aidl"
    "system/gsid:aidl:aidl:aidl"
    "system/hardware/interfaces::aidl:aidl"
    "system/libhidl::aidl:aidl"
    "system/logging:logd/binder:aidl:aidl"
    "system/memory/mmd:aidl:aidl:aidl"
    "system/netd::aidl:aidl"
    "system/security:identity/binder:aidl:aidl"
    "system/security:keystore2/aidl:aidl:aidl"
    "system/sepolicy::aidl:aidl"
    "system/update_engine:binder_bindings:aidl:aidl"
    "system/update_engine:stable:aidl:aidl"
    "system/vold:binder:aidl:aidl"

    # art (mainline)
    "art:artd/binder:aidl:aidl"
    "art:dexopt_chroot_setup/binder:aidl:aidl"

    # external/*
    "external/libtextclassifier:java/src:aidl:aidl"
)

WORK_DIR="$(mktemp -d -t binderdump-aosp-sync.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

log() { printf '[sync] %s\n' "$*" >&2; }

# fetch_subtree <repo> <branch> <subdir-or-empty> <out-dir>
# Downloads <repo>/<subdir>@<branch> as a tarball and extracts into out-dir.
# Returns 1 (non-fatal) if the subtree doesn't exist on this branch.
fetch_subtree() {
    local repo="$1" branch="$2" subdir="$3" out_dir="$4"
    local url
    if [[ -z "$subdir" ]]; then
        url="$AOSP_BASE/$repo/+archive/refs/heads/$branch.tar.gz"
    else
        url="$AOSP_BASE/$repo/+archive/refs/heads/$branch/$subdir.tar.gz"
    fi
    log "  fetching $repo${subdir:+/$subdir} @ $branch"
    mkdir -p "$out_dir"
    if ! curl --fail --silent --show-error --location "$url" \
            | tar -xzf - -C "$out_dir" 2>/dev/null; then
        return 1
    fi
}

# copy_matching <src-root> <dst-root> <find-name-pattern> [<rel-prefix>]
# Copies files under src-root matching pattern into dst-root preserving
# relative paths. If <rel-prefix> is given it is inserted between dst-root
# and the file's stage-relative path.
copy_matching() {
    local src="$1" dst="$2" pattern="$3" prefix="${4:-}"
    [[ -d "$src" ]] || return 0
    local count=0
    while IFS= read -r -d '' f; do
        local rel="${f#"$src"/}"
        local target
        if [[ -n "$prefix" ]]; then
            target="$dst/$prefix/$rel"
        else
            target="$dst/$rel"
        fi
        mkdir -p "$(dirname "$target")"
        cp "$f" "$target"
        count=$((count + 1))
    done < <(find "$src" -type f -name "$pattern" -print0)
    log "    copied $count $pattern${prefix:+ -> $prefix/}"
}

sync_version() {
    local sdk="$1" branch="$2"
    local out="$DATA_DIR/android-$sdk"
    local aidl_root="$out/aidl"
    local hal_root="$out/hal"

    log ">> android-$sdk ($branch) -> $out"
    rm -rf "$out"
    mkdir -p "$aidl_root" "$hal_root"

    local stage="$WORK_DIR/$sdk"
    mkdir -p "$stage"

    local entry repo subdir ext dest prefix dest_root tag stage_dir
    for entry in "${PATH_TABLE[@]}"; do
        IFS=':' read -r repo subdir ext dest prefix <<< "$entry"
        case "$dest" in
            aidl) dest_root="$aidl_root" ;;
            hal)  dest_root="$hal_root" ;;
            *)    log "  bad dest in PATH_TABLE: $entry"; exit 1 ;;
        esac
        tag=$(echo "${repo}_${subdir}_${ext}_${prefix}" | tr '/' '_' | tr -s '_')
        stage_dir="$stage/$tag"

        if ! fetch_subtree "$repo" "$branch" "$subdir" "$stage_dir"; then
            log "  warn: fetch failed for $repo${subdir:+/$subdir} @ $branch (skipping)"
            continue
        fi
        copy_matching "$stage_dir" "$dest_root" "*.${ext}" "$prefix"
    done

    rm -rf "$stage"

    # strip hardware/interfaces HIDL tests/ trees — they import cross-version
    # types that break the parser.
    find "$hal_root" -path '*/tests/*' -delete 2>/dev/null || true

    # Drop empty directories.
    find "$aidl_root" "$hal_root" -type d -empty -delete 2>/dev/null || true

    local n_aidl n_hal
    n_aidl=$(find "$aidl_root" -type f -name '*.aidl' 2>/dev/null | wc -l)
    n_hal=$(find  "$hal_root" -type f -name '*.hal'  2>/dev/null | wc -l)
    log "   android-$sdk: $n_aidl .aidl, $n_hal .hal"
}

main() {
    local -a wanted=()
    if (( $# > 0 )); then
        wanted=("$@")
    else
        wanted=(13 14 15 16)
    fi

    for ver in "${wanted[@]}"; do
        local info="${VERSIONS[$ver]:-}"
        if [[ -z "$info" ]]; then
            log "unknown version: $ver (known: ${!VERSIONS[*]})"
            exit 1
        fi
        local sdk="${info%% *}"
        local branch="${info##* }"
        sync_version "$sdk" "$branch"
    done

    log "done. tree at: $DATA_DIR"
}

main "$@"
