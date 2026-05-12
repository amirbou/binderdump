#!/usr/bin/env bash
# Sync AOSP AIDL/HAL files into binderdump-aidl/data/aosp/.
#
# Pulls per-subtree tarballs from the AOSP gitiles +archive endpoint
# (no `repo` tool, no full AOSP checkout) and lays them out as:
#
#   binderdump-aidl/data/aosp/android-<sdk>/aidl/<source-relative-path>
#   binderdump-aidl/data/aosp/android-<sdk>/hal/<source-relative-path>
#
# Source mapping (matches data/aosp/README.md):
#   frameworks/base/core/java/                   -> aidl/
#   frameworks/base/services/                    -> aidl/
#   frameworks/base/telephony/                   -> aidl/
#   frameworks/base/wifi/                        -> aidl/
#   frameworks/base/media/                       -> aidl/
#   frameworks/native/libs/binder/aidl/          -> aidl/
#   frameworks/native/libs/gui/aidl/             -> aidl/
#   frameworks/native/libs/sensor/aidl/          -> aidl/
#   frameworks/native/libs/permission/aidl/      -> aidl/
#   frameworks/native/services/inputflinger/     -> aidl/
#   frameworks/native/services/surfaceflinger/   -> aidl/
#   frameworks/native/services/sensorservice/    -> aidl/
#   frameworks/av/                               -> aidl/
#   hardware/interfaces/                         -> aidl/
#   hardware/interfaces/                         -> hal/
#   system/hardware/interfaces/                  -> aidl/
#   system/libhidl/                              -> aidl/
#   system/sepolicy/                             -> aidl/
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

# Format: "<repo>:<subdir>:<ext>:<dest>"
# Empty subdir = root tarball of the repo.
PATH_TABLE=(
    "frameworks/base:core/java:aidl:aidl"
    "frameworks/base:services:aidl:aidl"
    "frameworks/base:telephony:aidl:aidl"
    "frameworks/base:wifi:aidl:aidl"
    "frameworks/base:media:aidl:aidl"
    "frameworks/base:packages/SystemUI:aidl:aidl"
    "frameworks/base:libs/WindowManager:aidl:aidl"
    "frameworks/native:libs/binder/aidl:aidl:aidl"
    "frameworks/native:libs/gui:aidl:aidl"
    "frameworks/native:libs/sensor/aidl:aidl:aidl"
    "frameworks/native:libs/permission/aidl:aidl:aidl"
    "frameworks/native:services/inputflinger:aidl:aidl"
    "frameworks/native:services/surfaceflinger:aidl:aidl"
    "frameworks/native:services/sensorservice:aidl:aidl"
    "frameworks/av::aidl:aidl"
    "frameworks/proto_logging::aidl:aidl"
    "hardware/interfaces::aidl:aidl"
    "hardware/interfaces::hal:hal"
    "system/hardware/interfaces::aidl:aidl"
    "system/libhidl::aidl:aidl"
    "system/sepolicy::aidl:aidl"
    "system/netd::aidl:aidl"
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

# copy_matching <src-root> <dst-root> <find-name-pattern>
# Copies files under src-root matching pattern into dst-root preserving
# relative paths.
copy_matching() {
    local src="$1" dst="$2" pattern="$3"
    [[ -d "$src" ]] || return 0
    local count=0
    while IFS= read -r -d '' f; do
        local rel="${f#"$src"/}"
        local target="$dst/$rel"
        mkdir -p "$(dirname "$target")"
        cp "$f" "$target"
        count=$((count + 1))
    done < <(find "$src" -type f -name "$pattern" -print0)
    log "    copied $count $pattern"
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

    local entry repo subdir ext dest dest_root tag stage_dir
    for entry in "${PATH_TABLE[@]}"; do
        IFS=':' read -r repo subdir ext dest <<< "$entry"
        case "$dest" in
            aidl) dest_root="$aidl_root" ;;
            hal)  dest_root="$hal_root" ;;
            *)    log "  bad dest in PATH_TABLE: $entry"; exit 1 ;;
        esac
        tag=$(echo "${repo}_${subdir}_${ext}" | tr '/' '_' | tr -s '_')
        stage_dir="$stage/$tag"

        if ! fetch_subtree "$repo" "$branch" "$subdir" "$stage_dir"; then
            log "  warn: fetch failed for $repo${subdir:+/$subdir} @ $branch (skipping)"
            continue
        fi
        copy_matching "$stage_dir" "$dest_root" "*.${ext}"
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
