# AOSP AIDL/HIDL data

Each `android-<sdk>/` directory contains the verbatim AIDL/HIDL files
shipped with that AOSP release. Files are committed (not a submodule)
for hermetic builds.

## Refreshing or adding versions

Use `scripts/sync_aosp_aidl.sh`. It pulls per-subtree tarballs from the
AOSP gitiles `+archive` endpoint (no `repo` tool, no full AOSP checkout)
and lays them out as `android-<sdk>/{aidl,hal}/<source-relative-path>`.

```sh
scripts/sync_aosp_aidl.sh             # refresh all configured versions
scripts/sync_aosp_aidl.sh 14 15       # subset by Android release number
```

Source mapping the script applies:

| AOSP subtree                                | extension | destination |
| ------------------------------------------- | --------- | ----------- |
| `frameworks/base/core/java/`                | `.aidl`   | `aidl/`     |
| `frameworks/base/services/`                 | `.aidl`   | `aidl/`     |
| `frameworks/base/telephony/`                | `.aidl`   | `aidl/`     |
| `frameworks/base/wifi/`                     | `.aidl`   | `aidl/`     |
| `frameworks/base/media/`                    | `.aidl`   | `aidl/`     |
| `frameworks/native/libs/binder/aidl/`       | `.aidl`   | `aidl/`     |
| `frameworks/native/libs/gui/aidl/`          | `.aidl`   | `aidl/`     |
| `frameworks/native/libs/sensor/aidl/`       | `.aidl`   | `aidl/`     |
| `frameworks/native/libs/permission/aidl/`   | `.aidl`   | `aidl/`     |
| `frameworks/native/services/inputflinger/`  | `.aidl`   | `aidl/`     |
| `frameworks/native/services/surfaceflinger/`| `.aidl`   | `aidl/`     |
| `frameworks/native/services/sensorservice/` | `.aidl`   | `aidl/`     |
| `frameworks/av/`                            | `.aidl`   | `aidl/`     |
| `hardware/interfaces/`                      | `.aidl`   | `aidl/`     |
| `hardware/interfaces/`                      | `.hal`    | `hal/`      |
| `system/hardware/interfaces/`               | `.aidl`   | `aidl/`     |
| `system/libhidl/`                           | `.aidl`   | `aidl/`     |
| `system/sepolicy/`                          | `.aidl`   | `aidl/`     |

Note: `hardware/interfaces/tests/` subtrees are stripped after sync — they
import cross-version types that break the parser.

To add a new Android release, add its `<release>: "<sdk> <branch>"` row
to the `VERSIONS` table at the top of the script and re-run. Then:

1. `cargo build -p binderdump-aidl` — fix any parser regressions.
2. Update `Registry::with_builtin` callers if you've added new versions
   of any cargo enum / type.

The build script hard-fails on unparseable files. If a file can't parse
and the parser fix is non-trivial, remove the file and file an issue
rather than silencing.
