# AOSP AIDL/HIDL data

Each `android-<sdk>/` directory contains the verbatim AIDL/HIDL files
shipped with that AOSP release. Files are committed (not a submodule)
for hermetic builds.

## Adding a new Android version

Only `frameworks/`, `hardware/`, and `system/` are needed — no point
syncing the rest of AOSP. The `repo init` step is the same; pass each
project to `repo sync` explicitly:

1. `repo init -u https://android.googlesource.com/platform/manifest -b android-<release>`
2. `repo sync -j8 frameworks/base frameworks/native hardware/interfaces system/sepolicy system/libhidl`
3. Copy:
    - `frameworks/base/core/java/**/*.aidl`
    - `frameworks/native/libs/binder/aidl/**/*.aidl`
    - `system/sepolicy/**/*.aidl` (if any)
    - `hardware/interfaces/**/*.hal`
   into `binderdump-aidl/data/aosp/android-<sdk>/{aidl,hidl}/` preserving
   relative paths.
4. `cargo build -p binderdump-aidl` — fix any parser regressions.
5. Update `Registry::with_builtin` callers if you've added new versions
   of any cargo enum / type.

The build script hard-fails on unparseable files. If a file can't parse
and the parser fix is non-trivial, remove the file and file an issue
rather than silencing.
