# Synthetic AIDL for hand-written C++ binder interfaces

This corpus holds stand-in `.aidl` files for the legacy C++ binder
interfaces listed in `binderdump-aidl/src/native_interfaces.rs`.
These interfaces have never had real AIDL definitions in AOSP — they
are hand-written C++ classes (`IXxx.h` + `IXxx.cpp` with manual
onTransact switch arms). The dissector resolves their
`(interface, transaction_code) -> method_name` mapping by treating
this corpus as a secondary AIDL source (see `Source::Native`).

Each file mirrors the enum in the upstream `IXxx.cpp` (or `.h` for
the rare interfaces whose enum lives in the header). Parameter types
are placeholders (`IBinder`) — only method names matter; the payload
byte layout for these hand-written Parcelables is not modeled here.

To refresh: re-fetch the upstream source and update the explicit
transaction codes (`void foo() = N;`).

## Layout

```
binderdump-aidl/data/native/
└── android-<sdk>/
    └── aidl/
        └── <pkg-path>/IXxx.aidl
```

The directory structure mirrors `binderdump-aidl/data/aosp/`. One
synthetic `.aidl` per (interface, SDK) — when the upstream C++ enum is
identical across SDKs the files are byte-identical duplicates.

The registry resolves native lookups by SDK: `Registry::resolve(sdk,
fqn, code)` consults only the `android-<sdk>/aidl/` subtree's layers.

## Coverage matrix

| SDK | Sourced from | Interfaces | Notes |
|---|---|---|---|
| 33 | android13-release | 30 | IGpuService (4), SensorServer (6), ITransactionComposerListener (3) reflect smaller pre-android-14 enums; includes ICameraRecordingProxyListener (android-11 copy for vendor compat) |
| 34 | android14-release | 30 | IGpuService (5), SensorServer (7) reflect smaller pre-android-15 enums; IMediaPlayer/IMediaRecorder use singular GET_ROUTED_DEVICE_ID; includes ICameraRecordingProxyListener (android-11 copy for vendor compat) |
| 35 | android15-release | 30 | IGpuService (7) lacks GET_FEATURE_CONFIG_OVERRIDES added in android-16; IMediaPlayer/IMediaRecorder use singular GET_ROUTED_DEVICE_ID; IProcfsInspector fell back to android14-release (404 on android-15); includes ICameraRecordingProxyListener (android-11 copy for vendor compat) |
| 36 | android16-release | 30 | includes ICameraRecordingProxyListener (android-11 copy for vendor compat); IGpuService (8) adds getFeatureConfigOverrides |
| 37 | android17-release | 30 | IGpuService (9) adds getPersistGraphicsEgl; IMediaPlayer adds setVideoSurfaceTextureV2 (code 32); IMediaRecorder adds querySurfaceMediaSourceV2 (6) and setPreviewSurfaceV2 (23); IRemoteDisplayClient adds onDisplayConnectedSurface (4); IConsumerListener/IGraphicBufferConsumer kept at android-15 (de-binderized upstream — no binder enum past android-15); IMediaLogService kept android14-release (404 since); IProcfsInspector kept android14-release (removed upstream); includes ICameraRecordingProxyListener (android-11 copy for vendor compat) |

No per-SDK exemptions: every FQN in `binderdump-aidl/src/native_interfaces.rs`
has synthetic AIDL coverage at every SDK. Interfaces whose upstream class was
deleted (`android.ui.ISurfaceComposer`, `android.hardware.ICameraRecordingProxyListener`)
are sourced from an older AOSP branch (android-11 or android-12) and shipped
to all 5 SDK directories — vendor binaries may still emit these legacy
descriptors regardless of the Android version.

## Verification

Per-family unit tests in `binderdump-aidl/src/registry.rs` exercise every
synthetic interface via `Registry::with_native_dir`. End-to-end coverage
via the dissector fixture is opportunistic — most modern captures route
through AIDL-resolved interfaces. Regenerating the fixture to include
native-interface traffic is out of scope.
