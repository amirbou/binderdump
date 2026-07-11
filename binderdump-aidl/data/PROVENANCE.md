# Corpus provenance

Each `aosp/android-<sdk>/` and `native/android-<sdk>/` directory is synced by
`scripts/sync_aosp_aidl.sh` from a specific AOSP branch. The mapping:

| SDK | Android | Source branch      |
| --- | ------- | ------------------ |
| 33  | 13      | `android13-release` |
| 34  | 14      | `android14-release` |
| 35  | 15      | `android15-release` |
| 36  | 16      | `android16-release` |
| 37  | 17      | `android17-release` |

These are the **base yearly release** branches. Devices in the field — Pixel
QPR builds especially — ship interface revisions made *after* the base release:
methods appended to an interface, parameters added to a method, or a struct
field grown. When that happens the device's transaction codes and method
signatures no longer match the corpus for its SDK.

Two observable effects, both surfaced (not silently mislabeled) by the
dissector's `binderdump.decode_status`:

- **Extra transaction codes** — a method the base release didn't have yet shows
  as `code N not a known method of <iface>` (e.g. QPR-added `IOverviewProxy`
  methods on an android15-QPR2 device).
- **Grown/added parameters** — a method whose signature gained a parameter
  decodes its known params cleanly but leaves trailing bytes; the dissector
  reports `… trailing bytes after all params (unmodeled — possibly a newer
  signature than the corpus)` (AIDL only; HIDL trails its scatter-gather buffer
  region, which is expected). A parameter inserted in the *middle* of a signature
  instead shifts everything after it and shows up as a decode failure on a later
  param.

To reduce skew for a specific device, re-sync the relevant SDK from the matching
QPR branch (edit the `VERSIONS` map in `scripts/sync_aosp_aidl.sh`) — but note
that a later QPR re-introduces the same skew, so the base-release baseline is the
maintained default.
