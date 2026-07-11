# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html): once 1.0.0 is
tagged, the pcapng wire format and the `binderdump.*` dissector field names are
the public API, and breaking changes to either bump the major version.

## [Unreleased]

### Added
- `android.content.Intent` decoding, including the extras `Bundle`.
- Front-half decode of the `onTransactionCompleted` `ListenerStats` parameter
  (callback ids + latch time).
- Explicit "no parameters" / "no return value" markers for resolved methods that
  carry no payload, so an empty tree isn't mistaken for a decode failure.
- Corpus provenance (`binderdump-aidl/data/PROVENANCE.md`) and a version-skew
  signal in `binderdump.decode_status` when a resolved method leaves trailing
  bytes the base-release corpus doesn't model.
- `scripts/install_dissector.sh` and a bundled Wireshark column profile.
- Corpus additions: `IProducerListener`, `IJankListener`, `IContentProvider`,
  `IBulkCursor`, `IGraphicBufferProducer`, an android15-QPR2 `IOverviewProxy`
  bump, and the `_GHT` (get-HAL-token) special transaction code.

### Fixed
- Cleared the workspace's rustc dead-code warnings.
