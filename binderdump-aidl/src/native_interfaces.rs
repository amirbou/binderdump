// Hand-written C++ binder interfaces (no AIDL definition). Originally
// sourced from frameworks/native/libs/binder/include/binder/IInterface.h
// kManualInterfaces[]; entries that have since gained an AIDL definition
// in the synced corpus (binderdump-aidl/data/aosp/) are pruned because the
// registry resolves them via the dotted-fqn path instead.
//
// Test-only interfaces from libbinder's own test suite
// (android.gfx.tests.*) are intentionally excluded — captures from a real
// device won't see those descriptors.
//
// TODO: method-name resolution for these interfaces. Currently we only tag
// the interface as `native`; the transaction-code -> method-name table is
// not populated since these classes have no AIDL. Likely path: scrape each
// BnXxx subclass's onTransact() switch arms in AOSP, or codegen from the
// IInterface.h-adjacent headers that declare the IXxx::TransactionId enums.

use std::collections::HashSet;
use std::sync::OnceLock;

const FQNS: &[&str] = &[
    "android.content.IBulkCursor",
    "android.content.IContentProvider",
    "android.graphicsenv.IGpuService",
    "android.gui.IConsumerListener",
    "android.gui.IGraphicBufferConsumer",
    "android.gui.IGraphicBufferProducer",
    "android.gui.IJankListener",
    "android.gui.IProducerListener",
    "android.gui.ITransactionComposerListener",
    "android.gui.SensorEventConnection",
    "android.gui.SensorServer",
    "android.hardware.ICameraRecordingProxy",
    "android.hardware.ICameraRecordingProxyListener",
    "android.hardware.IOMXObserver",
    "android.hardware.IStreamListener",
    "android.hardware.IStreamSource",
    "android.media.IDataSource",
    "android.media.IMediaCodecList",
    "android.media.IMediaExtractor",
    "android.media.IMediaLogService",
    "android.media.IMediaMetadataRetriever",
    "android.media.IMediaPlayer",
    "android.media.IMediaPlayerClient",
    "android.media.IMediaPlayerService",
    "android.media.IMediaRecorder",
    "android.media.IMediaRecorderClient",
    "android.media.IMediaSource",
    "android.media.IRemoteDisplay",
    "android.media.IRemoteDisplayClient",
    "android.ui.ISurfaceComposer",
    "android.utils.IMemory",
    "android.utils.IMemoryHeap",
    "com.android.car.procfsinspector.IProcfsInspector",
    "drm.IDrmManagerService",
    "drm.IDrmServiceListener",
];

static MANUAL_INTERFACES: OnceLock<HashSet<&'static str>> = OnceLock::new();

pub fn is_native(fqn: &str) -> bool {
    MANUAL_INTERFACES
        .get_or_init(|| FQNS.iter().copied().collect())
        .contains(fqn)
}

/// Iterate every FQN tagged as native. Order is the declaration order
/// in [[FQNS]] — callers MUST NOT rely on it.
pub fn all() -> impl Iterator<Item = &'static str> {
    FQNS.iter().copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_native_interface() {
        assert!(is_native("android.gui.ITransactionComposerListener"));
        assert!(is_native("android.ui.ISurfaceComposer"));
        assert!(is_native("android.media.IMediaPlayer"));
    }

    #[test]
    fn unknown_is_not_native() {
        assert!(!is_native("com.example.IFoo"));
        assert!(!is_native("android.os.IServiceManager"));
        assert!(!is_native(""));
    }
}
