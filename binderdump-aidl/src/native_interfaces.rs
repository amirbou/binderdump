// Hand-written C++ binder interfaces (no AIDL definition). Sourced from
// frameworks/native/libs/binder/include/binder/IInterface.h kManualInterfaces[].
// Refresh by re-pulling that file when AOSP updates the list.
//
// TODO: method-name resolution for these interfaces. Currently we only tag
// the interface as `native`; the transaction-code -> method-name table is
// not populated since these classes have no AIDL. Likely path: scrape each
// BnXxx subclass's onTransact() switch arms in AOSP, or codegen from the
// IInterface.h-adjacent headers that declare the IXxx::TransactionId enums.

use std::collections::HashSet;
use std::sync::OnceLock;

static MANUAL_INTERFACES: OnceLock<HashSet<&'static str>> = OnceLock::new();

pub fn is_native(fqn: &str) -> bool {
    MANUAL_INTERFACES
        .get_or_init(|| {
            [
                "android.app.IActivityManager",
                "android.app.IUidObserver",
                "android.gfx.tests.ICallback",
                "android.gfx.tests.IIPCTest",
                "android.gfx.tests.ISafeInterfaceTest",
                "android.graphicsenv.IGpuService",
                "android.gui.IConsumerListener",
                "android.gui.IGraphicBufferConsumer",
                "android.gui.ITransactionComposerListener",
                "android.gui.SensorEventConnection",
                "android.gui.SensorServer",
                "android.hardware.ICamera",
                "android.hardware.ICameraClient",
                "android.hardware.ICameraRecordingProxy",
                "android.hardware.ICameraRecordingProxyListener",
                "android.hardware.IOMXObserver",
                "android.hardware.IStreamListener",
                "android.hardware.IStreamSource",
                "android.media.IAudioService",
                "android.media.IDataSource",
                "android.media.IMediaCodecList",
                "android.media.IMediaExtractor",
                "android.media.IMediaHTTPConnection",
                "android.media.IMediaHTTPService",
                "android.media.IMediaLogService",
                "android.media.IMediaMetadataRetriever",
                "android.media.IMediaPlayer",
                "android.media.IMediaPlayerClient",
                "android.media.IMediaPlayerService",
                "android.media.IMediaRecorder",
                "android.media.IMediaRecorderClient",
                "android.media.IMediaResourceMonitor",
                "android.media.IMediaSource",
                "android.media.IRemoteDisplay",
                "android.media.IRemoteDisplayClient",
                "android.os.IPermissionController",
                "android.os.IProcessInfoService",
                "android.os.ISchedulingPolicyService",
                "android.os.storage.IObbActionListener",
                "android.os.storage.IStorageEventListener",
                "android.os.storage.IStorageManager",
                "android.os.storage.IStorageShutdownObserver",
                "android.ui.ISurfaceComposer",
                "android.utils.IMemory",
                "android.utils.IMemoryHeap",
                "com.android.car.procfsinspector.IProcfsInspector",
                "com.android.internal.app.IAppOpsService",
                "com.android.internal.app.IBatteryStats",
                "com.android.internal.os.IResultReceiver",
                "com.android.internal.os.IShellCallback",
                "drm.IDrmManagerService",
                "drm.IDrmServiceListener",
            ]
            .into_iter()
            .collect()
        })
        .contains(fqn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_native_interface() {
        assert!(is_native("android.gui.ITransactionComposerListener"));
        assert!(is_native("android.ui.ISurfaceComposer"));
        assert!(is_native("android.app.IActivityManager"));
    }

    #[test]
    fn unknown_is_not_native() {
        assert!(!is_native("com.example.IFoo"));
        assert!(!is_native("android.os.IServiceManager"));
        assert!(!is_native(""));
    }
}
