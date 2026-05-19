// Synthetic AIDL stand-in for android::IMediaLogService.
// Source: frameworks/av/services/medialog/IMediaLogService.cpp (android14-release)
// (IMediaLogService.cpp no longer present in android16-release; android14-release
//  is the most recent branch where services/medialog/IMediaLogService.cpp exists)
// (enum and BnMediaLogService::onTransact switch arms)
//
//   REGISTER_WRITER     = IBinder::FIRST_CALL_TRANSACTION  // 1
//   UNREGISTER_WRITER                                      // 2
//   REQUEST_MERGE_WAKEUP                                   // 3
//
// Parameter types are placeholders — payload decoding is out of scope.

package android.media;

interface IMediaLogService {
    IBinder registerWriter() = 1;
    IBinder unregisterWriter() = 2;
    IBinder requestMergeWakeup() = 3;
}
