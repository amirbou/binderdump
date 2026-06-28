// Synthetic AIDL stand-in for android::IMediaLogService.
// Source: frameworks/av/services/medialog/IMediaLogService.cpp (android13-release)
// (enum and BnMediaLogService::onTransact switch arms)
//
//   REGISTER_WRITER     = IBinder::FIRST_CALL_TRANSACTION  // 1
//   UNREGISTER_WRITER                                      // 2
//   REQUEST_MERGE_WAKEUP                                   // 3
//
// Remaining IBinder stubs are non-expressible in AIDL:
//   REGISTER_WRITER: IMemory binder + writeCString (NUL-terminated, not String16)
//   UNREGISTER_WRITER: IMemory binder (typed shared-memory interface)

package android.media;

interface IMediaLogService {
    IBinder registerWriter() = 1;
    IBinder unregisterWriter() = 2;
    void requestMergeWakeup() = 3;
}
