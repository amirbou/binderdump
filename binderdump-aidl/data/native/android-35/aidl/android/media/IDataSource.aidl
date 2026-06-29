// Synthetic AIDL stand-in for android::IDataSource.
// Source: frameworks/av/media/libmedia/IDataSource.cpp (android15-release)
// (enum and BnDataSource::onTransact switch arms)
//
//   GET_IMEMORY = IBinder::FIRST_CALL_TRANSACTION  // 1
//   READ_AT                                        // 2
//   GET_SIZE                                       // 3
//   CLOSE                                          // 4
//   GET_FLAGS                                      // 5
//   TO_STRING                                      // 6
//
// Remaining IBinder stubs are non-expressible in AIDL:
//   GET_IMEMORY: returns IMemory binder (custom shared-memory interface)
//   GET_SIZE: two-field reply (int32 status + int64 size), not a scalar return
//   TO_STRING: writeString8/readString8 (UTF-8, not String16)

package android.media;

interface IDataSource {
    IBinder getIMemory() = 1;
    void readAt(long offset, long size, out long result) = 2;
    IBinder getSize() = 3;
    void close() = 4;
    void getFlags(out int flags) = 5;
    IBinder toString() = 6;
}
