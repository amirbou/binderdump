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
// Parameter types are placeholders — payload decoding is out of scope.

package android.media;

interface IDataSource {
    IBinder getIMemory() = 1;
    IBinder readAt() = 2;
    IBinder getSize() = 3;
    IBinder close() = 4;
    IBinder getFlags() = 5;
    IBinder toString() = 6;
}
