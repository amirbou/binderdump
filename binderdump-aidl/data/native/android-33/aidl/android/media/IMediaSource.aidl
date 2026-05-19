// Synthetic AIDL stand-in for android::IMediaSource.
// Source: frameworks/av/media/libmedia/IMediaSource.cpp (android13-release)
// (first enum and BnMediaSource::onTransact switch arms; the second enum
//  defines buffer-type tags used in the reply payload, not transaction codes)
//
//   START                    = IBinder::FIRST_CALL_TRANSACTION  // 1
//   STOP                                                        // 2
//   PAUSE                                                       // 3
//   GETFORMAT                                                   // 4
//   // READ deprecated, skipped
//   READMULTIPLE                                                // 5
//   RELEASE_BUFFER                                              // 6
//   SUPPORT_NONBLOCKING_READ                                    // 7
//
// Parameter types are placeholders — payload decoding is out of scope.

package android.media;

interface IMediaSource {
    IBinder start() = 1;
    IBinder stop() = 2;
    IBinder pause() = 3;
    IBinder getFormat() = 4;
    IBinder readMultiple() = 5;
    IBinder releaseBuffer() = 6;
    IBinder supportNonblockingRead() = 7;
}
