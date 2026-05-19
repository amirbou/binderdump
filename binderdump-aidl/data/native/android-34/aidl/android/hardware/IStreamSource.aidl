// Synthetic AIDL stand-in for android::IStreamSource.
// Source: frameworks/av/media/libmedia/IStreamSource.cpp (android14-release)
// (enum and BnStreamSource::onTransact switch arms are in that .cpp)
//
//   SET_LISTENER       = IBinder::FIRST_CALL_TRANSACTION  // 1
//   SET_BUFFERS                                           // 2
//   ON_BUFFER_AVAILABLE                                   // 3
//   FLAGS                                                 // 4
//
// IStreamListener entries (5-6) share the same enum but belong to a separate interface.
//
// Parameter types are placeholders — payload decoding is out of scope.

package android.hardware;

interface IStreamSource {
    IBinder setListener() = 1;
    IBinder setBuffers() = 2;
    IBinder onBufferAvailable() = 3;
    IBinder flags() = 4;
}
