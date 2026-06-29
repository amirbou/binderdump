// Synthetic AIDL stand-in for android::IStreamSource.
// Source: frameworks/av/media/libmedia/IStreamSource.cpp (android16-release)
// (enum and BnStreamSource::onTransact switch arms are in that .cpp)
//
//   SET_LISTENER       = IBinder::FIRST_CALL_TRANSACTION  // 1
//   SET_BUFFERS                                           // 2
//   ON_BUFFER_AVAILABLE                                   // 3
//   FLAGS                                                 // 4
//
// IStreamListener entries (5-6) share the same enum but belong to a separate interface.
//
// Remaining IBinder methods are non-expressible stubs (IBinder loop without AIDL array header,
// AMessage custom parcelable).

package android.hardware;

interface IStreamSource {
    void setListener(in IBinder listener) = 1;
    void setBuffers(long count, in IBinder buffers) = 2;
    oneway void onBufferAvailable(long index) = 3;
    void flags(out int flags) = 4;
}
