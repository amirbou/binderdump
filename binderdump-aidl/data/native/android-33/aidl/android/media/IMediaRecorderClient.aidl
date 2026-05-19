// Synthetic AIDL stand-in for android::IMediaRecorderClient.
// Source: frameworks/av/media/libmedia/IMediaRecorderClient.cpp (android13-release)
// (enum and BnMediaRecorderClient::onTransact switch arms)
//
//   NOTIFY = IBinder::FIRST_CALL_TRANSACTION  // 1
//
// Parameter types are placeholders — payload decoding is out of scope.

package android.media;

interface IMediaRecorderClient {
    IBinder notify() = 1;
}
