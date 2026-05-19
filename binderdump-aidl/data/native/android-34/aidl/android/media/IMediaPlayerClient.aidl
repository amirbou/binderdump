// Synthetic AIDL stand-in for android::IMediaPlayerClient.
// Source: frameworks/av/media/libmedia/IMediaPlayerClient.cpp (android14-release)
// (enum and BnMediaPlayerClient::onTransact switch arms)
//
//   NOTIFY = IBinder::FIRST_CALL_TRANSACTION  // 1
//
// Parameter types are placeholders — payload decoding is out of scope.

package android.media;

interface IMediaPlayerClient {
    IBinder notify() = 1;
}
