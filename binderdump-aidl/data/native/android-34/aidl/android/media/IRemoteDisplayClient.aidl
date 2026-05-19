// Synthetic AIDL stand-in for android::IRemoteDisplayClient.
// Source: frameworks/av/media/libmedia/IRemoteDisplayClient.cpp (android14-release)
// (enum and BnRemoteDisplayClient::onTransact switch arms)
//
//   ON_DISPLAY_CONNECTED    = IBinder::FIRST_CALL_TRANSACTION  // 1
//   ON_DISPLAY_DISCONNECTED                                    // 2
//   ON_DISPLAY_ERROR                                           // 3
//
// Parameter types are placeholders — payload decoding is out of scope.

package android.media;

interface IRemoteDisplayClient {
    IBinder onDisplayConnected() = 1;
    IBinder onDisplayDisconnected() = 2;
    IBinder onDisplayError() = 3;
}
