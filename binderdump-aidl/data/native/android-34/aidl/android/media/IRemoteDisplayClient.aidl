// Synthetic AIDL stand-in for android::IRemoteDisplayClient.
// Source: frameworks/av/media/libmedia/IRemoteDisplayClient.cpp (android14-release)
// (enum and BnRemoteDisplayClient::onTransact switch arms)
//
//   ON_DISPLAY_CONNECTED    = IBinder::FIRST_CALL_TRANSACTION  // 1
//   ON_DISPLAY_DISCONNECTED                                    // 2
//   ON_DISPLAY_ERROR                                           // 3
//
// Remaining IBinder stubs are non-expressible in AIDL:
//   ON_DISPLAY_CONNECTED: first param is IGraphicBufferProducer (typed surface binder)

package android.media;

interface IRemoteDisplayClient {
    IBinder onDisplayConnected() = 1;
    oneway void onDisplayDisconnected() = 2;
    oneway void onDisplayError(int error) = 3;
}
