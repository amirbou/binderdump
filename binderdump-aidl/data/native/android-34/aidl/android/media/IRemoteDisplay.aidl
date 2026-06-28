// Synthetic AIDL stand-in for android::IRemoteDisplay.
// Source: frameworks/av/media/libmedia/IRemoteDisplay.cpp (android13-release)
// (enum and BnRemoteDisplay::onTransact switch arms)
//
//   DISPOSE = IBinder::FIRST_CALL_TRANSACTION  // 1
//   PAUSE                                      // 2
//   RESUME                                     // 3
//
// Wire: no request args; reply: readInt32() (status_t).

package android.media;

interface IRemoteDisplay {
    void dispose(out int status) = 1;
    void pause(out int status) = 2;
    void resume(out int status) = 3;
}
