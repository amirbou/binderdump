// Synthetic AIDL stand-in for android::IRemoteDisplay.
// Source: frameworks/av/media/libmedia/IRemoteDisplay.cpp (android16-release)
// (enum and BnRemoteDisplay::onTransact switch arms)
//
//   DISPOSE = IBinder::FIRST_CALL_TRANSACTION  // 1
//   PAUSE                                      // 2
//   RESUME                                     // 3
//
// Parameter types are placeholders — payload decoding is out of scope.

package android.media;

interface IRemoteDisplay {
    IBinder dispose() = 1;
    IBinder pause() = 2;
    IBinder resume() = 3;
}
