// Synthetic AIDL stand-in for android::IDrmServiceListener.
// Source: frameworks/av/drm/common/include/IDrmServiceListener.h (android13-release)
// Enum in IDrmServiceListener class body:
//
//   NOTIFY  = IBinder::FIRST_CALL_TRANSACTION  // 1
//
// Parameter types are placeholders — payload decoding is out of scope.

package drm;

interface IDrmServiceListener {
    IBinder notify() = 1;
}
