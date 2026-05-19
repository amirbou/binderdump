// Synthetic AIDL stand-in for android::IOMXObserver.
// Source: frameworks/av/media/libmedia/IOMX.cpp (android15-release)
// (IOMXObserver is defined alongside IOMX in the same .cpp;
//  BnOMXObserver::onTransact has a single case: OBSERVER_ON_MSG)
//
// The shared enum in IOMX.cpp places OBSERVER_ON_MSG after the IOMXNode entries:
//   CONNECT                     = IBinder::FIRST_CALL_TRANSACTION  // 1
//   ...
//   OBSERVER_ON_MSG                                                 // 20
//
// However IOMXObserver is its own separate binder interface
// (IMPLEMENT_META_INTERFACE(OMXObserver, "android.hardware.IOMXObserver")).
// BnOMXObserver::onTransact dispatches on the raw integer value 20 because
// the enum is shared across both BnOMX and BnOMXObserver in the same TU.
// onMessages is therefore transaction code 20 on the wire.
//
// Parameter types are placeholders — payload decoding is out of scope.

package android.hardware;

interface IOMXObserver {
    IBinder onMessages() = 20;
}
