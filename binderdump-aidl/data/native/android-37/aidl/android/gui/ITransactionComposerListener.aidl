// Synthetic AIDL stand-in for android::ITransactionCompletedListener.
// The wire descriptor remains "android.gui.ITransactionComposerListener" (legacy name).
// Source: frameworks/native/libs/gui/ITransactionCompletedListener.cpp (android17-release)
// (Tag enum and SafeInterface dispatch)
//
//   IMPLEMENT_META_INTERFACE(TransactionCompletedListener,
//                            "android.gui.ITransactionComposerListener")
//
//   ON_TRANSACTION_COMPLETED       = IBinder::FIRST_CALL_TRANSACTION  // 1
//   ON_RELEASE_BUFFER                                                  // 2
//   ON_TRANSACTION_QUEUE_STALLED                                       // 3
//   ON_TRUSTED_PRESENTATION_CHANGED                                    // 4
//
// onTransactionCompleted (1) decodes the ListenerStats front half (callback ids + latchTime)
// via native_struct; the presentFence/SurfaceStats tail is build-variant. onReleaseBuffer (2)
// stays an opaque IBinder stub (Fence Flattenable).

package android.gui;

interface ITransactionComposerListener {
    oneway void onTransactionCompleted(in ListenerStats stats) = 1;
    IBinder onReleaseBuffer() = 2;
    oneway void onTransactionQueueStalled(in String8 reason) = 3;
    oneway void onTrustedPresentationChanged(int id, boolean inTrustedPresentationState) = 4;
}
