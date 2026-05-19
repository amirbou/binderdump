// Synthetic AIDL stand-in for android::ITransactionCompletedListener.
// The wire descriptor remains "android.gui.ITransactionComposerListener" (legacy name).
// Source: frameworks/native/libs/gui/ITransactionCompletedListener.cpp (android15-release)
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
// Parameter types are placeholders — payload decoding is out of scope.

package android.gui;

interface ITransactionComposerListener {
    IBinder onTransactionCompleted() = 1;
    IBinder onReleaseBuffer() = 2;
    IBinder onTransactionQueueStalled() = 3;
    IBinder onTrustedPresentationChanged() = 4;
}
