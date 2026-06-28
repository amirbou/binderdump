// Synthetic AIDL stand-in for android::IConsumerListener.
// Source: frameworks/native/libs/gui/IConsumerListener.cpp (android15-release)
// (Tag enum and BnConsumerListener::onTransact switch arms)
//
//   ON_DISCONNECT            = IBinder::FIRST_CALL_TRANSACTION  // 1
//   ON_FRAME_AVAILABLE                                          // 2
//   ON_FRAME_REPLACED                                          // 3
//   ON_BUFFERS_RELEASED                                        // 4
//   ON_SIDEBAND_STREAM_CHANGED                                 // 5
//   ON_FRAME_DEQUEUED                                          // 6
//   ON_FRAME_CANCELLED                                         // 7
//   ON_FRAME_DETACHED                                          // 8
//
// IMPLEMENT_META_INTERFACE(ConsumerListener, "android.gui.IConsumerListener")
//
// Remaining IBinder stubs (1–5) are non-expressible: no params/complex Parcelable.

package android.gui;

interface IConsumerListener {
    IBinder onDisconnect() = 1;
    IBinder onFrameAvailable() = 2;
    IBinder onFrameReplaced() = 3;
    IBinder onBuffersReleased() = 4;
    IBinder onSidebandStreamChanged() = 5;
    oneway void onFrameDequeued(long bufferId) = 6;
    oneway void onFrameCancelled(long bufferId) = 7;
    oneway void onFrameDetached(long bufferId) = 8;
}
