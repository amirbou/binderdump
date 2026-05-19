// Synthetic AIDL stand-in for android::IConsumerListener.
// Source: frameworks/native/libs/gui/IConsumerListener.cpp (android14-release)
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
// Parameter types are placeholders — payload decoding is out of scope.

package android.gui;

interface IConsumerListener {
    IBinder onDisconnect() = 1;
    IBinder onFrameAvailable() = 2;
    IBinder onFrameReplaced() = 3;
    IBinder onBuffersReleased() = 4;
    IBinder onSidebandStreamChanged() = 5;
    IBinder onFrameDequeued() = 6;
    IBinder onFrameCancelled() = 7;
    IBinder onFrameDetached() = 8;
}
