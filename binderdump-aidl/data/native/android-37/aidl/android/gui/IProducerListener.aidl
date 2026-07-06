// Synthetic AIDL stand-in for the hand-written C++ binder interface
// android::IProducerListener. Source: frameworks/native/libs/gui/
// IProducerListener.cpp (android15-release) — the BpProducerListener
// transaction enum, anchored at IBinder::FIRST_CALL_TRANSACTION (1).
// Codes only; params are opaque (the callbacks carry no data we model).
//
//   ON_BUFFER_RELEASED  = 1
//   NEEDS_RELEASE_NOTIFY = 2
//   ON_BUFFERS_DISCARDED = 3

package android.gui;

interface IProducerListener {
    void onBufferReleased() = 1;
    void needsReleaseNotify() = 2;
    void onBuffersDiscarded() = 3;
}
