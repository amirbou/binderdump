// Synthetic AIDL stand-in for android.gui.IJankListener. Upstream this is a
// stable AIDL (frameworks/native/libs/gui/aidl/android/gui/IJankListener.aidl)
// that first shipped in Android 16 / main; it appears on android15-QPR devices
// that backport it. Single method, code 1. The JankData[] param is opaque here.
//
//   onJankData = 1

package android.gui;

interface IJankListener {
    void onJankData() = 1;
}
