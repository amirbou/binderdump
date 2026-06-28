// Synthetic AIDL stand-in for android::ICameraRecordingProxy.
// Source: frameworks/av/camera/ICameraRecordingProxy.cpp (android15-release)
// (enum and BnCameraRecordingProxy::onTransact switch arms are in that .cpp)
//
//   START_RECORDING = IBinder::FIRST_CALL_TRANSACTION  // 1
//   STOP_RECORDING                                     // 2

package android.hardware;

interface ICameraRecordingProxy {
    void startRecording(out int status) = 1;
    void stopRecording() = 2;
}
