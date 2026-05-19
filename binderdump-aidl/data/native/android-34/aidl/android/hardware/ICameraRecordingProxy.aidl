// Synthetic AIDL stand-in for android::ICameraRecordingProxy.
// Source: frameworks/av/camera/ICameraRecordingProxy.cpp (android14-release)
// (enum and BnCameraRecordingProxy::onTransact switch arms are in that .cpp)
//
//   START_RECORDING = IBinder::FIRST_CALL_TRANSACTION  // 1
//   STOP_RECORDING                                     // 2
//
// Parameter types are placeholders — payload decoding is out of scope.

package android.hardware;

interface ICameraRecordingProxy {
    IBinder startRecording() = 1;
    IBinder stopRecording() = 2;
}
