// Synthetic AIDL stand-in for android::ICameraRecordingProxyListener.
// Source: frameworks/av/camera/ICameraRecordingProxyListener.cpp (android11-release)
// (file deleted by android12-release; android11-release is the newest branch with it)
// (enum and BnCameraRecordingProxyListener::onTransact switch arms are in that .cpp)
//
//   DATA_CALLBACK_TIMESTAMP                    = IBinder::FIRST_CALL_TRANSACTION  // 1
//   RECORDING_FRAME_HANDLE_CALLBACK_TIMESTAMP                                     // 2
//   RECORDING_FRAME_HANDLE_CALLBACK_TIMESTAMP_BATCH                               // 3
//
// Remaining IBinder methods are non-expressible stubs (native_handle_t).

package android.hardware;

interface ICameraRecordingProxyListener {
    oneway void dataCallbackTimestamp(long timestamp, int msgType, in IBinder imageData) = 1;
    IBinder recordingFrameHandleCallbackTimestamp() = 2;
    IBinder recordingFrameHandleCallbackTimestampBatch() = 3;
}
