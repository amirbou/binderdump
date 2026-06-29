// Synthetic AIDL stand-in for android::IMediaRecorder.
// Source: frameworks/av/media/libmedia/IMediaRecorder.cpp (android17-release)
// (enum and BnMediaRecorder::onTransact switch arms)
//
//   RELEASE                                 = IBinder::FIRST_CALL_TRANSACTION  // 1
//   INIT                                                                        // 2
//   CLOSE                                                                       // 3
//   SET_INPUT_SURFACE                                                            // 4
//   QUERY_SURFACE_MEDIASOURCE                                                    // 5
//   QUERY_SURFACE_MEDIASOURCE_V2                                                 // 6
//   RESET                                                                        // 7
//   STOP                                                                         // 8
//   START                                                                        // 9
//   PREPARE                                                                      // 10
//   GET_MAX_AMPLITUDE                                                            // 11
//   SET_VIDEO_SOURCE                                                             // 12
//   SET_AUDIO_SOURCE                                                             // 13
//   SET_OUTPUT_FORMAT                                                            // 14
//   SET_VIDEO_ENCODER                                                            // 15
//   SET_AUDIO_ENCODER                                                            // 16
//   SET_OUTPUT_FILE_FD                                                           // 17
//   SET_NEXT_OUTPUT_FILE_FD                                                      // 18
//   SET_VIDEO_SIZE                                                               // 19
//   SET_VIDEO_FRAMERATE                                                          // 20
//   SET_PARAMETERS                                                               // 21
//   SET_PREVIEW_SURFACE                                                          // 22
//   SET_PREVIEW_SURFACE_V2                                                       // 23
//   SET_CAMERA                                                                   // 24
//   SET_LISTENER                                                                 // 25
//   SET_CLIENT_NAME                                                              // 26
//   PAUSE                                                                        // 27
//   RESUME                                                                       // 28
//   GET_METRICS                                                                  // 29
//   SET_INPUT_DEVICE                                                             // 30
//   GET_ROUTED_DEVICE_IDS                                                        // 31
//   ENABLE_AUDIO_DEVICE_CALLBACK                                                 // 32
//   GET_ACTIVE_MICROPHONES                                                       // 33
//   GET_PORT_ID                                                                  // 34
//   GET_RTP_DATA_USAGE                                                           // 35
//   SET_PREFERRED_MICROPHONE_DIRECTION                                           // 36
//   SET_PREFERRED_MICROPHONE_FIELD_DIMENSION                                     // 37
//   SET_PRIVACY_SENSITIVE                                                        // 38
//   GET_PRIVACY_SENSITIVE                                                        // 39
//
// Remaining IBinder methods are non-expressible stubs (fd, String8, Parcelable, Parcelable vector, or array reply).
// code 6: new QUERY_SURFACE_MEDIASOURCE_V2 (android17); uses readParcelable view::Surface — STUB.
// code 23: new SET_PREVIEW_SURFACE_V2 (android17); uses writeParcelable view::Surface — STUB.
// codes 7–22 and 24–39: shifted +1 and +2 respectively from android16 due to new insertions.

package android.media;

interface IMediaRecorder {
    void release(out int status) = 1;
    void init(out int status) = 2;
    void close(out int status) = 3;
    IBinder setInputSurface() = 4;
    void querySurfaceMediaSource(out IBinder source) = 5;
    IBinder querySurfaceMediaSourceV2() = 6;
    void reset(out int status) = 7;
    void stop(out int status) = 8;
    void start(out int status) = 9;
    void prepare(out int status) = 10;
    void getMaxAmplitude(out int max, out int status) = 11;
    void setVideoSource(int vs, out int status) = 12;
    void setAudioSource(int as, out int status) = 13;
    void setOutputFormat(int of, out int status) = 14;
    void setVideoEncoder(int ve, out int status) = 15;
    void setAudioEncoder(int ae, out int status) = 16;
    IBinder setOutputFileFd() = 17;
    IBinder setNextOutputFileFd() = 18;
    void setVideoSize(int width, int height, out int status) = 19;
    void setVideoFrameRate(int framesPerSecond, out int status) = 20;
    IBinder setParameters() = 21;
    void setPreviewSurface(in IBinder surface, out int status) = 22;
    IBinder setPreviewSurfaceV2() = 23;
    void setCamera(in IBinder camera, in IBinder proxy, out int status) = 24;
    void setListener(in IBinder listener, out int status) = 25;
    void setClientName(in String clientName, out int status) = 26;
    void pause(out int status) = 27;
    void resume(out int status) = 28;
    IBinder getMetrics() = 29;
    void setInputDevice(int deviceId, out int status) = 30;
    IBinder getRoutedDeviceIds() = 31;
    void enableAudioDeviceCallback(boolean enabled, out int status) = 32;
    IBinder getActiveMicrophones() = 33;
    void getPortId(out int status, out int portId) = 34;
    void getRtpDataUsage(out int status, out long bytes) = 35;
    void setPreferredMicrophoneDirection(int direction, out int status) = 36;
    void setPreferredMicrophoneFieldDimension(float zoom, out int status) = 37;
    void setPrivacySensitive(int privacySensitive, out int status) = 38;
    void getPrivacySensitive(out int status, out int privacySensitive) = 39;
}
