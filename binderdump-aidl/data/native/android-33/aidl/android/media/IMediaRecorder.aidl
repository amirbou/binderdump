// Synthetic AIDL stand-in for android::IMediaRecorder.
// Source: frameworks/av/media/libmedia/IMediaRecorder.cpp (android13-release)
// (enum and BnMediaRecorder::onTransact switch arms)
//
//   RELEASE                                 = IBinder::FIRST_CALL_TRANSACTION  // 1
//   INIT                                                                        // 2
//   CLOSE                                                                       // 3
//   SET_INPUT_SURFACE                                                            // 4
//   QUERY_SURFACE_MEDIASOURCE                                                    // 5
//   RESET                                                                        // 6
//   STOP                                                                         // 7
//   START                                                                        // 8
//   PREPARE                                                                      // 9
//   GET_MAX_AMPLITUDE                                                            // 10
//   SET_VIDEO_SOURCE                                                             // 11
//   SET_AUDIO_SOURCE                                                             // 12
//   SET_OUTPUT_FORMAT                                                            // 13
//   SET_VIDEO_ENCODER                                                            // 14
//   SET_AUDIO_ENCODER                                                            // 15
//   SET_OUTPUT_FILE_FD                                                           // 16
//   SET_NEXT_OUTPUT_FILE_FD                                                      // 17
//   SET_VIDEO_SIZE                                                               // 18
//   SET_VIDEO_FRAMERATE                                                          // 19
//   SET_PARAMETERS                                                               // 20
//   SET_PREVIEW_SURFACE                                                          // 21
//   SET_CAMERA                                                                   // 22
//   SET_LISTENER                                                                 // 23
//   SET_CLIENT_NAME                                                              // 24
//   PAUSE                                                                        // 25
//   RESUME                                                                       // 26
//   GET_METRICS                                                                  // 27
//   SET_INPUT_DEVICE                                                             // 28
//   GET_ROUTED_DEVICE_ID                                                         // 29
//   ENABLE_AUDIO_DEVICE_CALLBACK                                                 // 30
//   GET_ACTIVE_MICROPHONES                                                       // 31
//   GET_PORT_ID                                                                  // 32
//   GET_RTP_DATA_USAGE                                                           // 33
//   SET_PREFERRED_MICROPHONE_DIRECTION                                           // 34
//   SET_PREFERRED_MICROPHONE_FIELD_DIMENSION                                     // 35
//   SET_PRIVACY_SENSITIVE                                                        // 36
//   GET_PRIVACY_SENSITIVE                                                        // 37
//
// Remaining IBinder methods are non-expressible stubs (fd, String8, Parcelable vector, or array reply).

package android.media;

interface IMediaRecorder {
    void release(out int status) = 1;
    void init(out int status) = 2;
    void close(out int status) = 3;
    IBinder setInputSurface() = 4;
    void querySurfaceMediaSource(out IBinder source) = 5;
    void reset(out int status) = 6;
    void stop(out int status) = 7;
    void start(out int status) = 8;
    void prepare(out int status) = 9;
    void getMaxAmplitude(out int max, out int status) = 10;
    void setVideoSource(int vs, out int status) = 11;
    void setAudioSource(int as, out int status) = 12;
    void setOutputFormat(int of, out int status) = 13;
    void setVideoEncoder(int ve, out int status) = 14;
    void setAudioEncoder(int ae, out int status) = 15;
    IBinder setOutputFileFd() = 16;
    IBinder setNextOutputFileFd() = 17;
    void setVideoSize(int width, int height, out int status) = 18;
    void setVideoFrameRate(int framesPerSecond, out int status) = 19;
    IBinder setParameters() = 20;
    void setPreviewSurface(in IBinder surface, out int status) = 21;
    void setCamera(in IBinder camera, in IBinder proxy, out int status) = 22;
    void setListener(in IBinder listener, out int status) = 23;
    void setClientName(in String clientName, out int status) = 24;
    void pause(out int status) = 25;
    void resume(out int status) = 26;
    IBinder getMetrics() = 27;
    void setInputDevice(int deviceId, out int status) = 28;
    void getRoutedDeviceId(out int status, out int deviceId) = 29;
    void enableAudioDeviceCallback(boolean enabled, out int status) = 30;
    IBinder getActiveMicrophones() = 31;
    void getPortId(out int status, out int portId) = 32;
    void getRtpDataUsage(out int status, out long bytes) = 33;
    void setPreferredMicrophoneDirection(int direction, out int status) = 34;
    void setPreferredMicrophoneFieldDimension(float zoom, out int status) = 35;
    void setPrivacySensitive(int privacySensitive, out int status) = 36;
    void getPrivacySensitive(out int status, out int privacySensitive) = 37;
}
