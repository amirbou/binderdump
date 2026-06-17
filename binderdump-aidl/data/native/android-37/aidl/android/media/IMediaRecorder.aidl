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
// Parameter types are placeholders — payload decoding is out of scope.

package android.media;

interface IMediaRecorder {
    IBinder release() = 1;
    IBinder init() = 2;
    IBinder close() = 3;
    IBinder setInputSurface() = 4;
    IBinder querySurfaceMediaSource() = 5;
    IBinder querySurfaceMediaSourceV2() = 6;
    IBinder reset() = 7;
    IBinder stop() = 8;
    IBinder start() = 9;
    IBinder prepare() = 10;
    IBinder getMaxAmplitude() = 11;
    IBinder setVideoSource() = 12;
    IBinder setAudioSource() = 13;
    IBinder setOutputFormat() = 14;
    IBinder setVideoEncoder() = 15;
    IBinder setAudioEncoder() = 16;
    IBinder setOutputFileFd() = 17;
    IBinder setNextOutputFileFd() = 18;
    IBinder setVideoSize() = 19;
    IBinder setVideoFrameRate() = 20;
    IBinder setParameters() = 21;
    IBinder setPreviewSurface() = 22;
    IBinder setPreviewSurfaceV2() = 23;
    IBinder setCamera() = 24;
    IBinder setListener() = 25;
    IBinder setClientName() = 26;
    IBinder pause() = 27;
    IBinder resume() = 28;
    IBinder getMetrics() = 29;
    IBinder setInputDevice() = 30;
    IBinder getRoutedDeviceIds() = 31;
    IBinder enableAudioDeviceCallback() = 32;
    IBinder getActiveMicrophones() = 33;
    IBinder getPortId() = 34;
    IBinder getRtpDataUsage() = 35;
    IBinder setPreferredMicrophoneDirection() = 36;
    IBinder setPreferredMicrophoneFieldDimension() = 37;
    IBinder setPrivacySensitive() = 38;
    IBinder getPrivacySensitive() = 39;
}
