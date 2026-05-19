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
// Parameter types are placeholders — payload decoding is out of scope.

package android.media;

interface IMediaRecorder {
    IBinder release() = 1;
    IBinder init() = 2;
    IBinder close() = 3;
    IBinder setInputSurface() = 4;
    IBinder querySurfaceMediaSource() = 5;
    IBinder reset() = 6;
    IBinder stop() = 7;
    IBinder start() = 8;
    IBinder prepare() = 9;
    IBinder getMaxAmplitude() = 10;
    IBinder setVideoSource() = 11;
    IBinder setAudioSource() = 12;
    IBinder setOutputFormat() = 13;
    IBinder setVideoEncoder() = 14;
    IBinder setAudioEncoder() = 15;
    IBinder setOutputFileFd() = 16;
    IBinder setNextOutputFileFd() = 17;
    IBinder setVideoSize() = 18;
    IBinder setVideoFrameRate() = 19;
    IBinder setParameters() = 20;
    IBinder setPreviewSurface() = 21;
    IBinder setCamera() = 22;
    IBinder setListener() = 23;
    IBinder setClientName() = 24;
    IBinder pause() = 25;
    IBinder resume() = 26;
    IBinder getMetrics() = 27;
    IBinder setInputDevice() = 28;
    IBinder getRoutedDeviceId() = 29;
    IBinder enableAudioDeviceCallback() = 30;
    IBinder getActiveMicrophones() = 31;
    IBinder getPortId() = 32;
    IBinder getRtpDataUsage() = 33;
    IBinder setPreferredMicrophoneDirection() = 34;
    IBinder setPreferredMicrophoneFieldDimension() = 35;
    IBinder setPrivacySensitive() = 36;
    IBinder getPrivacySensitive() = 37;
}
