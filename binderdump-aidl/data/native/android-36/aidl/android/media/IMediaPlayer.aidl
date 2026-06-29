// Synthetic AIDL stand-in for android::IMediaPlayer.
// Source: frameworks/av/media/libmedia/include/media/IMediaPlayer.h (android16-release)
// (enum is defined in the protected section of the header; BnMediaPlayer::onTransact
//  switch arms are in media/libmedia/IMediaPlayer.cpp confirming each method name)
//
//   DISCONNECT              = IBinder::FIRST_CALL_TRANSACTION  // 1
//   SET_DATA_SOURCE_URL                                        // 2
//   SET_DATA_SOURCE_FD                                         // 3
//   SET_DATA_SOURCE_STREAM                                     // 4
//   SET_DATA_SOURCE_CALLBACK                                   // 5
//   SET_DATA_SOURCE_RTP                                        // 6
//   SET_BUFFERING_SETTINGS                                     // 7
//   GET_BUFFERING_SETTINGS                                     // 8
//   PREPARE_ASYNC                                              // 9
//   START                                                      // 10
//   STOP                                                       // 11
//   IS_PLAYING                                                 // 12
//   SET_PLAYBACK_SETTINGS                                      // 13
//   GET_PLAYBACK_SETTINGS                                      // 14
//   SET_SYNC_SETTINGS                                          // 15
//   GET_SYNC_SETTINGS                                          // 16
//   PAUSE                                                      // 17
//   SEEK_TO                                                    // 18
//   GET_CURRENT_POSITION                                       // 19
//   GET_DURATION                                               // 20
//   RESET                                                      // 21
//   NOTIFY_AT                                                  // 22
//   SET_AUDIO_STREAM_TYPE                                      // 23
//   SET_LOOPING                                                // 24
//   SET_VOLUME                                                 // 25
//   INVOKE                                                     // 26
//   SET_METADATA_FILTER                                        // 27
//   GET_METADATA                                               // 28
//   SET_AUX_EFFECT_SEND_LEVEL                                  // 29
//   ATTACH_AUX_EFFECT                                          // 30
//   SET_VIDEO_SURFACETEXTURE                                   // 31
//   SET_PARAMETER                                              // 32
//   GET_PARAMETER                                              // 33
//   SET_RETRANSMIT_ENDPOINT                                    // 34
//   GET_RETRANSMIT_ENDPOINT                                    // 35
//   SET_NEXT_PLAYER                                            // 36
//   APPLY_VOLUME_SHAPER                                        // 37
//   GET_VOLUME_SHAPER_STATE                                    // 38
//   PREPARE_DRM                                                // 39
//   RELEASE_DRM                                                // 40
//   SET_OUTPUT_DEVICE                                          // 41
//   GET_ROUTED_DEVICE_IDS                                      // 42
//   ENABLE_AUDIO_DEVICE_CALLBACK                               // 43
//
// setDataSource is overloaded at multiple codes (url/fd/stream/callback/rtp).
// Remaining IBinder methods are non-expressible stubs (raw Parcel, fd, Parcelable, or array reply).
// code 42: renamed GET_ROUTED_DEVICE_IDS (android16); reply now writes int32 count + count*int32 — STUB (array).

package android.media;

interface IMediaPlayer {
    void disconnect() = 1;
    IBinder setDataSourceUrl() = 2;
    IBinder setDataSourceFd() = 3;
    void setDataSourceStream(in IBinder source, out int status) = 4;
    void setDataSourceCallback(in IBinder source, out int status) = 5;
    IBinder setDataSourceRtp() = 6;
    void setBufferingSettings(int initialMarkMs, int resumePlaybackMarkMs, out int status) = 7;
    void getBufferingSettings(out int status, out int initialMarkMs, out int resumePlaybackMarkMs) = 8;
    void prepareAsync(out int status) = 9;
    void start(out int status) = 10;
    void stop(out int status) = 11;
    void isPlaying(out int state, out int status) = 12;
    void setPlaybackSettings(float speed, float pitch, int fallbackMode, int stretchMode, out int status) = 13;
    void getPlaybackSettings(out int status, out float speed, out float pitch, out int fallbackMode, out int stretchMode) = 14;
    void setSyncSettings(int source, int audioAdjustMode, float tolerance, float videoFpsHint, out int status) = 15;
    void getSyncSettings(out int status, out int source, out int audioAdjustMode, out float tolerance, out float videoFps) = 16;
    void pause(out int status) = 17;
    void seekTo(int msec, int mode, out int status) = 18;
    void getCurrentPosition(out int msec, out int status) = 19;
    void getDuration(out int msec, out int status) = 20;
    void reset(out int status) = 21;
    void notifyAt(long mediaTimeUs, out int status) = 22;
    void setAudioStreamType(int stream, out int status) = 23;
    void setLooping(int loop, out int status) = 24;
    void setVolume(float leftVolume, float rightVolume, out int status) = 25;
    IBinder invoke() = 26;
    IBinder setMetadataFilter() = 27;
    IBinder getMetadata() = 28;
    void setAuxEffectSendLevel(float level, out int status) = 29;
    void attachAuxEffect(int effectId, out int status) = 30;
    void setVideoSurfaceTexture(in IBinder bufferProducer, out int status) = 31;
    IBinder setParameter() = 32;
    IBinder getParameter() = 33;
    IBinder setRetransmitEndpoint() = 34;
    IBinder getRetransmitEndpoint() = 35;
    void setNextPlayer(in IBinder player, out int status) = 36;
    IBinder applyVolumeShaper() = 37;
    IBinder getVolumeShaperState() = 38;
    IBinder prepareDrm() = 39;
    void releaseDrm(out int status) = 40;
    void setOutputDevice(int deviceId, out int status) = 41;
    IBinder getRoutedDeviceIds() = 42;
    void enableAudioDeviceCallback(boolean enabled, out int status) = 43;
}
