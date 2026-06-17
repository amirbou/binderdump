// Synthetic AIDL stand-in for android::IMediaPlayer.
// Source: frameworks/av/media/libmedia/include/media/IMediaPlayer.h (android17-release)
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
//   SET_VIDEO_SURFACETEXTURE_V2                                // 32
//   SET_PARAMETER                                              // 33
//   GET_PARAMETER                                              // 34
//   SET_RETRANSMIT_ENDPOINT                                    // 35
//   GET_RETRANSMIT_ENDPOINT                                    // 36
//   SET_NEXT_PLAYER                                            // 37
//   APPLY_VOLUME_SHAPER                                        // 38
//   GET_VOLUME_SHAPER_STATE                                    // 39
//   PREPARE_DRM                                                // 40
//   RELEASE_DRM                                                // 41
//   SET_OUTPUT_DEVICE                                          // 42
//   GET_ROUTED_DEVICE_IDS                                      // 43
//   ENABLE_AUDIO_DEVICE_CALLBACK                               // 44
//
// setDataSource is overloaded at multiple codes (url/fd/stream/callback/rtp).
// setVideoSurfaceTexture is overloaded at codes 31 and 32 (legacy / v2).
// Parameter types are placeholders — payload decoding is out of scope.

package android.media;

interface IMediaPlayer {
    IBinder disconnect() = 1;
    IBinder setDataSourceUrl() = 2;
    IBinder setDataSourceFd() = 3;
    IBinder setDataSourceStream() = 4;
    IBinder setDataSourceCallback() = 5;
    IBinder setDataSourceRtp() = 6;
    IBinder setBufferingSettings() = 7;
    IBinder getBufferingSettings() = 8;
    IBinder prepareAsync() = 9;
    IBinder start() = 10;
    IBinder stop() = 11;
    IBinder isPlaying() = 12;
    IBinder setPlaybackSettings() = 13;
    IBinder getPlaybackSettings() = 14;
    IBinder setSyncSettings() = 15;
    IBinder getSyncSettings() = 16;
    IBinder pause() = 17;
    IBinder seekTo() = 18;
    IBinder getCurrentPosition() = 19;
    IBinder getDuration() = 20;
    IBinder reset() = 21;
    IBinder notifyAt() = 22;
    IBinder setAudioStreamType() = 23;
    IBinder setLooping() = 24;
    IBinder setVolume() = 25;
    IBinder invoke() = 26;
    IBinder setMetadataFilter() = 27;
    IBinder getMetadata() = 28;
    IBinder setAuxEffectSendLevel() = 29;
    IBinder attachAuxEffect() = 30;
    IBinder setVideoSurfaceTexture() = 31;
    IBinder setVideoSurfaceTextureV2() = 32;
    IBinder setParameter() = 33;
    IBinder getParameter() = 34;
    IBinder setRetransmitEndpoint() = 35;
    IBinder getRetransmitEndpoint() = 36;
    IBinder setNextPlayer() = 37;
    IBinder applyVolumeShaper() = 38;
    IBinder getVolumeShaperState() = 39;
    IBinder prepareDrm() = 40;
    IBinder releaseDrm() = 41;
    IBinder setOutputDevice() = 42;
    IBinder getRoutedDeviceIds() = 43;
    IBinder enableAudioDeviceCallback() = 44;
}
