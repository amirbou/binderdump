// Synthetic AIDL stand-in for android::IMediaPlayer.
// Source: frameworks/av/media/libmedia/include/media/IMediaPlayer.h (android13-release)
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
//   GET_ROUTED_DEVICE_ID                                       // 42
//   ENABLE_AUDIO_DEVICE_CALLBACK                               // 43
//
// setDataSource is overloaded at multiple codes (url/fd/stream/callback/rtp).
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
    IBinder setParameter() = 32;
    IBinder getParameter() = 33;
    IBinder setRetransmitEndpoint() = 34;
    IBinder getRetransmitEndpoint() = 35;
    IBinder setNextPlayer() = 36;
    IBinder applyVolumeShaper() = 37;
    IBinder getVolumeShaperState() = 38;
    IBinder prepareDrm() = 39;
    IBinder releaseDrm() = 40;
    IBinder setOutputDevice() = 41;
    IBinder getRoutedDeviceId() = 42;
    IBinder enableAudioDeviceCallback() = 43;
}
