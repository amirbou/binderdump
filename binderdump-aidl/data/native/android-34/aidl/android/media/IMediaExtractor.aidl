// Synthetic AIDL stand-in for android::IMediaExtractor.
// Source: frameworks/av/media/libmedia/IMediaExtractor.cpp (android14-release)
// (enum and BnMediaExtractor::onTransact switch arms)
//
//   COUNTTRACKS     = IBinder::FIRST_CALL_TRANSACTION  // 1
//   GETTRACK                                           // 2
//   GETTRACKMETADATA                                   // 3
//   GETMETADATA                                        // 4
//   FLAGS                                              // 5
//   SETMEDIACAS                                        // 6
//   NAME                                               // 7
//   GETMETRICS                                         // 8
//   SETENTRYPOINT                                      // 9
//   SETLOGSESSIONID                                    // 10
//
// Parameter types are placeholders — payload decoding is out of scope.

package android.media;

interface IMediaExtractor {
    IBinder countTracks() = 1;
    IBinder getTrack() = 2;
    IBinder getTrackMetaData() = 3;
    IBinder getMetaData() = 4;
    IBinder flags() = 5;
    IBinder setMediaCas() = 6;
    IBinder name() = 7;
    IBinder getMetrics() = 8;
    IBinder setEntryPoint() = 9;
    IBinder setLogSessionId() = 10;
}
