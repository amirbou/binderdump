// Synthetic AIDL stand-in for android::IMediaExtractor.
// Source: frameworks/av/media/libmedia/IMediaExtractor.cpp (android17-release)
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
// Remaining IBinder stubs are non-expressible in AIDL:
//   GETTRACK: returns IMediaSource binder (typed interface, not generic IBinder)
//   GETTRACKMETADATA: reply is MetaData custom parcelable
//   GETMETADATA: reply is MetaData custom parcelable
//   SETMEDIACAS: writeByteVector (HInterfaceToken, CAS-specific byte vector)
//   NAME: reply is readString8 (UTF-8 reply, not expressible)
//   GETMETRICS: passes reply Parcel directly (raw AMediaFormat encoding)

package android.media;

interface IMediaExtractor {
    void countTracks(out int count) = 1;
    IBinder getTrack() = 2;
    IBinder getTrackMetaData() = 3;
    IBinder getMetaData() = 4;
    void flags(out int flags) = 5;
    IBinder setMediaCas() = 6;
    IBinder name() = 7;
    IBinder getMetrics() = 8;
    void setEntryPoint(int entryPoint) = 9;
    void setLogSessionId(in String8 sessionId) = 10;
}
