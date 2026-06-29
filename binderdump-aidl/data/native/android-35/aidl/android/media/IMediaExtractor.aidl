// Synthetic AIDL stand-in for android::IMediaExtractor.
// Source: frameworks/av/media/libmedia/IMediaExtractor.cpp (android15-release)
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
//   NAME: readString8 (UTF-8, not String16)
//   GETMETRICS: passes reply Parcel directly (raw AMediaFormat encoding)
//   SETLOGSESSIONID: writeString8 (UTF-8, not String16)

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
    IBinder setLogSessionId() = 10;
}
