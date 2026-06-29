// Synthetic AIDL stand-in for android::IMediaPlayerService.
// Source: frameworks/av/media/libmedia/IMediaPlayerService.cpp (android15-release)
// (enum and BnMediaPlayerService::onTransact switch arms)
//
//   CREATE                    = IBinder::FIRST_CALL_TRANSACTION  // 1
//   CREATE_MEDIA_RECORDER                                        // 2
//   CREATE_METADATA_RETRIEVER                                    // 3
//   ADD_BATTERY_DATA                                             // 4
//   PULL_BATTERY_DATA                                            // 5
//   LISTEN_FOR_REMOTE_DISPLAY                                    // 6
//   GET_CODEC_LIST                                               // 7
//
// Remaining IBinder methods are non-expressible stubs (AttributionSourceState Parcelable, raw Parcel, or String8).

package android.media;

interface IMediaPlayerService {
    IBinder create() = 1;
    IBinder createMediaRecorder() = 2;
    void createMetadataRetriever(out IBinder retriever) = 3;
    void addBatteryData(int params) = 4;
    IBinder pullBatteryData() = 5;
    IBinder listenForRemoteDisplay() = 6;
    void getCodecList(out IBinder codecList) = 7;
}
