// Synthetic AIDL stand-in for android::IMediaPlayerService.
// Source: frameworks/av/media/libmedia/IMediaPlayerService.cpp (android13-release)
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
// Remaining non-expressible stubs:
//   PULL_BATTERY_DATA: raw Parcel* reply passed directly (unstructured metrics) — not expressible

package android.media;

interface IMediaPlayerService {
    IBinder create(in android.content.AttributionSourceState attributionSource) = 1;
    IBinder createMediaRecorder(in android.content.AttributionSourceState attributionSource) = 2;
    void createMetadataRetriever(out IBinder retriever) = 3;
    void addBatteryData(int params) = 4;
    IBinder pullBatteryData() = 5;
    void listenForRemoteDisplay(in String opPackageName, in IBinder client, in String8 iface, out IBinder display) = 6;
    void getCodecList(out IBinder codecList) = 7;
}
