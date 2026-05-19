// Synthetic AIDL stand-in for android::IMediaCodecList.
// Source: frameworks/av/media/libmedia/IMediaCodecList.cpp (android13-release)
// (enum and BnMediaCodecList::onTransact switch arms)
//
//   CREATE             = IBinder::FIRST_CALL_TRANSACTION  // 1
//   COUNT_CODECS                                          // 2
//   GET_CODEC_INFO                                        // 3
//   GET_GLOBAL_SETTINGS                                   // 4
//   FIND_CODEC_BY_TYPE                                    // 5
//   FIND_CODEC_BY_NAME                                    // 6
//
// Parameter types are placeholders — payload decoding is out of scope.

package android.media;

interface IMediaCodecList {
    IBinder create() = 1;
    IBinder countCodecs() = 2;
    IBinder getCodecInfo() = 3;
    IBinder getGlobalSettings() = 4;
    IBinder findCodecByType() = 5;
    IBinder findCodecByName() = 6;
}
