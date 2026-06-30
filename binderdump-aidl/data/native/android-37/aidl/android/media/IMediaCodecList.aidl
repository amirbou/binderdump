// Synthetic AIDL stand-in for android::IMediaCodecList.
// Source: frameworks/av/media/libmedia/IMediaCodecList.cpp (android17-release)
// (enum and BnMediaCodecList::onTransact switch arms)
//
//   CREATE             = IBinder::FIRST_CALL_TRANSACTION  // 1
//   COUNT_CODECS                                          // 2
//   GET_CODEC_INFO                                        // 3
//   GET_GLOBAL_SETTINGS                                   // 4
//   FIND_CODEC_BY_TYPE                                    // 5
//   FIND_CODEC_BY_NAME                                    // 6
//
// Remaining IBinder stubs are non-expressible in AIDL:
//   CREATE: enum placeholder only, no Bp/Bn implementation found in source
//   GET_CODEC_INFO: reply includes MediaCodecInfo custom parcelable
//   GET_GLOBAL_SETTINGS: reply includes AMessage custom parcelable

package android.media;

interface IMediaCodecList {
    IBinder create() = 1;
    void countCodecs(out int count) = 2;
    IBinder getCodecInfo() = 3;
    IBinder getGlobalSettings() = 4;
    void findCodecByType(in CString type, int encoder, int startIndex, out int result) = 5;
    void findCodecByName(in CString name, out int result) = 6;
}
