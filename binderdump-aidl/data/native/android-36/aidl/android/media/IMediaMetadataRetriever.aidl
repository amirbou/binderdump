// Synthetic AIDL stand-in for android::IMediaMetadataRetriever.
// Source: frameworks/av/media/libmedia/IMediaMetadataRetriever.cpp (android16-release)
// (enum and BnMediaMetadataRetriever::onTransact switch arms)
//
//   DISCONNECT              = IBinder::FIRST_CALL_TRANSACTION  // 1
//   SET_DATA_SOURCE_URL                                        // 2
//   SET_DATA_SOURCE_FD                                         // 3
//   SET_DATA_SOURCE_CALLBACK                                   // 4
//   GET_FRAME_AT_TIME                                          // 5
//   GET_IMAGE_AT_INDEX                                         // 6
//   GET_IMAGE_RECT_AT_INDEX                                    // 7
//   GET_FRAME_AT_INDEX                                         // 8
//   EXTRACT_ALBUM_ART                                          // 9
//   EXTRACT_METADATA                                           // 10
//
// Remaining IBinder stubs are non-expressible in AIDL:
//   SET_DATA_SOURCE_URL: CString url + variable-length String8 headers map
//   SET_DATA_SOURCE_FD: fd param
//   SET_DATA_SOURCE_CALLBACK: conditional CString mime (int32 flag + CString when non-null)
//   GET_FRAME_AT_TIME..EXTRACT_ALBUM_ART: reply is IMemory binder (shared memory)
//   EXTRACT_METADATA: reply is readCString (UTF-8 reply, not expressible)

package android.media;

interface IMediaMetadataRetriever {
    void disconnect() = 1;
    IBinder setDataSourceUrl() = 2;
    IBinder setDataSourceFd() = 3;
    IBinder setDataSourceCallback() = 4;
    IBinder getFrameAtTime() = 5;
    IBinder getImageAtIndex() = 6;
    IBinder getImageRectAtIndex() = 7;
    IBinder getFrameAtIndex() = 8;
    IBinder extractAlbumArt() = 9;
    IBinder extractMetadata() = 10;
}
