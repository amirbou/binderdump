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
// Remaining IBinder methods are non-expressible stubs (CString, fd, IMemory shared memory, or CString reply).

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
