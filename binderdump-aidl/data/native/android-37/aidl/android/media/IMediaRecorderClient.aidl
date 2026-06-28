// Synthetic AIDL stand-in for android::IMediaRecorderClient.
// Source: frameworks/av/media/libmedia/IMediaRecorderClient.cpp (android17-release)
// (enum and BnMediaRecorderClient::onTransact switch arms)
//
//   NOTIFY = IBinder::FIRST_CALL_TRANSACTION  // 1
//
// Note: IMediaRecorderClient.notify has no optional Parcel blob (unlike IMediaPlayerClient.notify).

package android.media;

interface IMediaRecorderClient {
    oneway void notify(int msg, int ext1, int ext2) = 1;
}
