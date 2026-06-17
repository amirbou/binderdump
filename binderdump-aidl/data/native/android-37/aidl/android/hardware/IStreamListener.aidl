// Synthetic AIDL stand-in for android::IStreamListener.
// Source: frameworks/av/media/libmedia/IStreamSource.cpp (android17-release)
// (IStreamListener is defined alongside IStreamSource in the same .cpp;
//  BnStreamListener::onTransact switch arms are in that file)
//
// The shared enum places IStreamListener entries after IStreamSource's four:
//   SET_LISTENER       = IBinder::FIRST_CALL_TRANSACTION  // 1
//   SET_BUFFERS                                           // 2
//   ON_BUFFER_AVAILABLE                                   // 3
//   FLAGS                                                 // 4
//   QUEUE_BUFFER                                          // 5
//   ISSUE_COMMAND                                         // 6
//
// BnStreamListener::onTransact dispatches on these shared integer values (5 and 6)
// because the enum is defined once for both interfaces in the same TU.
// queueBuffer is therefore code 5 and issueCommand is code 6 on the wire.
//
// Parameter types are placeholders — payload decoding is out of scope.

package android.hardware;

interface IStreamListener {
    IBinder queueBuffer() = 5;
    IBinder issueCommand() = 6;
}
