// Synthetic AIDL stand-in for android::IGraphicBufferConsumer.
// Source: frameworks/native/libs/gui/IGraphicBufferConsumer.cpp (android14-release)
// (Tag enum and BnGraphicBufferConsumer::onTransact switch arms via SafeInterface)
//
//   ACQUIRE_BUFFER              = IBinder::FIRST_CALL_TRANSACTION  // 1
//   DETACH_BUFFER                                                   // 2
//   ATTACH_BUFFER                                                   // 3
//   RELEASE_BUFFER                                                  // 4
//   CONSUMER_CONNECT                                                // 5
//   CONSUMER_DISCONNECT                                             // 6
//   GET_RELEASED_BUFFERS                                            // 7
//   SET_DEFAULT_BUFFER_SIZE                                         // 8
//   SET_MAX_BUFFER_COUNT                                            // 9
//   SET_MAX_ACQUIRED_BUFFER_COUNT                                   // 10
//   SET_CONSUMER_NAME                                               // 11
//   SET_DEFAULT_BUFFER_FORMAT                                       // 12
//   SET_DEFAULT_BUFFER_DATA_SPACE                                   // 13
//   SET_CONSUMER_USAGE_BITS                                         // 14
//   SET_CONSUMER_IS_PROTECTED                                       // 15
//   SET_TRANSFORM_HINT                                              // 16
//   GET_SIDEBAND_STREAM                                             // 17
//   GET_OCCUPANCY_HISTORY                                           // 18
//   DISCARD_FREE_BUFFERS                                            // 19
//   DUMP_STATE                                                      // 20
//
// Parameter types are placeholders — payload decoding is out of scope.

package android.gui;

interface IGraphicBufferConsumer {
    IBinder acquireBuffer() = 1;
    IBinder detachBuffer() = 2;
    IBinder attachBuffer() = 3;
    IBinder releaseBuffer() = 4;
    IBinder consumerConnect() = 5;
    IBinder consumerDisconnect() = 6;
    IBinder getReleasedBuffers() = 7;
    IBinder setDefaultBufferSize() = 8;
    IBinder setMaxBufferCount() = 9;
    IBinder setMaxAcquiredBufferCount() = 10;
    IBinder setConsumerName() = 11;
    IBinder setDefaultBufferFormat() = 12;
    IBinder setDefaultBufferDataSpace() = 13;
    IBinder setConsumerUsageBits() = 14;
    IBinder setConsumerIsProtected() = 15;
    IBinder setTransformHint() = 16;
    IBinder getSidebandStream() = 17;
    IBinder getOccupancyHistory() = 18;
    IBinder discardFreeBuffers() = 19;
    IBinder dumpState() = 20;
}
