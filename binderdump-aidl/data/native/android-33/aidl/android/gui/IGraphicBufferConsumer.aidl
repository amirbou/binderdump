// Synthetic AIDL stand-in for android::IGraphicBufferConsumer.
// Source: frameworks/native/libs/gui/IGraphicBufferConsumer.cpp (android13-release)
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
// Remaining IBinder stubs: 1 (BufferItem Parcelable), 3 (GraphicBuffer Flattenable),
// 4 (Fence Flattenable), 17 (NativeHandle fds), 18 (Flattenable vector),
// 20 (String8 reply — not expressible as out param).

package android.gui;

interface IGraphicBufferConsumer {
    IBinder acquireBuffer() = 1;
    void detachBuffer(int slot, out int status) = 2;
    IBinder attachBuffer() = 3;
    IBinder releaseBuffer() = 4;
    void consumerConnect(IBinder consumer, boolean controlledByApp, out int status) = 5;
    void consumerDisconnect(out int status) = 6;
    void getReleasedBuffers(out int status, out long slotMask) = 7;
    void setDefaultBufferSize(int width, int height, out int status) = 8;
    void setMaxBufferCount(int bufferCount, out int status) = 9;
    void setMaxAcquiredBufferCount(int maxAcquiredBuffers, out int status) = 10;
    void setConsumerName(in String8 name, out int status) = 11;
    void setDefaultBufferFormat(int defaultFormat, out int status) = 12;
    void setDefaultBufferDataSpace(int defaultDataSpace, out int status) = 13;
    void setConsumerUsageBits(long usage, out int status) = 14;
    void setConsumerIsProtected(boolean isProtected, out int status) = 15;
    void setTransformHint(int hint, out int status) = 16;
    IBinder getSidebandStream() = 17;
    IBinder getOccupancyHistory() = 18;
    void discardFreeBuffers(out int status) = 19;
    IBinder dumpState() = 20;
}
