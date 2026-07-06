// Synthetic AIDL stand-in for android::IGraphicBufferProducer.
// Source: frameworks/native/libs/gui/IGraphicBufferProducer.cpp (android15-release)
// (Tag enum and BnGraphicBufferProducer::onTransact switch arms via SafeInterface)
//
//   REQUEST_BUFFER              = IBinder::FIRST_CALL_TRANSACTION  // 1
//   DEQUEUE_BUFFER                                                  // 2
//   DETACH_BUFFER                                                   // 3
//   DETACH_NEXT_BUFFER                                              // 4
//   ATTACH_BUFFER                                                   // 5
//   QUEUE_BUFFER                                                    // 6
//   CANCEL_BUFFER                                                   // 7
//   QUERY                                                           // 8
//   CONNECT                                                         // 9
//   DISCONNECT                                                      // 10
//   SET_SIDEBAND_STREAM                                             // 11
//   ALLOCATE_BUFFERS                                                // 12
//   ALLOW_ALLOCATION                                                // 13
//   SET_GENERATION_NUMBER                                           // 14
//   GET_CONSUMER_NAME                                               // 15
//   SET_MAX_DEQUEUED_BUFFER_COUNT                                   // 16
//   SET_ASYNC_MODE                                                  // 17
//   SET_SHARED_BUFFER_MODE                                          // 18
//   SET_AUTO_REFRESH                                                // 19
//   SET_DEQUEUE_TIMEOUT                                             // 20
//   GET_LAST_QUEUED_BUFFER                                          // 21
//   GET_FRAME_TIMESTAMPS                                            // 22
//   GET_UNIQUE_ID                                                   // 23
//   GET_CONSUMER_USAGE                                              // 24
//   SET_LEGACY_BUFFER_DROP                                          // 25
//   SET_AUTO_PREROTATION                                            // 26
//
// Opaque stubs: 1 (GraphicBuffer Flattenable return), 2 (Fence + GraphicBuffer out),
// 3 (detach with Flattenable reply), 4 (GraphicBuffer + Fence out),
// 5 (GraphicBuffer Flattenable param), 6 (QueueBufferInput Flattenable param),
// 7 (Fence Flattenable param), 9 (IProducerListener binder + QueueBufferOutput reply),
// 10 (DisconnectMode enum + int api — kept opaque), 11 (NativeHandle sideband stream),
// 12 (allocates buffers in-place, no typed reply), 15 (String8 reply — not typeable),
// 21 (GraphicBuffer + Fence + float[16] matrix), 22 (FrameEventHistoryDelta Flattenable).

package android.gui;

interface IGraphicBufferProducer {
    IBinder requestBuffer() = 1;
    IBinder dequeueBuffer() = 2;
    IBinder detachBuffer() = 3;
    IBinder detachNextBuffer() = 4;
    IBinder attachBuffer() = 5;
    IBinder queueBuffer() = 6;
    IBinder cancelBuffer() = 7;
    void query(int what, out int value, out int status) = 8;
    IBinder connect() = 9;
    IBinder disconnect() = 10;
    IBinder setSidebandStream() = 11;
    IBinder allocateBuffers() = 12;
    void allowAllocation(boolean allow, out int status) = 13;
    void setGenerationNumber(int generationNumber, out int status) = 14;
    IBinder getConsumerName() = 15;
    void setMaxDequeuedBufferCount(int maxDequeuedBuffers, out int status) = 16;
    void setAsyncMode(boolean async, out int status) = 17;
    void setSharedBufferMode(boolean sharedBufferMode, out int status) = 18;
    void setAutoRefresh(boolean autoRefresh, out int status) = 19;
    void setDequeueTimeout(long timeout, out int status) = 20;
    IBinder getLastQueuedBuffer() = 21;
    IBinder getFrameTimestamps() = 22;
    void getUniqueId(out long id, out int status) = 23;
    void getConsumerUsageBits(out long usage, out int status) = 24;
    void setLegacyBufferDrop(boolean drop, out int status) = 25;
    void setAutoPrerotation(boolean autoPrerotation, out int status) = 26;
}
