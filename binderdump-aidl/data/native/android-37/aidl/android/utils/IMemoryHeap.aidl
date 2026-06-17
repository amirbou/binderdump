// Synthetic AIDL stand-in for the hand-written C++ binder interface
// android::IMemoryHeap. Source enum (in BpMemoryHeap / BnMemoryHeap):
// frameworks/native/libs/binder/IMemory.cpp (android17-release)
//
//   enum { HEAP_ID = IBinder::FIRST_CALL_TRANSACTION };  // = 1
//
// BnMemoryHeap::onTransact case HEAP_ID calls getHeapID().
//
// Parameter types are placeholders — payload decoding is out of scope.

package android.utils;

interface IMemoryHeap {
    IBinder getHeapID() = 1;
}
