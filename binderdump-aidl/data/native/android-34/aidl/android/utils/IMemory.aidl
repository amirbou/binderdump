// Synthetic AIDL stand-in for the hand-written C++ binder interface
// android::IMemory. Source enum (in BpMemory / BnMemory):
// frameworks/native/libs/binder/IMemory.cpp (android14-release)
//
//   enum { GET_MEMORY = IBinder::FIRST_CALL_TRANSACTION };  // = 1
//
// BnMemory::onTransact case GET_MEMORY calls getMemory().
//
// Parameter types are placeholders — payload decoding is out of scope.

package android.utils;

interface IMemory {
    IBinder getMemory() = 1;
}
