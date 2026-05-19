// Synthetic AIDL stand-in for com.android.car.procfsinspector.IProcfsInspector.
// Source: packages/services/Car/procfs-inspector/client/src/com/android/car/procfsinspector/IProcfsInspector.aidl
//         (android14-release) — this is the actual upstream AIDL, not a C++ enum.
// Interface is @deprecated (superseded by CarWatchdogService).
//
//   readProcessTable  = IBinder::FIRST_CALL_TRANSACTION  // 1
//
// Parameter types are placeholders — payload decoding is out of scope.

package com.android.car.procfsinspector;

interface IProcfsInspector {
    IBinder readProcessTable() = 1;
}
