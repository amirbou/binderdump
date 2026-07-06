// Synthetic AIDL stand-in for the manual-Binder interface
// android.content.IBulkCursor (legacy database cursor). Source:
// frameworks/base/core/java/android/database/IBulkCursor.java
// (android15-release) — transaction constants (FIRST_CALL_TRANSACTION + N).
// Params are opaque.
//
//   getWindow=1 deactivate=2 requery=3 onMove=4 getExtras=5 respond=6 close=7

package android.content;

interface IBulkCursor {
    void getWindow() = 1;
    void deactivate() = 2;
    void requery() = 3;
    void onMove() = 4;
    void getExtras() = 5;
    void respond() = 6;
    void close() = 7;
}
