// Synthetic AIDL stand-in for the manual-Binder interface
// android.content.IContentProvider. Source: frameworks/base/core/java/
// android/content/IContentProvider.java (android15-release) — the
// *_TRANSACTION constants (IBinder.FIRST_CALL_TRANSACTION + N). Codes are
// non-contiguous: the gaps are retired methods and are preserved verbatim.
// Params are opaque (Uri/Bundle/ContentValues etc. are not modeled here).

package android.content;

interface IContentProvider {
    void query() = 1;
    void getType() = 2;
    void insert() = 3;
    void delete() = 4;
    void update() = 10;
    void bulkInsert() = 13;
    void openFile() = 14;
    void openAssetFile() = 15;
    void applyBatch() = 20;
    void call() = 21;
    void getStreamTypes() = 22;
    void openTypedAssetFile() = 23;
    void createCancelationSignal() = 24;
    void canonicalize() = 25;
    void uncanonicalize() = 26;
    void refresh() = 27;
    void checkUriPermission() = 28;
    void getTypeAsync() = 29;
    void canonicalizeAsync() = 30;
    void uncanonicalizeAsync() = 31;
    void getTypeAnonymousAsync() = 32;
}
