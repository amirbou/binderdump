// Synthetic AIDL stand-in for android::IDrmManagerService.
// Source: frameworks/av/drm/common/include/IDrmManagerService.h (android17-release)
// Enum in IDrmManagerService class body:
//
//   ADD_UNIQUEID              = IBinder::FIRST_CALL_TRANSACTION  // 1
//   REMOVE_UNIQUEID                                              // 2
//   ADD_CLIENT                                                   // 3
//   REMOVE_CLIENT                                                // 4
//   SET_DRM_SERVICE_LISTENER                                     // 5
//   INSTALL_DRM_ENGINE                                           // 6
//   GET_CONSTRAINTS_FROM_CONTENT                                 // 7
//   GET_METADATA_FROM_CONTENT                                    // 8
//   CAN_HANDLE                                                   // 9
//   PROCESS_DRM_INFO                                             // 10
//   ACQUIRE_DRM_INFO                                             // 11
//   SAVE_RIGHTS                                                  // 12
//   GET_ORIGINAL_MIMETYPE                                        // 13
//   GET_DRM_OBJECT_TYPE                                          // 14
//   CHECK_RIGHTS_STATUS                                          // 15
//   CONSUME_RIGHTS                                               // 16
//   SET_PLAYBACK_STATUS                                          // 17
//   VALIDATE_ACTION                                              // 18
//   REMOVE_RIGHTS                                                // 19
//   REMOVE_ALL_RIGHTS                                            // 20
//   OPEN_CONVERT_SESSION                                         // 21
//   CONVERT_DATA                                                 // 22
//   CLOSE_CONVERT_SESSION                                        // 23
//   GET_ALL_SUPPORT_INFO                                         // 24
//   OPEN_DECRYPT_SESSION                                         // 25
//   OPEN_DECRYPT_SESSION_FROM_URI                                // 26
//   OPEN_DECRYPT_SESSION_FOR_STREAMING                           // 27
//   CLOSE_DECRYPT_SESSION                                        // 28
//   INITIALIZE_DECRYPT_UNIT                                      // 29
//   DECRYPT                                                      // 30
//   FINALIZE_DECRYPT_UNIT                                        // 31
//   PREAD                                                        // 32
//
// Remaining IBinder stubs are non-expressible in AIDL:
//   INSTALL_DRM_ENGINE (6): no BpDrmManagerService implementation found
//   GET_CONSTRAINTS_FROM_CONTENT (7): DrmConstraints reply (custom Parcelable)
//   GET_METADATA_FROM_CONTENT (8): DrmMetadata reply (custom Parcelable)
//   PROCESS_DRM_INFO (10): DrmInfo input + DrmInfoStatus reply (custom types)
//   ACQUIRE_DRM_INFO (11): DrmInfoRequest input + DrmInfo reply (custom types)
//   SAVE_RIGHTS (12): DrmRights input (custom Parcelable with blob)
//   GET_ORIGINAL_MIMETYPE (13): fd param
//   CONSUME_RIGHTS (16): DecryptHandle input (custom Parcelable)
//   SET_PLAYBACK_STATUS (17): DecryptHandle input (custom Parcelable)
//   CONVERT_DATA (22): DrmBuffer input (custom type)
//   GET_ALL_SUPPORT_INFO (24): vector<DrmSupportInfo> reply (non-expressible)
//   OPEN_DECRYPT_SESSION (25): fd param
//   OPEN_DECRYPT_SESSION_FROM_URI (26): DecryptHandle reply (custom Parcelable)
//   OPEN_DECRYPT_SESSION_FOR_STREAMING (27): DrmBuffer input + DecryptHandle reply
//   CLOSE_DECRYPT_SESSION (28): DecryptHandle input
//   INITIALIZE_DECRYPT_UNIT (29): DecryptHandle + DrmBuffer inputs
//   DECRYPT (30): DecryptHandle + DrmBuffer inputs
//   FINALIZE_DECRYPT_UNIT (31): DecryptHandle input
//   PREAD (32): DecryptHandle input

package drm;

interface IDrmManagerService {
    void addUniqueId(int isNative, out int uniqueId) = 1;
    void removeUniqueId(int uniqueId) = 2;
    void addClient(int uniqueId) = 3;
    void removeClient(int uniqueId) = 4;
    void setDrmServiceListener(int uniqueId, IBinder listener) = 5;
    IBinder installDrmEngine() = 6;
    IBinder getConstraintsFromContent() = 7;
    IBinder getMetadataFromContent() = 8;
    void canHandle(int uniqueId, in String8 path, in String8 mimeType, out int result) = 9;
    IBinder processDrmInfo() = 10;
    IBinder acquireDrmInfo() = 11;
    IBinder saveRights() = 12;
    IBinder getOriginalMimetype() = 13;
    void getDrmObjectType(int uniqueId, in String8 path, in String8 mimeType, out int objectType) = 14;
    void checkRightsStatus(int uniqueId, in String8 path, int action, out int result) = 15;
    IBinder consumeRights() = 16;
    IBinder setPlaybackStatus() = 17;
    void validateAction(int uniqueId, in String8 path, int action, int outputType, int configuration, out int result) = 18;
    void removeRights(int uniqueId, in String8 path, out int status) = 19;
    void removeAllRights(int uniqueId, out int status) = 20;
    void openConvertSession(int uniqueId, in String8 mimeType, out int convertId) = 21;
    IBinder convertData() = 22;
    void closeConvertSession(int uniqueId, int convertId) = 23;
    void getAllSupportInfo(int uniqueId) = 24;
    IBinder openDecryptSession() = 25;
    IBinder openDecryptSessionFromUri() = 26;
    IBinder openDecryptSessionForStreaming() = 27;
    IBinder closeDecryptSession() = 28;
    IBinder initializeDecryptUnit() = 29;
    IBinder decrypt() = 30;
    IBinder finalizeDecryptUnit() = 31;
    IBinder pread() = 32;
}
