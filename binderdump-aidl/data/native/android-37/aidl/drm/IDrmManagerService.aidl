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
// Parameter types are placeholders — payload decoding is out of scope.

package drm;

interface IDrmManagerService {
    IBinder addUniqueId() = 1;
    IBinder removeUniqueId() = 2;
    IBinder addClient() = 3;
    IBinder removeClient() = 4;
    IBinder setDrmServiceListener() = 5;
    IBinder installDrmEngine() = 6;
    IBinder getConstraintsFromContent() = 7;
    IBinder getMetadataFromContent() = 8;
    IBinder canHandle() = 9;
    IBinder processDrmInfo() = 10;
    IBinder acquireDrmInfo() = 11;
    IBinder saveRights() = 12;
    IBinder getOriginalMimetype() = 13;
    IBinder getDrmObjectType() = 14;
    IBinder checkRightsStatus() = 15;
    IBinder consumeRights() = 16;
    IBinder setPlaybackStatus() = 17;
    IBinder validateAction() = 18;
    IBinder removeRights() = 19;
    IBinder removeAllRights() = 20;
    IBinder openConvertSession() = 21;
    IBinder convertData() = 22;
    IBinder closeConvertSession() = 23;
    IBinder getAllSupportInfo() = 24;
    IBinder openDecryptSession() = 25;
    IBinder openDecryptSessionFromUri() = 26;
    IBinder openDecryptSessionForStreaming() = 27;
    IBinder closeDecryptSession() = 28;
    IBinder initializeDecryptUnit() = 29;
    IBinder decrypt() = 30;
    IBinder finalizeDecryptUnit() = 31;
    IBinder pread() = 32;
}
