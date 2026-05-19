// Synthetic AIDL stand-in for android::IGpuService.
// Source: frameworks/native/libs/graphicsenv/include/graphicsenv/IGpuService.h (android14-release)
// Enum BnGpuService::IGpuServiceTag:
//
//   SET_GPU_STATS                 = IBinder::FIRST_CALL_TRANSACTION  // 1
//   SET_TARGET_STATS                                                  // 2
//   SET_UPDATABLE_DRIVER_PATH                                         // 3
//   GET_UPDATABLE_DRIVER_PATH                                         // 4
//   TOGGLE_ANGLE_AS_SYSTEM_DRIVER                                     // 5
//
// SET_TARGET_STATS_ARRAY (6) and ADD_VULKAN_ENGINE_NAME (7) were added after
// android14-release.
//
// Parameter types are placeholders — payload decoding is out of scope.

package android.graphicsenv;

interface IGpuService {
    IBinder setGpuStats() = 1;
    IBinder setTargetStats() = 2;
    IBinder setUpdatableDriverPath() = 3;
    IBinder getUpdatableDriverPath() = 4;
    IBinder toggleAngleAsSystemDriver() = 5;
}
