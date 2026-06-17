// Synthetic AIDL stand-in for android::IGpuService.
// Source: frameworks/native/libs/graphicsenv/include/graphicsenv/IGpuService.h (android17-release)
// Enum BnGpuService::IGpuServiceTag:
//
//   SET_GPU_STATS                 = IBinder::FIRST_CALL_TRANSACTION  // 1
//   SET_TARGET_STATS                                                  // 2
//   SET_UPDATABLE_DRIVER_PATH                                         // 3
//   GET_UPDATABLE_DRIVER_PATH                                         // 4
//   TOGGLE_ANGLE_AS_SYSTEM_DRIVER                                     // 5
//   SET_TARGET_STATS_ARRAY                                            // 6
//   ADD_VULKAN_ENGINE_NAME                                            // 7
//   GET_FEATURE_CONFIG_OVERRIDES                                      // 8
//   GET_PERSIST_GRAPHICS_EGL                                          // 9
//
// Parameter types are placeholders — payload decoding is out of scope.

package android.graphicsenv;

interface IGpuService {
    IBinder setGpuStats() = 1;
    IBinder setTargetStats() = 2;
    IBinder setUpdatableDriverPath() = 3;
    IBinder getUpdatableDriverPath() = 4;
    IBinder toggleAngleAsSystemDriver() = 5;
    IBinder setTargetStatsArray() = 6;
    IBinder addVulkanEngineName() = 7;
    IBinder getFeatureConfigOverrides() = 8;
    IBinder getPersistGraphicsEgl() = 9;
}
