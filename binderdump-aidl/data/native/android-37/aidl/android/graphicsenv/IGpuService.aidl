// Synthetic AIDL stand-in for android::IGpuService.
// Source: frameworks/native/libs/graphicsenv/IGpuService.cpp + include/graphicsenv/IGpuService.h (android17-release)
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
// Codes 1-5 carry source-verified types. Codes 6-9 stay typeless IBinder stubs:
// SET_TARGET_STATS_ARRAY (raw Parcel::write() buffer), ADD_VULKAN_ENGINE_NAME
// (writeCString, no length prefix), GET_FEATURE_CONFIG_OVERRIDES and
// GET_PERSIST_GRAPHICS_EGL (custom returns) aren't AIDL-expressible — the
// decoder shows the method name only.

package android.graphicsenv;

interface IGpuService {
    oneway void setGpuStats(in String driverPackageName, in String driverVersionName, long driverVersionCode, long driverBuildTime, in String appPackageName, int vulkanVersion, int driver, boolean isDriverLoaded, long driverLoadingTime) = 1;
    oneway void setTargetStats(in String appPackageName, long driverVersionCode, int stats, long value) = 2;
    oneway void setUpdatableDriverPath(in String driverPath) = 3;
    String getUpdatableDriverPath() = 4;
    oneway void toggleAngleAsSystemDriver(boolean enabled) = 5;
    IBinder setTargetStatsArray() = 6;
    IBinder addVulkanEngineName() = 7;
    IBinder getFeatureConfigOverrides() = 8;
    IBinder getPersistGraphicsEgl() = 9;
}
