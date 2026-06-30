// Synthetic AIDL stand-in for android::IGpuService.
// Source: frameworks/native/libs/graphicsenv/IGpuService.cpp + include/graphicsenv/IGpuService.h (android15-release)
// Enum BnGpuService::IGpuServiceTag:
//
//   SET_GPU_STATS                 = IBinder::FIRST_CALL_TRANSACTION  // 1
//   SET_TARGET_STATS                                                  // 2
//   SET_UPDATABLE_DRIVER_PATH                                         // 3
//   GET_UPDATABLE_DRIVER_PATH                                         // 4
//   TOGGLE_ANGLE_AS_SYSTEM_DRIVER                                     // 5
//   SET_TARGET_STATS_ARRAY                                            // 6
//   ADD_VULKAN_ENGINE_NAME                                            // 7
//
// (GET_FEATURE_CONFIG_OVERRIDES was not yet present on android15-release)
//
// Codes 1-5 carry source-verified types. Code 6 stays a typeless IBinder stub:
// SET_TARGET_STATS_ARRAY ends in a raw Parcel::write() buffer and isn't
// AIDL-expressible. Code 7 (ADD_VULKAN_ENGINE_NAME) is now typed:
// BpGpuService::addVulkanEngineName calls writeCString → in CString.

package android.graphicsenv;

interface IGpuService {
    oneway void setGpuStats(in String driverPackageName, in String driverVersionName, long driverVersionCode, long driverBuildTime, in String appPackageName, int vulkanVersion, int driver, boolean isDriverLoaded, long driverLoadingTime) = 1;
    oneway void setTargetStats(in String appPackageName, long driverVersionCode, int stats, long value) = 2;
    oneway void setUpdatableDriverPath(in String driverPath) = 3;
    void getUpdatableDriverPath(out String driverPath) = 4;
    oneway void toggleAngleAsSystemDriver(boolean enabled) = 5;
    IBinder setTargetStatsArray() = 6;
    oneway void addVulkanEngineName(in CString engineName) = 7;
}
