// Synthetic AIDL stand-in for android::IGpuService.
// Source: frameworks/native/libs/graphicsenv/IGpuService.cpp + include/graphicsenv/IGpuService.h (android13-release)
// Enum BnGpuService::IGpuServiceTag:
//
//   SET_GPU_STATS                 = IBinder::FIRST_CALL_TRANSACTION  // 1
//   SET_TARGET_STATS                                                  // 2
//   SET_UPDATABLE_DRIVER_PATH                                         // 3
//   GET_UPDATABLE_DRIVER_PATH                                         // 4
//
// TOGGLE_ANGLE_AS_SYSTEM_DRIVER (5) was added after android13-release.
// SET_TARGET_STATS_ARRAY (6) and ADD_VULKAN_ENGINE_NAME (7) were added after
// android14-release.
//
// Types verified against BpGpuService (writeUtf8AsUtf16 -> String, writeUint64/
// writeInt64 -> long, writeInt32 -> int, writeBool -> boolean).

package android.graphicsenv;

interface IGpuService {
    oneway void setGpuStats(in String driverPackageName, in String driverVersionName, long driverVersionCode, long driverBuildTime, in String appPackageName, int vulkanVersion, int driver, boolean isDriverLoaded, long driverLoadingTime) = 1;
    oneway void setTargetStats(in String appPackageName, long driverVersionCode, int stats, long value) = 2;
    oneway void setUpdatableDriverPath(in String driverPath) = 3;
    void getUpdatableDriverPath(out String driverPath) = 4;
}
