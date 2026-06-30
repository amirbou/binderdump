// Synthetic AIDL stand-in for android::ISensorServer.
// Source: frameworks/native/libs/sensor/ISensorServer.cpp (android15-release)
// (enum and BnSensorServer::onTransact switch arms)
//
//   IMPLEMENT_META_INTERFACE(SensorServer, "android.gui.SensorServer")
//
//   GET_SENSOR_LIST                           = IBinder::FIRST_CALL_TRANSACTION  // 1
//   CREATE_SENSOR_EVENT_CONNECTION                                                // 2
//   ENABLE_DATA_INJECTION                                                         // 3
//   GET_DYNAMIC_SENSOR_LIST                                                       // 4
//   CREATE_SENSOR_DIRECT_CONNECTION                                               // 5
//   SET_OPERATION_PARAMETER                                                       // 6
//   GET_RUNTIME_SENSOR_LIST                                                       // 7
//   ENABLE_REPLAY_DATA_INJECTION                                                  // 8
//   ENABLE_HAL_BYPASS_REPLAY_DATA_INJECTION                                       // 9
//
// Remaining IBinder stubs: 1 (Sensor Flattenable array), 4 (Sensor Flattenable array),
// 5 (NativeHandle fds), 6 (float array), 7 (Sensor Flattenable array).

package android.gui;

interface SensorServer {
    IBinder getSensorList() = 1;
    void createSensorEventConnection(in String8 packageName, int mode, in String opPackageName, in String attributionTag, out IBinder connection) = 2;
    void enableDataInjection(int mode, out int status) = 3;
    IBinder getDynamicSensorList() = 4;
    IBinder createSensorDirectConnection() = 5;
    IBinder setOperationParameter() = 6;
    IBinder getRuntimeSensorList() = 7;
    void enableReplayDataInjection(int mode, out int status) = 8;
    void enableHalBypassReplayDataInjection(int mode, out int status) = 9;
}
