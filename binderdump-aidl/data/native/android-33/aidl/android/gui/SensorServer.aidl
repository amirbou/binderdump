// Synthetic AIDL stand-in for android::ISensorServer.
// Source: frameworks/native/libs/sensor/ISensorServer.cpp (android13-release)
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
//
// GET_RUNTIME_SENSOR_LIST (7) was added after android13-release.
// ENABLE_REPLAY_DATA_INJECTION (8) and ENABLE_HAL_BYPASS_REPLAY_DATA_INJECTION (9)
// were added after android14-release.
//
// Parameter types are placeholders — payload decoding is out of scope.

package android.gui;

interface SensorServer {
    IBinder getSensorList() = 1;
    IBinder createSensorEventConnection() = 2;
    IBinder enableDataInjection() = 3;
    IBinder getDynamicSensorList() = 4;
    IBinder createSensorDirectConnection() = 5;
    IBinder setOperationParameter() = 6;
}
