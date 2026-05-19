// Synthetic AIDL stand-in for android::ISensorEventConnection.
// Source: frameworks/native/libs/sensor/ISensorEventConnection.cpp (android14-release)
// (enum and BnSensorEventConnection::onTransact switch arms)
//
//   IMPLEMENT_META_INTERFACE(SensorEventConnection, "android.gui.SensorEventConnection")
//
//   GET_SENSOR_CHANNEL  = IBinder::FIRST_CALL_TRANSACTION  // 1
//   ENABLE_DISABLE                                         // 2
//   SET_EVENT_RATE                                         // 3
//   FLUSH_SENSOR                                           // 4
//   CONFIGURE_CHANNEL                                      // 5
//   DESTROY                                                // 6
//
// Parameter types are placeholders — payload decoding is out of scope.

package android.gui;

interface SensorEventConnection {
    IBinder getSensorChannel() = 1;
    IBinder enableDisable() = 2;
    IBinder setEventRate() = 3;
    IBinder flushSensor() = 4;
    IBinder configureChannel() = 5;
    IBinder destroy() = 6;
}
