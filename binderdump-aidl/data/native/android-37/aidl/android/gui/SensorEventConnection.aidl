// Synthetic AIDL stand-in for android::ISensorEventConnection.
// Source: frameworks/native/libs/sensor/ISensorEventConnection.cpp (android17-release)
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
// Remaining IBinder stub: 1 (BitTube socketpair fd — not AIDL-decodable).

package android.gui;

interface SensorEventConnection {
    IBinder getSensorChannel() = 1;
    void enableDisable(int handle, boolean enabled, long samplingPeriodNs, long maxBatchReportLatencyNs, int reservedFlags, out int status) = 2;
    void setEventRate(int handle, long ns, out int status) = 3;
    void flushSensor(out int status) = 4;
    void configureChannel(int handle, int rateLevel, out int status) = 5;
    oneway void destroy() = 6;
}
