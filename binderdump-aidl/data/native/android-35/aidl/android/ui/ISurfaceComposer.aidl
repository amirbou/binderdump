// Synthetic AIDL stand-in for the legacy hand-written C++ binder
// interface android::ui::ISurfaceComposer (the pre-AIDL-conversion
// class — modern descriptor is android.gui.ISurfaceComposer, which
// lives in the AOSP corpus).
// Source: frameworks/native/libs/gui/ISurfaceComposer.cpp (android12-release).
// The legacy class was deleted upstream during the AIDL conversion;
// this corpus exists so captures from older or vendor binaries that
// still emit the legacy `android.ui.ISurfaceComposer` descriptor get
// readable method names. Codes are frozen at their android-12 values.
//
// Enum from ISurfaceComposer.h (ISurfaceComposerTag):
//
//   BOOT_FINISHED                          = IBinder::FIRST_CALL_TRANSACTION  // 1
//   CREATE_CONNECTION                                                          // 2
//   GET_STATIC_DISPLAY_INFO                                                    // 3
//   CREATE_DISPLAY_EVENT_CONNECTION                                             // 4
//   CREATE_DISPLAY                                                             // 5
//   DESTROY_DISPLAY                                                            // 6
//   GET_PHYSICAL_DISPLAY_TOKEN                                                 // 7
//   SET_TRANSACTION_STATE                                                      // 8
//   AUTHENTICATE_SURFACE                                                       // 9
//   GET_SUPPORTED_FRAME_TIMESTAMPS                                             // 10
//   GET_DISPLAY_MODES                (deprecated, use GET_DYNAMIC_DISPLAY_INFO)// 11
//   GET_ACTIVE_DISPLAY_MODE          (deprecated, use GET_DYNAMIC_DISPLAY_INFO)// 12
//   GET_DISPLAY_STATE                                                          // 13
//   CAPTURE_DISPLAY                                                            // 14
//   CAPTURE_LAYERS                                                             // 15
//   CLEAR_ANIMATION_FRAME_STATS                                                // 16
//   GET_ANIMATION_FRAME_STATS                                                  // 17
//   SET_POWER_MODE                                                             // 18
//   GET_DISPLAY_STATS                                                          // 19
//   GET_HDR_CAPABILITIES             (deprecated, use GET_DYNAMIC_DISPLAY_INFO)// 20
//   GET_DISPLAY_COLOR_MODES          (deprecated, use GET_DYNAMIC_DISPLAY_INFO)// 21
//   GET_ACTIVE_COLOR_MODE            (deprecated, use GET_DYNAMIC_DISPLAY_INFO)// 22
//   SET_ACTIVE_COLOR_MODE                                                      // 23
//   ENABLE_VSYNC_INJECTIONS                                                    // 24
//   INJECT_VSYNC                                                               // 25
//   GET_LAYER_DEBUG_INFO                                                       // 26
//   GET_COMPOSITION_PREFERENCE                                                 // 27
//   GET_COLOR_MANAGEMENT                                                       // 28
//   GET_DISPLAYED_CONTENT_SAMPLING_ATTRIBUTES                                  // 29
//   SET_DISPLAY_CONTENT_SAMPLING_ENABLED                                       // 30
//   GET_DISPLAYED_CONTENT_SAMPLE                                               // 31
//   GET_PROTECTED_CONTENT_SUPPORT                                              // 32
//   IS_WIDE_COLOR_DISPLAY                                                      // 33
//   GET_DISPLAY_NATIVE_PRIMARIES                                               // 34
//   GET_PHYSICAL_DISPLAY_IDS                                                   // 35
//   ADD_REGION_SAMPLING_LISTENER                                               // 36
//   REMOVE_REGION_SAMPLING_LISTENER                                            // 37
//   SET_DESIRED_DISPLAY_MODE_SPECS                                             // 38
//   GET_DESIRED_DISPLAY_MODE_SPECS                                             // 39
//   GET_DISPLAY_BRIGHTNESS_SUPPORT                                             // 40
//   SET_DISPLAY_BRIGHTNESS                                                     // 41
//   CAPTURE_DISPLAY_BY_ID                                                      // 42
//   NOTIFY_POWER_BOOST                                                         // 43
//   SET_GLOBAL_SHADOW_SETTINGS                                                 // 44
//   GET_AUTO_LOW_LATENCY_MODE_SUPPORT(deprecated, use GET_DYNAMIC_DISPLAY_INFO)// 45
//   SET_AUTO_LOW_LATENCY_MODE                                                  // 46
//   GET_GAME_CONTENT_TYPE_SUPPORT    (deprecated, use GET_DYNAMIC_DISPLAY_INFO)// 47
//   SET_GAME_CONTENT_TYPE                                                      // 48
//   SET_FRAME_RATE                                                             // 49
//   ACQUIRE_FRAME_RATE_FLEXIBILITY_TOKEN                                       // 50
//   SET_FRAME_TIMELINE_INFO                                                    // 51
//   ADD_TRANSACTION_TRACE_LISTENER                                             // 52
//   GET_GPU_CONTEXT_PRIORITY                                                   // 53
//   GET_MAX_ACQUIRED_BUFFER_COUNT                                              // 54
//   GET_DYNAMIC_DISPLAY_INFO                                                   // 55
//   ADD_FPS_LISTENER                                                           // 56
//   REMOVE_FPS_LISTENER                                                        // 57
//   OVERRIDE_HDR_TYPES                                                         // 58
//   ADD_HDR_LAYER_INFO_LISTENER                                                // 59
//   REMOVE_HDR_LAYER_INFO_LISTENER                                             // 60
//   ON_PULL_ATOM                                                               // 61
//   ADD_TUNNEL_MODE_ENABLED_LISTENER                                           // 62
//   REMOVE_TUNNEL_MODE_ENABLED_LISTENER                                        // 63
//
// Remaining IBinder stubs use non-expressible types (Flattenable, vector, blob, String8).

package android.ui;

interface ISurfaceComposer {
    void bootFinished() = 1;
    void createConnection(out IBinder result) = 2;
    IBinder getStaticDisplayInfo() = 3;
    void createDisplayEventConnection(int vsyncSource, int eventRegistration, out IBinder result) = 4;
    IBinder createDisplay() = 5;
    void destroyDisplay(IBinder display) = 6;
    void getPhysicalDisplayToken(long displayId, out IBinder result) = 7;
    IBinder setTransactionState() = 8;
    void authenticateSurface(IBinder bufferProducer, out int result) = 9;
    void getSupportedFrameTimestamps(out int status) = 10;
    IBinder getDisplayModes() = 11;
    IBinder getActiveDisplayMode() = 12;
    IBinder getDisplayState() = 13;
    IBinder captureDisplay() = 14;
    IBinder captureLayers() = 15;
    void clearAnimationFrameStats(out int status) = 16;
    void getAnimationFrameStats() = 17;
    void setPowerMode(IBinder display, int mode) = 18;
    void getDisplayStats(IBinder display, out int status) = 19;
    IBinder getHdrCapabilities() = 20;
    IBinder getDisplayColorModes() = 21;
    IBinder getActiveColorMode() = 22;
    void setActiveColorMode(IBinder display, int colorMode, out int status) = 23;
    oneway void enableVsyncInjections(boolean enable) = 24;
    oneway void injectVsync(long when) = 25;
    void getLayerDebugInfo(out int status) = 26;
    void getCompositionPreference(out int status, out int defaultDataspace, out int defaultPixelFormat, out int wideColorGamutDataspace, out int wideColorGamutPixelFormat) = 27;
    void getColorManagement(out boolean colorManagement) = 28;
    void getDisplayedContentSamplingAttributes(IBinder display, out int format, out int dataspace, out int componentMask) = 29;
    void setDisplayContentSamplingEnabled(IBinder display, boolean enable, byte componentMask, long maxFrames) = 30;
    void getDisplayedContentSample(IBinder display, long maxFrames, long timestamp, out long numFrames) = 31;
    void getProtectedContentSupport(out boolean result) = 32;
    void isWideColorDisplay(IBinder token, out boolean result) = 33;
    void getDisplayNativePrimaries(IBinder display, out int status) = 34;
    void getPhysicalDisplayIds() = 35;
    IBinder addRegionSamplingListener() = 36;
    void removeRegionSamplingListener(IBinder listener) = 37;
    void setDesiredDisplayModeSpecs(IBinder token, int defaultMode, boolean allowGroupSwitching, float primaryRefreshRateMin, float primaryRefreshRateMax, float appRequestRefreshRateMin, float appRequestRefreshRateMax, out int status) = 38;
    void getDesiredDisplayModeSpecs(IBinder token, out int defaultMode, out boolean allowGroupSwitching, out float primaryRefreshRateMin, out float primaryRefreshRateMax, out float appRequestRefreshRateMin, out float appRequestRefreshRateMax, out int status) = 39;
    void getDisplayBrightnessSupport(IBinder displayToken, out boolean result) = 40;
    IBinder setDisplayBrightness() = 41;
    void captureDisplayById(long displayOrLayerStack, IBinder listener) = 42;
    oneway void notifyPowerBoost(int boostId) = 43;
    IBinder setGlobalShadowSettings() = 44;
    IBinder getAutoLowLatencyModeSupport() = 45;
    void setAutoLowLatencyMode(IBinder display, boolean on) = 46;
    IBinder getGameContentTypeSupport() = 47;
    void setGameContentType(IBinder display, boolean on) = 48;
    void setFrameRate(IBinder surface, float frameRate, byte compatibility, byte changeFrameRateStrategy, out int status) = 49;
    void acquireFrameRateFlexibilityToken(out int status, out IBinder token) = 50;
    IBinder setFrameTimelineInfo() = 51;
    void addTransactionTraceListener(IBinder listener) = 52;
    void getGpuContextPriority(out int result) = 53;
    void getMaxAcquiredBufferCount(out int result) = 54;
    IBinder getDynamicDisplayInfo() = 55;
    void addFpsListener(int taskId, IBinder listener) = 56;
    void removeFpsListener(IBinder listener) = 57;
    IBinder overrideHdrTypes() = 58;
    void addHdrLayerInfoListener(IBinder displayToken, IBinder listener) = 59;
    void removeHdrLayerInfoListener(IBinder displayToken, IBinder listener) = 60;
    void onPullAtom(int atomId, out int atomDataSize) = 61;
    void addTunnelModeEnabledListener(IBinder listener) = 62;
    void removeTunnelModeEnabledListener(IBinder listener) = 63;
}
