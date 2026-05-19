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
// Parameter types are placeholders — payload decoding is out of scope.

package android.ui;

interface ISurfaceComposer {
    IBinder bootFinished() = 1;
    IBinder createConnection() = 2;
    IBinder getStaticDisplayInfo() = 3;
    IBinder createDisplayEventConnection() = 4;
    IBinder createDisplay() = 5;
    IBinder destroyDisplay() = 6;
    IBinder getPhysicalDisplayToken() = 7;
    IBinder setTransactionState() = 8;
    IBinder authenticateSurface() = 9;
    IBinder getSupportedFrameTimestamps() = 10;
    IBinder getDisplayModes() = 11;
    IBinder getActiveDisplayMode() = 12;
    IBinder getDisplayState() = 13;
    IBinder captureDisplay() = 14;
    IBinder captureLayers() = 15;
    IBinder clearAnimationFrameStats() = 16;
    IBinder getAnimationFrameStats() = 17;
    IBinder setPowerMode() = 18;
    IBinder getDisplayStats() = 19;
    IBinder getHdrCapabilities() = 20;
    IBinder getDisplayColorModes() = 21;
    IBinder getActiveColorMode() = 22;
    IBinder setActiveColorMode() = 23;
    IBinder enableVsyncInjections() = 24;
    IBinder injectVsync() = 25;
    IBinder getLayerDebugInfo() = 26;
    IBinder getCompositionPreference() = 27;
    IBinder getColorManagement() = 28;
    IBinder getDisplayedContentSamplingAttributes() = 29;
    IBinder setDisplayContentSamplingEnabled() = 30;
    IBinder getDisplayedContentSample() = 31;
    IBinder getProtectedContentSupport() = 32;
    IBinder isWideColorDisplay() = 33;
    IBinder getDisplayNativePrimaries() = 34;
    IBinder getPhysicalDisplayIds() = 35;
    IBinder addRegionSamplingListener() = 36;
    IBinder removeRegionSamplingListener() = 37;
    IBinder setDesiredDisplayModeSpecs() = 38;
    IBinder getDesiredDisplayModeSpecs() = 39;
    IBinder getDisplayBrightnessSupport() = 40;
    IBinder setDisplayBrightness() = 41;
    IBinder captureDisplayById() = 42;
    IBinder notifyPowerBoost() = 43;
    IBinder setGlobalShadowSettings() = 44;
    IBinder getAutoLowLatencyModeSupport() = 45;
    IBinder setAutoLowLatencyMode() = 46;
    IBinder getGameContentTypeSupport() = 47;
    IBinder setGameContentType() = 48;
    IBinder setFrameRate() = 49;
    IBinder acquireFrameRateFlexibilityToken() = 50;
    IBinder setFrameTimelineInfo() = 51;
    IBinder addTransactionTraceListener() = 52;
    IBinder getGpuContextPriority() = 53;
    IBinder getMaxAcquiredBufferCount() = 54;
    IBinder getDynamicDisplayInfo() = 55;
    IBinder addFpsListener() = 56;
    IBinder removeFpsListener() = 57;
    IBinder overrideHdrTypes() = 58;
    IBinder addHdrLayerInfoListener() = 59;
    IBinder removeHdrLayerInfoListener() = 60;
    IBinder onPullAtom() = 61;
    IBinder addTunnelModeEnabledListener() = 62;
    IBinder removeTunnelModeEnabledListener() = 63;
}
