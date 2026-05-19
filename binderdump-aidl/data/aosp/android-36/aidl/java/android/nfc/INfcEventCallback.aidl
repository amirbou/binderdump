package android.nfc;

import android.nfc.ComponentNameAndUser;
import android.nfc.cardemulation.PollingFrame;

/**
 * @hide
 */
oneway interface INfcEventCallback {
    void onPreferredServiceChanged(in ComponentNameAndUser ComponentNameAndUser);
    void onObserveModeStateChanged(boolean isEnabled);
    void onObserveModeDisabledInFirmware(in PollingFrame exitFrame);
    void onAidConflictOccurred(in String aid);
    void onAidNotRouted(in String aid);
    void onNfcStateChanged(in int nfcState);
    void onRemoteFieldChanged(boolean isDetected);
    void onInternalErrorReported(in int errorType);
}
