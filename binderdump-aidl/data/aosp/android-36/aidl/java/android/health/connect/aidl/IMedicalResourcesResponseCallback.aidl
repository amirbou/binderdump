package android.health.connect.aidl;

import android.health.connect.datatypes.MedicalResource;
import android.health.connect.aidl.HealthConnectExceptionParcel;

/**
 * Callback for {@link IHealthConnectService#upsertMedicalResources}.
 *
 * {@hide}
 */
interface IMedicalResourcesResponseCallback {
    // Called on a successful operation
    oneway void onResult(in List<MedicalResource> medicalResources);
    // Called when an error is hit
    oneway void onError(in HealthConnectExceptionParcel exception);
}
