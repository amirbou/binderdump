/*
 * Copyright (C) 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.os;

import android.os.Bundle;
import android.os.IProfilingAnomalyCallback;
import android.os.IProfilingResultCallback;
import android.os.IProfilingTriggerCallback;
import android.os.ProfilingTriggerValueParcel;

/**
 * @hide
 */
interface IProfilingService {

    oneway void requestProfiling(int profilingType, in Bundle params, String tag,
            long keyMostSigBits, long keyLeastSigBits, String packageName);

    oneway void registerResultsCallback(boolean isGeneralCallback,
            IProfilingResultCallback callback);

    oneway void generalListenerAdded();

    oneway void requestCancel(long keyMostSigBits, long keyLeastSigBits);

    oneway void receiveFileDescriptor(in ParcelFileDescriptor fileDescriptor, long keyMostSigBits,
            long keyLeastSigBits);

    oneway void addProfilingTriggers(in List<ProfilingTriggerValueParcel> triggers,
            String packageName);

    oneway void removeProfilingTriggers(in int[] triggers, String packageName);

    oneway void addAllProfilingTriggers(String packageName);

    oneway void clearProfilingTriggers(String packageName);

    oneway void processTrigger(int uid, String packageName, int triggerType, String tag, IProfilingTriggerCallback callback);

    oneway void stopActiveProfiling(int uid, String packageName, int triggerType);

    oneway void registerAnomalyCallback(IProfilingAnomalyCallback callbacks);

    boolean isTriggerRegistered(int uid, String packageName, int triggerType);

    oneway void sendAnomalyProfile(long keyMostSigBits, long keyLeastSigBits, int uid, String packageName, int triggerType, String tag, String resultFileName);

    oneway void collectAnomalyProfile(long keyMostSigBits, long keyLeastSigBits, int uid, String packageName, int profilingType, int triggerType, boolean returnToAnomalyDetectorOnly, String tag, in Bundle params);

    oneway void notifyResultDelivered(long keyMostSigBits, long keyLeastSigBits);
}
