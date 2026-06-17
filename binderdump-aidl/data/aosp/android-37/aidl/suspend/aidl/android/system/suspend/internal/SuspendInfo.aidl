/*
 * Copyright (C) 2020 The Android Open Source Project
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

package android.system.suspend.internal;

parcelable SuspendInfo {
    /* Total number of times that suspend was attempted */
    long suspendAttemptCount;

    /* Total number of times that suspend attempt failed */
    long failedSuspendCount;

    /**
     * Total number of times that a short suspend occurred. A successful suspend is considered a
     * short suspend if the suspend duration is less than suspend.short_suspend_threshold_millis
     */
    long shortSuspendCount;

    /* Total time, in milliseconds, spent in suspend */
    long suspendTimeMillis;

    /* Total time, in milliseconds, spent in short suspends */
    long shortSuspendTimeMillis;

    /* Total time, in milliseconds, spent doing suspend/resume work for successful suspends */
    long suspendOverheadTimeMillis;

    /* Total time, in milliseconds, spent doing suspend/resume work for failed suspends */
    long failedSuspendOverheadTimeMillis;

    /**
     * Total number of times the number of consecutive bad (short, failed) suspends
     * crossed suspend.backoff_threshold_count
     */
    long newBackoffCount;

    /**
     * Total number of times the number of consecutive bad (short, failed) suspends
     * exceeded suspend.backoff_threshold_count
     */
    long backoffContinueCount;

    /* Total time, in milliseconds, that system has waited between suspend attempts */
    long sleepTimeMillis;

    /**
     * A histogram of successful suspend durations, in milliseconds.
     * Bin upper bounds: 1000, 2500, 4000, 7000, 12000. Final bin is >= 12000.
     */
    long[] suspendDurationMillisBins = {0, 0, 0, 0, 0, 0};

    /**
     * A histogram of the lengths of consecutive bad suspend streaks.
     * Bin upper bounds: 2, 4, 7, 11. Final bin is >= 11.
     */
    long[] consecutiveBadSuspendBins = {0, 0, 0, 0, 0};

    /**
     * Number of times a backoff chain continued
     * while the delay was capped at its maximum value.
     */
    long maxBackoffContinuations = 0;

    /* Number of times a bad suspend occurred following a good suspend */
    long newBadSuspends = 0;

    /**
     * The number of bad suspends that occurred in sequences which ended in
     * a good suspend before the backoff threshold was reached.
     */
    long earlyRecoveryBadSuspends = 0;

    /**
     * The minimum duration the system must remain successfully suspended to
     * compensate for the energy cost of entering and exiting the suspend state,
     * beyond which net power savings are achieved.
     */
    long breakEvenMillis = 0;
}
