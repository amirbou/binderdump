/*
 * Copyright (C) 2026 The Android Open Source Project
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

package com.google.hardware.pixel.display;

import com.google.hardware.pixel.display.HistogramRequest;

@VintfStability
parcelable HistogramSubscription {
    /**
     * A client-defined unique ID to identify this specific subscription.
     *
     * This ID is returned in the corresponding HistogramEvent, allowing the
     * client to correlate events with the original subscription. It also
     * serves as the handle for the client to register, unregister, activate,
     * or deactivate the subscription.
     *
     * Note: The server does not generate this ID. If not explicitly set by the
     *       client, it defaults to 0.
     */
    int subscriptionId = 0;

    /**
     * The histogram configuration for this subscription.
     */
    HistogramRequest request;

    /**
     * Defines the conditions and timing for a histogram callback.
     */
    @VintfStability
    parcelable HistogramTrigger {
        /**
         * The minimum time interval between two callbacks, in milliseconds.
         *
         * This is a throttling mechanism to prevent spamming the client with too
         * many callbacks. If the histogram request is not swapped out due to
         * time-sharing, the DisplayHAL will publish the histogram event immediately
         * once this duration has expired. If it is swapped out, please refer to
         * staleToleranceMs below.
         *
         * The value must be greater than or equal to 0. A negative value will be
         * considered an invalid subscription.
         */
        int minNotifyIntervalMs = 0;

        /**
         * The maximum time, in milliseconds, the client can tolerate stale data.
         *
         * This is a critical deadline for the subscriber. If a histogram request is
         * swapped out, the DisplayHAL relies on this configuration to schedule the
         * request accordingly. When a new frame with content changes becomes
         * available, the previous histogram data is considered stale, and the
         * DisplayHAL must provide an updated histogram within this duration.
         *
         * Note: A higher value allows the DisplayHAL to optimistically wait for
         * subsequent frame updates from the framework without forcing an
         * immediate frame update. This can improve power efficiency, especially
         * when multiple subscriptions are active and competing for hardware resources.
         *
         * The value must be greater than or equal to minNotifyIntervalMs; otherwise, the
         * subscription will be considered invalid. If this value is not explicitly
         * set (or is set to 0), it will be automatically set equal to the value of
         * minNotifyIntervalMs.
         */
        int staleToleranceMs = 0;

        /**
         * A threshold for an increase in Average Pixel Level (APL).
         *
         * The default value is 0, which does not ignore any update. If the APL
         * increase is less than this threshold, the DisplayHAL will ignore the
         * content change and not send a new histogram update. The previously
         * provided histogram data will still be considered up to date.
         *
         * The value must be greater than or equal to 0. A negative value will be
         * considered an invalid subscription.
         */
        float aplIncThreshold = 0f;

        /**
         * A threshold for a decrease in Average Pixel Level (APL).
         *
         * The default value is 0, which does not ignore any update. If the APL
         * decrease is less than this threshold, the DisplayHAL will ignore the
         * content change and not send a new histogram update. The previously
         * provided histogram data will still be considered up to date.
         *
         * The value must be greater than or equal to 0. A negative value will be
         * considered an invalid subscription.
         */
        float aplDecThreshold = 0f;
    }
    HistogramTrigger trigger;
}
