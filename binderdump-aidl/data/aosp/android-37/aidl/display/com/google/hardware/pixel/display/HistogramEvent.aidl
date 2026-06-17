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

import com.google.hardware.pixel.display.HistogramErrorCode;

@VintfStability
parcelable HistogramEvent {
    /**
     * The status of the histogram event.
     *
     * This indicates whether the data collection was successful or if an error occurred.
     */
    HistogramErrorCode status;

    /**
     * The ID of the subscription associated with this event.
     */
    int subscriptionId;

    parcelable HistogramHeader {
        /**
         * The unique ID of the original request.
         */
        int requestId;

        /**
         * The timestamp of when the corresponding frame was presented on the display,
         * in nanoseconds.
         */
        long presentTime;

        /**
         * The timestamp of when the histogram data was collected, in nanoseconds.
         */
        long collectTime;
    }
    @nullable HistogramHeader header;

    /**
     * A union that can hold a single histogram payload in one of several formats.
     *
     * This is a tagged union. The client should use the generated getTag()
     * method (or the equivalent API-specific discriminator) to determine
     * which field is currently populated before accessing the data.
     */
    union HistogramPayload {
        /**
         * The Average Pixel Level (APL) value.
         */
        float apl;
        /**
         * The raw 16-bit histogram data buffer.
         * @size: Equal to the number of histogram bins.
         * @usage: Used when the hardware bin counter depth is 16-bit.
         */
        char[] rawBuffer16Bit;
        /**
         * The raw 32-bit histogram data buffer.
         * @size: Equal to the number of histogram bins.
         * @usage: Used when the hardware bin counter depth is 32-bit.
         */
        int[] rawBuffer32Bit;
    }

    /**
     * An array of histogram payloads.
     *
     * Each payload in this array corresponds to a histogram buffer or APL value,
     * as defined by the original request. The number of payloads will match the
     * requested payload count. When the HistogramBinMode is set to PerComponentMode,
     * this array will contain three payloads (one for each R, G, and B channel).
     * Otherwise, it will contain a single payload.
     */
    HistogramPayload[] payloads;
}
