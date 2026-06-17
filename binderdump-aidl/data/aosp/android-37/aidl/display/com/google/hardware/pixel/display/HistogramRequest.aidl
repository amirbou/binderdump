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

import android.hardware.graphics.common.Rect;
import com.google.hardware.pixel.display.HistogramSamplePos;

@VintfStability
parcelable HistogramRequest {
    /**
     * A client-defined ID used to identify this specific request.
     *
     * This ID is a pass-through value; it is returned in the corresponding
     * HistogramEvent to allow the client to correlate events with their
     * original requests.
     *
     * Providing a unique ID is optional. If the client does not need to
     * correlate events when changing the request by updateSubscription, this
     * can remain at its default value of 0. The server does not validate
     * uniqueness or modify this value.
     */
    int requestId = 0;

    /**
     * Describes the region to capture the histogram data
     */
    @VintfStability
    parcelable HistogramCaptureRegion {
        /**
         * The region of interest (ROI) to be sampled for histogram data collection.
         *
         * Coordinates are based on the full resolution described by
         * getHistogramCapability, with the right and bottom coordinates being exclusive.
         * The value of (0, 0, 0, 0) disables the ROI and indicates that the full screen
         * should be captured instead.
         */
        @nullable Rect roi;

        /**
         * The ROI blocking region to be excluded from histogram data collection.
         *
         * The histogram is not captured for this region, even if it overlaps with
         * the capture region. Coordinates are based on the full resolution, with
         * the right and bottom coordinates being exclusive. The value of (0, 0, 0, 0)
         * indicates that the blocking ROI is disabled.
         */
        @nullable Rect blockingRoi;
    }
    HistogramCaptureRegion captureRegion;

    /**
     * Defines the method for histogram binning.
     */
    @VintfStability
    union HistogramBinMode {
        /**
         * The histogram is calculated separately for each color component (R, G, B).
         * The raw component value is used as the histogram input.
         * No additional parameters are required.
         *
         * Expects three histogram payloads via HistogramEvent (one for R, G, and B).
         */
        @VintfStability
        parcelable PerComponentMode {}
        PerComponentMode perComponent;

        /**
         * The histogram input value is derived from the maximum value among the
         * pixel's R, G, and B components. This is equivalent to max(R, G, B).
         * No additional parameters are required.
         *
         * Expects a single histogram payload via HistogramEvent.
         */
        @VintfStability
        parcelable MaxComponentMode {}
        MaxComponentMode maxComponent;

        /**
         * The histogram input value is derived from a weighted sum of the pixel's
         * R, G, and B components.
         *
         * The formula used is:
         *     (pixelR * weightR + pixelG * weightG + pixelB * weightB) / 1024
         *
         * This mode requires the weights (weightR, weightG, weightB) to be specified.
         * Constraint: weightR + weightG + weightB must equal 1024.
         *
         * Expects a single histogram payload via HistogramEvent.
         */
        @VintfStability
        parcelable WeightedSum {
            int weightR;
            int weightG;
            int weightB;
        }
        WeightedSum weightedSum;
    }
    HistogramBinMode binMode;

    /**
     * The selected tap point to sample histogram data.
     *
     * The DisplayHAL will use this position for the histogram data collection.
     */
    HistogramSamplePos samplePosition;

    /**
     * The expected color space for interpreting the pixel values used in the histogram
     * calculation.
     */
    @VintfStability
    enum ColorSpace {
        LINEAR,
        GAMMA_2_2,
    }
    ColorSpace colorSpace;

    /**
     * The format of the histogram payload requested by the client.
     */
    @VintfStability
    enum PayloadType {
        /**
         * The histogram is delivered as a raw data buffer.
         */
        RAW_BUFFER,
        /**
         * The histogram is delivered as an Average Pixel Level (APL) value.
         */
        APL,
    }
    PayloadType payloadType;
}
