/******************************************************************************
 *
 *  Copyright (C) 2024 Google LLC.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/
package google.hardware.image;

import android.hardware.graphics.common.PixelFormat;

/**
 * List of image codec constraints. This is filled in the HAL when the client
 * queries for this information.
 */
@VintfStability
parcelable QueryResult {
    /**
     * Colour formats that are supported by image codec.
     */
    PixelFormat[] supportedColorFormats;
    /**
     * Usage value required for HardwareBuffer creation. The client will use
     * this usage value when allocating the source buffer using gralloc. A
     * buffer created without this usage bit will be rejected.
     */
    long usageSrcBuf;
    /**
     * Usage value required for HardwareBuffer creation. The client will use
     * this usage value when allocating the destination buffer using gralloc.
     * A buffer created without this usage bit will be rejected.
     */
    long usageDstBuf;
}
