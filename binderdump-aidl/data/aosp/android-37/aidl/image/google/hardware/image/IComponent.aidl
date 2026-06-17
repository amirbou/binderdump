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

import android.hardware.HardwareBuffer;
import google.hardware.image.EncodeParams;
import google.hardware.image.Metadata;
import google.hardware.image.QueryResult;

/**
 * Interface for an image codec component. Components currently only have one
 * functionality: JPEG encode.
 */
@VintfStability
interface IComponent {
    /**
     * Encodes an image with the component. This is a blocking call and will
     * return when the encoding is complete.
     *
     * @params src HardwareBuffer containing a YUV image. The format must be
     * one of the supported PixelFormats returned by queryComponentConstraints().
     * @params dst HardwareBuffer Empty buffer to be filled with encode output
     * before the function returns.
     *
     * Parameter requirements for dst:
     * width >= yuv size
     * height: 1
     * layers: 1
     * format: BLOB
     * usage: usage returned by IComponent::queryComponentConstraints
     *
     * @params params The parameters needed from the client for encoding
     * @return size of the encoded output bitstream.
     * @throws ServiceSpecificException with ComponentError as the code on failure.
     */
    int encode(in HardwareBuffer src, inout HardwareBuffer dst, in EncodeParams params);

    /**
     * Queries for general information about the component.
     *
     * @return QueryResult object with all entries filled.
     * @throws ServiceSpecificException with ComponentError as the code on failure.
     */
    QueryResult queryComponentConstraints();
}
