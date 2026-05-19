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
import google.hardware.image.Metadata;
import google.hardware.image.Params;
import google.hardware.image.QueryResult;

/**
 * Interface for an image codec component. Components have two functionalities:
 * encode and decode.
 */
@VintfStability
interface IComponent {
    /**
     * Encodes an image with the component. This is a blocking call and will
     * return when the encoding is complete. The dst buffer is provided through
     * the IComponentCallback call during the encoding.
     *
     * @params src HardwareBuffer containing a YUV image. The format must be
     * one of the supported PixelFormats returned by queryComponentConstraints().
     * @return size of the encoded output bitstream.
     * @throws ServiceSpecificException with ComponentError as the code on failure.
     */
    int encode(in HardwareBuffer src);

    /**
     * Decodes an image with the component. This is a blocking call and will
     * return when the decoding is complete. The dst buffer is provided through
     * the IComponentCallback call during the decoding.
     *
     * @param src HardwareBuffer containing an encoded image bitstream. The
     * format must be BLOB.
     * @throws ServiceSpecificException with ComponentError as the code on failure.
     */
    void decode(in HardwareBuffer src);

    /**
     * Queries for general information about the component.
     *
     * @return QueryResult object with all entries filled.
     * @throws ServiceSpecificException with ComponentError as the code on failure.
     */
    QueryResult queryComponentConstraints();

    /**
     * Sets component parameters before encoding/decoding.
     *
     * @param params The parameters needed from the client for encoding/decoding.
     * @param meta List of Metadata objects representing JPEG APP segments. This
     * list can be empty if there is no metadata associated with the image to
     * be encoded.
     * @throws ServiceSpecificException with ComponentError as the code on failure.
     */
    void setParams(in Params params);
}
