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

import google.hardware.image.ComponentType;
import google.hardware.image.IComponent;
import google.hardware.image.IComponentCallback;

/**
 * Interface that creates image codec component interfaces when requested.
 * The google.hardware.image-V1-service service creates an instance of this
 * interface.
 */
@VintfStability
interface IComponentStore {
    /**
     * Creates and returns a new instance of an image codec component interface.
     * This component interface can be used to encode and decode images.
     *
     * @param name Component identifier.
     * @param type Specifies the component is for encoding or decoding.
     * @param callback Method for backwards communication from image HAL to
     * client app. Used to tell the client the size of the output buffer
     * required for encode/decode.
     * @return The created component.
     * @throws ServiceSpecificException with ComponentError as the code on failure.
     */
    IComponent createComponent(in ComponentType type, in IComponentCallback callback);
}
