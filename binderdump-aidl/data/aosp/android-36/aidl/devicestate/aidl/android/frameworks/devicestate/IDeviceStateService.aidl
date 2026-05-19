/*
 * Copyright (C) 2024 The Android Open Source Project
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

package android.frameworks.devicestate;

import android.frameworks.devicestate.IDeviceStateListener;

@VintfStability
interface IDeviceStateService {
    /**
     * Registers a listener to receive notifications from the device state manager.
     * <p>Note that only one callback can be registered per-process.</p>
     *
     * @param listener Device state listener
     *
     * @throws ServiceSpecificException with {@link ErrorCode#ALREADY_EXISTS}
     *         if the client tries to register more than one listener
     */
    void registerListener(in IDeviceStateListener listener);

    /**
     * Removes a previously registered listener from the device state manager.
     * <p>Registered listeners will also be automatically removed in case the client drops and
     * the binder connection becomes invalid.</p>
     *
     * @param listener Device state listener
     *
     * @throws ServiceSpecificException with {@link ErrorCode#BAD_INPUT} if listener was not
     *         registered
     */
    void unregisterListener(in IDeviceStateListener listener);
}
