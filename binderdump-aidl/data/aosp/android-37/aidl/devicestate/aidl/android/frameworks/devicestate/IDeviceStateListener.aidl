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

import android.frameworks.devicestate.DeviceStateConfiguration;

@VintfStability
interface IDeviceStateListener {
    /**
     * Called in response to a change in {@link DeviceStateConfiguration}.
     * <p>Guaranteed to be called once
     * after successful registration of the callback with the initial value. </p>
     *
     * @param deviceState Current device state configuration
     */
    oneway void onDeviceStateChanged(in DeviceStateConfiguration deviceState);
}
