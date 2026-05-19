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

/**
 * Detailed description of a device state that includes separated lists of
 * {@link DeviceStateSystemPropertyValue} and {@link DeviceStatePhysicalPropertyValue} for
 *  properties that correspond to the state of the system when the device is in this state, as well
 *  as physical properties that describe this state.
 *
 * @see android.hardware.devicestate.DeviceState
 */
@VintfStability
parcelable DeviceStateConfiguration {
    /**
     * For more information about how these properties were defined
     * @see android.hardware.devicestate.DeviceState
     */
    @VintfStability
    @Backing(type="long")
    enum DeviceStatePropertyValue {
        /**
         * Property that indicates that a fold-in style foldable device is currently in a fully closed
         * configuration.
         */
        FOLDABLE_HARDWARE_CONFIGURATION_FOLD_IN_CLOSED = 1 << 0,

        /**
         * Property that indicates that a fold-in style foldable device is currently in a half-opened
         * configuration.
         * <p>This signifies that the device's hinge is positioned somewhere around 90
         * degrees. Checking for display configuration properties as well can provide information
         * on which display is currently active.</p>
         */
        FOLDABLE_HARDWARE_CONFIGURATION_FOLD_IN_HALF_OPEN = 1 << 1,

        /**
         * Property that indicates that a fold-in style foldable device is currently in a fully open
         * configuration.
         */
        FOLDABLE_HARDWARE_CONFIGURATION_FOLD_IN_OPEN = 1 << 2,

        /**
         * Property that indicates that the outer display area of a foldable device is currently the
         * primary display area.
         *
         * <p>Note: This does not necessarily mean that the outer display area is the
         * default display. </p>
         */
        FOLDABLE_DISPLAY_CONFIGURATION_OUTER_PRIMARY = 1 << 3,

        /**
         * Property that indicates that the inner display area of a foldable device is currently the
         * primary display area.
         *
         * <p>Note: This does not necessarily mean that the inner display area is the
         * default display.</p>
         */
        FOLDABLE_DISPLAY_CONFIGURATION_INNER_PRIMARY = 1 << 4,

        /**
         * Property that indicates that this state corresponds to the device state for rear display
         * mode.
         * <p>This means that the active display is facing the same direction as the rear camera.</p>
         */
        FEATURE_REAR_DISPLAY = 1 << 5,

        /**
         * Property that indicates that this state corresponds to the device state where both displays
         * on a foldable are active, with the internal display being the default display.
         */
        FEATURE_DUAL_DISPLAY = 1 << 6,
    }

    /**
    * The device properties is a bitfield of potential states, and some physical configurations
    * could plausibly correspond to multiple different combinations of state bits.
    */
    long deviceProperties;
}
