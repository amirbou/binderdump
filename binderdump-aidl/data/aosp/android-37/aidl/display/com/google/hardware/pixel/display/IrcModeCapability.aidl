/*
 * Copyright (C) 2025 The Android Open Source Project
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

@VintfStability
parcelable IrcModeCapability {
    /**
     * Indicates whether the device's display server supports the IRC Off function,
     * allowing clients to request that mode.
     */
    boolean ircOff;

    /**
     * Indicates whether the device's display server supports the Peak Luminance function,
     * allowing clients to request that mode.
     */
    boolean peakLuminance;
}
