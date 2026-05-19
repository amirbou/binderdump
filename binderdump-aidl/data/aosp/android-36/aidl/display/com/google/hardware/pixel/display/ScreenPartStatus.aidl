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

/*
 *  Ideally IDisplay AIDL should directly use ScreenPartStatus
 *  from android.hardware.graphics.composer3. However, IDispaly
 *  AIDL enables java backend, but composer3 does not. Since we
 *  do not want composer3 to enable java backend, we will simply
 *  redefine an enum with some static asserts to keep the two
 *  ScreenPartStatus aligned.
 */
@VintfStability
@Backing(type="int")
enum ScreenPartStatus {
    UNSUPPORTED = 0,
    ORIGINAL = 1,
    REPLACED = 2,
}
