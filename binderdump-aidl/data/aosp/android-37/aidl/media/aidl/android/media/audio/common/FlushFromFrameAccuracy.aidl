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

package android.media.audio.common;

/**
 * The constants for flush from frame accuracy mode.
 * {@hide}
 */
@Backing(type="int")
@VintfStability
enum FlushFromFrameAccuracy {
    /**
     * Accuracy mode to indicate when `flushFromFrame` is called, the data
     * should be flushed from position that is as close as possible, but not
     * below, to the requested position.
     */
    BEST_EFFORT = 0,
    /**
     * Accuracy mode to indicate when `flushFromFrame` is called, the data must
     * be flushed from the requested position or fails to flush if it is not
     * possible to flush from the requested position.
     */
    EXACT = 1,
}
