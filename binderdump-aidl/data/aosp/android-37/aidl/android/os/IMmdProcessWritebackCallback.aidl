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

package android.os;

/**
 * Callback to register with IMmd interface.
 */
interface IMmdProcessWritebackCallback {
    enum WritebackStatus {
        /**
         * Status indicating that the writeback operation succeeded.
         */
        SUCCESS = 1,
        /**
         * Status indicating that writeback failed because the backing the backing
         * device became full.
         */
        FAILURE_DEVICE_FULL = 2,
        /**
         * Status indicating that writeback is unsupported on this device.
         */
        FAILURE_UNSUPPORTED = 3,
        /**
         * Status indicating that writeback failed for an unspecified reason.
         */
        FAILURE_OTHER = 4,
    }

    /**
     * Callback invoked when a zram writeback operation completes.
     *
     * @param status is a code specifying the completion status of the operation.
     * @param bytesWritten is the number of bytes written to the backing device.
     */
    oneway void onProcessMemoryWritebackComplete(WritebackStatus status, long bytesWritten);
}
