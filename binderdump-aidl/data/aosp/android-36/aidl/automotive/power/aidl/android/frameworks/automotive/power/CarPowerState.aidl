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

package android.frameworks.automotive.power;

/**
 * Representation of power states, matching those defined in CarPowerManager.
 */

@VintfStability
@Backing(type="int")
enum CarPowerState {
    INVALID = 0, // State is unavailable, unknown, or invalid
    WAIT_FOR_VHAL = 1, // Android is up, but waiting for vendor to give signal to start main functionality
    SUSPEND_ENTER = 2, // System is entering deep sleep (suspend to RAM)
    SUSPEND_EXIT = 3, // System waking up from suspend
    SHUTDOWN_ENTER = 5, // System entering shutdown
    ON = 6,
    SHUTDOWN_PREPARE = 7, // System getting ready for shutdown or suspend, application expect to cleanup and be ready to suspend
    SHUTDOWN_CANCELLED = 8, // Shutdown cancelled, returning to normal state
    HIBERNATION_ENTER = 9, // System entering hibernation (suspend to disk)
    HIBERNATION_EXIT = 10, // System waking up from hibernation
    PRE_SHUTDOWN_PREPARE = 11, // Shutdown initiated, but display on
    POST_SUSPEND_ENTER = 12, // Car power service and VHAL finish processing to enter deep sleep, device about to sleep
    POST_SHUTDOWN_ENTER = 13, // Car power service and VHAL finish processing to shutdown, device about to power off
    POST_HIBERNATION_ENTER = 14, // Car power service and VHAL finish processing to enter hibernation, device about to hibernate
}
