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

import android.frameworks.automotive.power.CarPowerState;
import android.frameworks.automotive.power.ICompletablePowerStateChangeFuture;

/**
 * ICarPowerStateChangeListenerWithCompletion is notified when the power state changes.
 *
 * Listeners with completion are able to halt the system's power state transition (within a
 * specified time limit) while the listener's process finishes up tasks needed before power state
 * changes.
 */

@VintfStability
oneway interface ICarPowerStateChangeListenerWithCompletion {

  /**
   * Called when the power state begins changing.
   *
   * @param newState The power state the system is changing to.
   * @param expirationTimeMs The timestamp (system elapsed time in milliseconds) that listeners with
   *        completion must complete by and after which, power state transition progresses.
   * @param future The future used by the listener to notify car power daemon that listener is
   *        ready to move on to the next step of the power state transition. The car power daemon
   *        halts power state progression until the listeners call {@link android.frameworks.
   *        automotive.power.ICompletablePowerStateChangeFuture#complete()} or timeout occurs. In
   *        the case that {@code state} doesn't allow for completion, {@code future} is
   *        {@code null}.
   */
  void onStateChanged(in CarPowerState state, long expirationTimeMs,
    in ICompletablePowerStateChangeFuture future);
}
