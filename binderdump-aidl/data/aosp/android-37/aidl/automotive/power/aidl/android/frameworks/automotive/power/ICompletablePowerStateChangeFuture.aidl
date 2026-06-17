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
 * ICompletablePowerStateChangeFuture is an interface passed from native car power state change
 * listeners with completion.
 *
 * <p>The listener uses this interface to tell car power deamon that it completed the task
 * relevant to the power state change.
 */

@VintfStability
interface ICompletablePowerStateChangeFuture {
  /**
   * Tells car power daemon that the listener completed the task to handle the power state change.
   */
  void complete();
}
