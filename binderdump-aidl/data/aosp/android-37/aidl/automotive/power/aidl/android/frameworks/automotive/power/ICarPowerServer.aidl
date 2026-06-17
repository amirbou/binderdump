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

import android.frameworks.automotive.power.ICarPowerStateChangeListener;
import android.frameworks.automotive.power.ICarPowerStateChangeListenerWithCompletion;
import android.frameworks.automotive.powerpolicy.CarPowerPolicy;
import android.frameworks.automotive.powerpolicy.CarPowerPolicyFilter;
import android.frameworks.automotive.powerpolicy.ICarPowerPolicyChangeCallback;
import android.frameworks.automotive.powerpolicy.PowerComponent;

/**
 * ICarPowerServer is an interface implemented by the car power daemon.
 *
 * <p>VHAL changes the power policy and the power policy daemon notifies the change to registered
 * subscribers. When subscribing to policy changes, a filter can be specified so that the registered
 * callbacks can listen only to a specific power component's change.
 *
 * <p>CarService changes the power state and the power daemon notifies the change to registered
 * listeners. Listeners can be with or without completion. With completion means that the power
 * state change can be paused (up to a certain amount of time) while listeners' processes finish up
 * tasks.
 */

@VintfStability
interface ICarPowerServer {
  /**
   * Gets the current power policy.
   * @throws IllegalStateException if the current policy is not set.
   */
  CarPowerPolicy getCurrentPowerPolicy();

  /**
   * Gets whether the power component is turned on or off.
   *
   * @param componentId Power component ID defined in PowerComponent.aidl to check power state.
   * @return True if the component's power state is on.
   * @throws IllegalArgumentException if the componentId is invalid.
   */
  boolean getPowerComponentState(in PowerComponent componentId);

  /**
   * Subscribes to power policy change.
   * Notification is sent to the registered callback when the power policy changes and the power
   * state of the components which the callback is interested in changes.
   *
   * @param callback Callback that is invoked when the power policy changes.
   * @param filter The list of components which the callback is interested in.
   * @throws IllegalArgumentException if the callback is already registered.
   * @throws IllegalStateException if the callback is dead.
   */
  void registerPowerPolicyChangeCallback(in ICarPowerPolicyChangeCallback callback,
      in CarPowerPolicyFilter filter);

  /**
   * Unsubscribes from power policy change.
   *
   * @param callback Callback that doesn't want to receive power policy change.
   * @throws IllegalArgumentException if the callback is not registered.
   */
  void unregisterPowerPolicyChangeCallback(in ICarPowerPolicyChangeCallback callback);

  /**
   * Applies the power policy.
   *
   * <p>{@code policyId} should be one of power policy IDs defined in
   * {@code /vendor/etc/automotive/power_policy.xml} or predefined system power policies.
   *
   * @param policyId ID of power policy.
   * @throws IllegalArgumentException if {@code policyId} is invalid.
   */
  void applyPowerPolicy(in @utf8InCpp String policyId);

  /**
   * Sets the current power policy group.
   *
   * <p>{@code policyGroupId} should be one of power policy group IDs defined in
   * {@code /vendor/etc/automotive/power_policy.xml}.
   *
   * @param policyGroupId ID of power policy group.
   * @throws IllegalArgumentException if {@code policyGroupId} is invalid.
   */
  void setPowerPolicyGroup(in @utf8InCpp String policyGroupId);

  /**
   * Register a power state change listener with the car power daemon.
   *
   * <p>Multiple listeners are allowed to be registered to one client.
   *
   * @param listener Listener to register.
   * @throws IllegalArgumentException if the listener is already registered.
   * @throws IllegalStateException if the listener is dead.
   */
  void registerPowerStateListener(in ICarPowerStateChangeListener listener);

  /**
   * Unregister a power state change listener with the car power daemon.
   *
   * @param listener Listener to unregister.
   * @throws IllegalArgumentException if the listener is not registered.
   */
  void unregisterPowerStateListener(in ICarPowerStateChangeListener listener);

  /**
   * Register a power state change listener with completion with the car power daemon.
   *
   * <p>Listeners with completion are able to halt the system's power state transition (within a
   * time limit) while their process completes needed work before the power state changes.
   *
   * <p>Multiple listeners are allowed to be registered to one client.
   *
   * @param listener Listener to register.
   * @throws IllegalArgumentException if the listener is already registered.
   * @throws IllegalStateException if the listener is dead.
   */
  void registerPowerStateListenerWithCompletion(
    in ICarPowerStateChangeListenerWithCompletion listener);

  /**
   * Unregister a power state change listener with completion with the car power daemon.
   *
   * @param listener Listener to unregister.
   * @throws IllegalArgumentException if the listener is not registered.
   */
  void unregisterPowerStateListenerWithCompletion(
    in ICarPowerStateChangeListenerWithCompletion listener);
}
