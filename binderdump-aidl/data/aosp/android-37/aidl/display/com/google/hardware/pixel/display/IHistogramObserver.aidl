/*
 * Copyright (C) 2026 The Android Open Source Project
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

import com.google.hardware.pixel.display.HistogramSubscription;

@VintfStability
interface IHistogramObserver {
    /**
     * Registers a set of histogram subscriptions for the observer.
     *
     * This function can be called multiple times. In each call, the DisplayHAL
     * will process all subscriptions in the input list.
     *
     * A subscription is identified by its unique ID. The DisplayHAL will reject
     * any call containing a subscription ID that has already been registered in
     * a previous or the current call.
     *
     * @param subscriptions The subscriptions to register.
     *
     * @exception HistogramErrorCode::BAD_SUBSCRIPTION when one or more subscriptions
     *                are invalid or contain a subscription ID that is already
     *                registered.
     */
    void registerSubscriptions(in HistogramSubscription[] subscriptions);

    /**
     * Activates a set of previously registered histogram subscriptions.
     *
     * All subscriptions not included in this set will be deactivated. Passing an
     * empty array will deactivate all currently active subscriptions. This
     * function can only be called after registerSubscriptions has been
     * successfully invoked.
     *
     * The DisplayHAL immediately schedules the config to obtain the histogram data
     * and sends an initial histogramEvent to the subscriber.
     * Following this initial event, the DisplayHAL adheres to the defined rules of
     * the HistogramSubscription for all future event publishing.
     *
     * @param subscriptionIds The IDs of the subscriptions to activate.
     *
     * @exception HistogramErrorCode::BAD_SUBSCRIPTION when one or more IDs in
     *                subscriptionIds have not been registered by a previous call
     *                to registerSubscriptions.
     */
    void activateSubscriptions(in int[] subscriptionIds);

    /**
     * Updates a registered histogram subscription.
     *
     * This function modifies the configuration of an existing subscription.
     *
     * @param subscription The subscription object containing the updated configuration.
     *
     * @exception HistogramErrorCode::BAD_SUBSCRIPTION when the subscription is invalid
     *                or its ID is not currently registered.
     */
    void updateSubscription(in HistogramSubscription subscription);

    /**
     * Unregisters a set of previously registered histogram subscriptions.
     *
     * Once unregistered, the subscription IDs are no longer valid and the
     * associated configurations are removed from the DisplayHAL. If any of the
     * subscriptions are currently active, they will be automatically deactivated
     * before being removed.
     *
     * Passing an empty array is a no-op.
     *
     * @param subscriptionIds The IDs of the subscriptions to unregister.
     *
     * @exception HistogramErrorCode::BAD_SUBSCRIPTION when one or more IDs in
     * subscriptionIds have not been registered by a previous call
     * to registerSubscriptions.
     */
    void unregisterSubscriptions(in int[] subscriptionIds);
}
