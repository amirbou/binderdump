/*
 * Copyright (C) 2022 The Android Open Source Project
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

package android.adservices.adid;

import android.adservices.adid.GetAdIdParam;
import android.adservices.adid.IGetAdIdCallback;
import android.adservices.common.CallerMetadata;
import android.adservices.adid.GetAdIdResult;
import android.adservices.adid.RecreateAdIdResult;

/**
 * AdId Service.
 *
 * @hide
 */
interface IAdIdService {
    /**
     * Get AdId.
     */
    void getAdId(in GetAdIdParam adIdParam, in CallerMetadata callerMetadata,
            in IGetAdIdCallback callback);

    /**
    * Synchronous API to get AdId.
    */
    GetAdIdResult getAdIdSync();

    /**
     * Synchronous API to recreate a new AdId.
     */
    RecreateAdIdResult recreateAdId();

    /**
     * Synchronous API to delete AdId.
     */
    void deleteAdId();
}
