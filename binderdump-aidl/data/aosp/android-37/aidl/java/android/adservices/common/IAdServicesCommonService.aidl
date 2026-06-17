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

package android.adservices.common;


import android.adservices.common.AdServicesStates;
import android.adservices.common.UpdateAdServicesModuleStatesParams;
import android.adservices.common.UpdateAdServicesUserChoicesParams;

import android.adservices.common.CallerMetadata;
import android.adservices.common.GetAdServicesCommonStatesParams;
import android.adservices.common.IAdServicesCommonCallback;
import android.adservices.common.IAdsPersonalizationCallback;
import android.adservices.common.IAdServicesCommonStatesCallback;
import android.adservices.common.IEnableAdServicesCallback;
import android.adservices.common.IRequestAdServicesModuleOverridesCallback;
import android.adservices.common.IRequestAdServicesModuleUserChoicesCallback;
import android.adservices.common.IGetAdServicesModuleStatesCallback;
import android.adservices.common.IGetAdServicesUserChoicesCallback;
import android.adservices.common.IUpdateAdIdCallback;

import android.adservices.common.UpdateAdIdRequest;
import android.net.Uri;

/**
 * Common AdServices service.
 * @hide
 * @deprecated The Rubidium (Rb) Relevance APIs, including those in android.adservices.common, are
 *     being deprecated. Relevance APIs have no direct replacement. Developers should stop using
 *     them, as calls will be rejected in future Android releases. Please refer to official Privacy
 *     Sandbox documentation for deprecation and roadmap details:
 *     https://privacysandbox.com/news/update-on-plans-for-privacy-sandbox-technologies/
 */
interface IAdServicesCommonService {

    void isAdServicesEnabled(in IAdServicesCommonCallback callback);

    void setAdServicesEnabled(
            in boolean adServicesEntryPointEnabled,
            in boolean adIdEnabled);

    void enableAdServices(in AdServicesStates adServicesStates, in IEnableAdServicesCallback callback);

    void updateAdIdCache(in UpdateAdIdRequest adIdUpdateRequest, in IUpdateAdIdCallback callback);

    void getAdServicesCommonStates(
        in GetAdServicesCommonStatesParams params,
        in CallerMetadata callerMetadata,
        in IAdServicesCommonStatesCallback callback);

    void requestAdServicesModuleOverrides(
        in UpdateAdServicesModuleStatesParams params,
        in IRequestAdServicesModuleOverridesCallback callback);

    void requestAdServicesModuleUserChoices(
        in UpdateAdServicesUserChoicesParams params,
        in IRequestAdServicesModuleUserChoicesCallback callback);

    void setAdsPersonalizationStatus(
        in int adsPersonalizationStatus,
        in IAdsPersonalizationCallback callback);

    void getAdServicesModuleStates(
        in IGetAdServicesModuleStatesCallback callback);

    void getAdServicesModuleUserChoices(
        in IGetAdServicesUserChoicesCallback callback);
}
