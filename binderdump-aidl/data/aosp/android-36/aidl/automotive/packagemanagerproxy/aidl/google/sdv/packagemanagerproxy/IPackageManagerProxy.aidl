/*
 * Copyright (c) 2024, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package google.sdv.packagemanagerproxy;

/**
 * A proxy interface for the corresponding IPackageManagerNative APIs.
 * The Package Manager team has agreed to expose these interfaces as
 * stable in the future. This is an interim solution until they are
 * exposed.
 * @hide
 */
@VintfStability
interface IPackageManagerProxy {
    /**
     * Returns a set of names for the given UIDs.
     * IMPORTANT: Unlike the Java version of this API, unknown UIDs are
     * not represented by 'null's. Instead, they are represented by empty
     * strings.
     */
    @utf8InCpp String[] getNamesForUids(in int[] uids);

    /**
     * Return the UID associated with the given package name.
     * Note that the same package will have different UIDs under different UserHandle on
     * the same device.
     * @param packageName The full name (i.e. com.google.apps.contacts) of the desired package.
     * @param flags Additional option flags to modify the data returned.
     * @param userId The user handle identifier to look up the package under.
     * @return Returns an integer UID who owns the given package name, or -1 if no such package is
     *            available to the caller.
     */
    int getPackageUid(@utf8InCpp String packageName, long flags, int userId);

    /**
     * Returns the version code of the named package.
     * Unknown or unknowable versions are returned as 0.
     */
    long getVersionCodeForPackage(@utf8InCpp String packageName);
}
