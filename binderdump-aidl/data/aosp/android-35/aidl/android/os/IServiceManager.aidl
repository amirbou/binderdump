/*
 * Copyright (C) 2006 The Android Open Source Project
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

import android.os.IClientCallback;
import android.os.IServiceCallback;
import android.os.Service;
import android.os.ServiceDebugInfo;
import android.os.ConnectionInfo;

/**
 * Basic interface for finding and publishing system services.
 *
 * @hide
 */
interface IServiceManager {
    /*
     * Must update values in IServiceManager.h
     */
    /* Allows services to dump sections according to priorities. */
    const int DUMP_FLAG_PRIORITY_CRITICAL = 1;
    const int DUMP_FLAG_PRIORITY_HIGH = 2;
    const int DUMP_FLAG_PRIORITY_NORMAL = 4;
    const int DUMP_FLAG_PRIORITY_DEFAULT = 8;
    const int DUMP_FLAG_PRIORITY_ALL = 15;
    const int DUMP_FLAG_PROTO = 16;

    /* Allows services to be registered as part of a static set of services that are always running.
     * Services in this set are not allowed to be dynamically restarted on demand.
     */
    const int FLAG_IS_LAZY_SERVICE = 1;

    /**
     * Retrieve an existing service called @a name from the
     * service manager.
     *
     * Returns null if the service does not exist.
     *
     * @deprecated use getService2 instead. There is no benefit to using this.
     */
    @nullable IBinder getService(@utf8InCpp String name);

    /**
     * Retrieves an existing service called @a name from the service manager.
     */
    Service getService2(@utf8InCpp String name);

    /**
     * Retrieves an existing service called @a name from the service manager.
     * Non-blocking.
     */
    Service checkService(@utf8InCpp String name);

    /**
     * Place a new @a service called @a name into the service manager.
     */
    void addService(@utf8InCpp String name, IBinder service,
        boolean allowIsolated, int dumpPriority);

    /**
     * Return a list of all currently running services.
     */
    @utf8InCpp String[] listServices(int dumpPriority);

    /**
     * Request a callback when a service is registered.
     */
    void registerForNotifications(@utf8InCpp String name, IServiceCallback callback);

    /**
     * Unregisters all requests for notifications for a specific callback.
     */
    void unregisterForNotifications(@utf8InCpp String name, IServiceCallback callback);

    /**
     * Returns whether a given interface is declared on the device, even if it
     * is not started yet.
     */
    boolean isDeclared(@utf8InCpp String name);

    /**
     * Returns all declared instances for a particular interface.
     */
    @utf8InCpp String[] getDeclaredInstances(@utf8InCpp String iface);

    /**
     * If updatable-via-apex, returns the APEX via which this is updated.
     */
    @nullable @utf8InCpp String updatableViaApex(@utf8InCpp String name);

    /**
     * Returns all instances which are updatable via the APEX. Instance names are fully qualified
     * like `pack.age.IFoo/default`.
     */
    @utf8InCpp String[] getUpdatableNames(@utf8InCpp String apexName);

    /**
     * If connection info is available for the given instance, returns the ConnectionInfo
     */
    @nullable ConnectionInfo getConnectionInfo(@utf8InCpp String name);

    /**
     * Request a callback when the number of clients of the service changes.
     */
    void registerClientCallback(@utf8InCpp String name, IBinder service, IClientCallback callback);

    /**
     * Attempt to unregister and remove a service. Will fail if the service is still in use.
     */
    void tryUnregisterService(@utf8InCpp String name, IBinder service);

    /**
     * Get debug information for all currently registered services.
     */
    ServiceDebugInfo[] getServiceDebugInfo();
}
