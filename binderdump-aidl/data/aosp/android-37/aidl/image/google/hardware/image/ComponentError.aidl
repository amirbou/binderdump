/******************************************************************************
 *
 *  Copyright (C) 2026 Google LLC.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/
package google.hardware.image;

@VintfStability
@Backing(type="int")
enum ComponentError {
    /**
     * Given command is invalid (user error). For example, incorrect sequence of
     * commands or command not supported with this component type.
     */
    INVALID_COMMAND,
    /**
     * Given param is invalid (user error).
     */
    INVALID_PARAM,
    /**
     * Memory allocation failure due to insufficient memory.
     */
    OUT_OF_MEMORY,
    /**
     * Command did not complete within timeout.
     */
    TIMED_OUT,
    /**
     * Command failed for a reason not listed above.
     */
    FAILURE
}
