/*
 *  Copyright 2026 Curity AB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package io.curity.identityserver.plugin.backchannel.vipps

import se.curity.identityserver.sdk.errors.OAuthError

/**
 * Exception thrown when Vipps backchannel authentication fails
 *
 * @param error The OAuth error code returned by Vipps
 * @param errorDescription Optional error description from Vipps
 */
class VippsBackchannelException(
    val error: OAuthError,
    val errorDescription: String? = null
) : RuntimeException()

