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

import io.curity.identityserver.plugins.oidc.OpenIdDiscoveryConfiguration
import se.curity.identityserver.sdk.config.Configuration
import se.curity.identityserver.sdk.config.annotation.Description
import se.curity.identityserver.sdk.config.annotation.Suggestions
import se.curity.identityserver.sdk.service.ExceptionFactory
import se.curity.identityserver.sdk.service.HttpClient
import se.curity.identityserver.sdk.service.Json
import se.curity.identityserver.sdk.service.SessionManager
import se.curity.identityserver.sdk.service.WebServiceClientFactory
import java.net.URI
import java.util.Optional

interface VippsAuthenticatorConfig : Configuration
{
    @get:Description("The client ID registered with Vipps")
    val clientId: String

    @get:Description("The client secret for Vipps")
    val clientSecret: String

    @get:Description("The extra scopes to request from Vipps, openid will always be included")
    val scopes: List<@Suggestions("nin") String>

    val openidConfiguration: OpenIdDiscoveryConfiguration

    val sessionManager: SessionManager

    val exceptionFactory: ExceptionFactory

    val json: Json

    val webServiceClientFactory: WebServiceClientFactory
}
