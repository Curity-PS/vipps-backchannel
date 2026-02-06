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

import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.Companion.ERROR_ACCESS_DENIED
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.Companion.ERROR_AUTHORIZATION_PENDING
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.Companion.ERROR_EXPIRED_TOKEN
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.Companion.ERROR_SLOW_DOWN
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.Companion.RESPONSE_ACCESS_TOKEN
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.Companion.RESPONSE_ERROR
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.Companion.RESPONSE_ID_TOKEN
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.Companion.SESSION_ACCESS_TOKEN
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.Companion.SESSION_AUTH_REQ_ID
import io.curity.identityserver.plugins.attributes.ValidatedJwtAttributes
import io.curity.identityserver.plugins.oidc.OpenIdDiscoveryConfiguration
import io.curity.identityserver.plugins.oidc.OpenIdDiscoveryManagedObject
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import se.curity.identityserver.sdk.attribute.Attribute
import se.curity.identityserver.sdk.attribute.AuthenticationAttributes
import se.curity.identityserver.sdk.attribute.ContextAttributes
import se.curity.identityserver.sdk.attribute.SubjectAttributes
import se.curity.identityserver.sdk.authentication.BackchannelAuthenticationHandler
import se.curity.identityserver.sdk.authentication.BackchannelAuthenticationRequest
import se.curity.identityserver.sdk.authentication.BackchannelAuthenticationResult
import se.curity.identityserver.sdk.authentication.BackchannelAuthenticatorState
import se.curity.identityserver.sdk.authentication.BackchannelStartAuthenticationResult
import java.util.Optional

/**
 * Backchannel authentication handler for Vipps CIBA flow
 */
class VippsBackchannelAuthenticationHandler(
    private val config: VippsAuthenticatorConfig,
    private val vippsOpenIdManagedObject: OpenIdDiscoveryManagedObject<OpenIdDiscoveryConfiguration>,
) : BackchannelAuthenticationHandler {
    private val _logger: Logger = LoggerFactory.getLogger(VippsBackchannelAuthenticationHandler::class.java)
    private val _sessionManager = config.sessionManager
    private val _client: VippsBackchannelClient = VippsBackchannelClient(config, vippsOpenIdManagedObject)

    /**
     * Start the backchannel authentication flow with Vipps
     *
     * @param authReqId The Curity authentication request ID
     * @param authRequest The backchannel authentication request containing subject and binding message
     * @return Result indicating success or failure
     */
    override fun startAuthentication(
        authReqId: String,
        authRequest: BackchannelAuthenticationRequest
    ): BackchannelStartAuthenticationResult {
        _logger.debug("Starting Vipps backchannel authentication for subject: ${authRequest.subject}")

        return try {
            // Initiate backchannel authentication with Vipps
            val vippsAuthReqId = _client.initiateBackchannelAuthentication(
                authRequest.subject, config.scopes, authRequest.bindingMessage,
            )

            // Store the Vipps auth_req_id in session
            _sessionManager.put(Attribute.of(SESSION_AUTH_REQ_ID, vippsAuthReqId))

            _logger.debug("Vipps backchannel authentication started successfully with auth_req_id: $vippsAuthReqId")
            BackchannelStartAuthenticationResult.ok()
        } catch (e: RuntimeException) {
            _logger.warn("Failed to start Vipps backchannel authentication: ${e.message}", e)
            BackchannelStartAuthenticationResult.error(
                "server_error",
                "Failed to initiate Vipps authentication"
            )
        }
    }

    /**
     * Check the status of an ongoing authentication request
     *
     * @param authReqId The Curity authentication request ID
     * @return Result containing authentication status and attributes (if successful)
     */
    override fun checkAuthenticationStatus(authReqId: String): Optional<BackchannelAuthenticationResult> {
        _logger.debug("Checking Vipps authentication status for authReqId: $authReqId")

        val vippsAuthReqIdAttr = _sessionManager.get(SESSION_AUTH_REQ_ID)
            ?: return Optional.of(BackchannelAuthenticationResult(null, BackchannelAuthenticatorState.UNKNOWN))

        val vippsAuthReqId = vippsAuthReqIdAttr.value.toString()

        return try {
            val response = _client.pollTokenEndpoint(vippsAuthReqId)
            Optional.of(processTokenResponse(response))
        } catch (e: RuntimeException) {
            _logger.warn("Error checking authentication status: ${e.message}", e)
            Optional.of(BackchannelAuthenticationResult(null, BackchannelAuthenticatorState.UNKNOWN))
        }
    }

    /**
     * Cancel an ongoing authentication request
     *
     * @param authReqId The Curity authentication request ID
     */
    override fun cancelAuthenticationRequest(authReqId: String) {
        _logger.debug("Canceling Vipps authentication for authReqId: $authReqId")

        // Clean up session data
        clearSession()
    }

    /**
     * Process the token endpoint response and determine authentication state
     */
    private fun processTokenResponse(response: Map<String, Any>): BackchannelAuthenticationResult {
        return when (val error = response[RESPONSE_ERROR]?.toString()) {
            null -> {
                // Success - tokens received
                val idToken = response[RESPONSE_ID_TOKEN]?.toString()
                val accessToken = response[RESPONSE_ACCESS_TOKEN]?.toString()

                if (idToken == null) {
                    _logger.warn("Token response missing id_token")
                    return BackchannelAuthenticationResult(null, BackchannelAuthenticatorState.FAILED)
                }
                val contextAttributes =
                    if (accessToken != null) mapOf("vipps_access_token" to accessToken) else emptyMap()

                // Extract subject from ID token or use access_token as proof of authentication
                val validatedAttributes = validateIdToken(idToken)

                val authenticationAttributes = AuthenticationAttributes.of(
                    SubjectAttributes.of(
                        validatedAttributes.subject,
                        validatedAttributes.removeAttributes(setOf("sub", "aud", "iss", "azp", "iat", "exp", "nonce"))
                    ),
                    ContextAttributes.of(contextAttributes),
                )

                // Clean up session
                clearSession()

                BackchannelAuthenticationResult(authenticationAttributes, BackchannelAuthenticatorState.SUCCEEDED)
            }

            ERROR_AUTHORIZATION_PENDING -> {
                _logger.debug("Authorization still pending")
                BackchannelAuthenticationResult(null, BackchannelAuthenticatorState.STARTED)
            }

            ERROR_SLOW_DOWN -> {
                _logger.debug("Slow down requested")
                BackchannelAuthenticationResult(null, BackchannelAuthenticatorState.STARTED)
            }

            ERROR_EXPIRED_TOKEN -> {
                _logger.info("Authentication request expired")
                clearSession()
                BackchannelAuthenticationResult(null, BackchannelAuthenticatorState.EXPIRED)
            }

            ERROR_ACCESS_DENIED -> {
                _logger.debug("User denied authentication")
                clearSession()
                BackchannelAuthenticationResult(null, BackchannelAuthenticatorState.FAILED)
            }

            else -> {
                _logger.warn("Unknown error from Vipps token endpoint: $error")
                BackchannelAuthenticationResult(null, BackchannelAuthenticatorState.UNKNOWN)
            }
        }
    }

    private fun clearSession() {
        _sessionManager.remove(SESSION_AUTH_REQ_ID)
        _sessionManager.remove(SESSION_ACCESS_TOKEN)
    }

    /**
     * Validate the ID token received from Vipps and extract subject and attributes
     */
    private fun validateIdToken(idToken: String): ValidatedJwtAttributes {
        return vippsOpenIdManagedObject.jwtValidator.validateJwt(
            idToken,
            vippsOpenIdManagedObject.getConfigurationValueOfType(String::class.java, "issuer"),
            config.clientId
        )
    }
}
