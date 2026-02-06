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

import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.ERROR_ACCESS_DENIED
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.ERROR_AUTHORIZATION_PENDING
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.ERROR_EXPIRED_TOKEN
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.ERROR_SLOW_DOWN
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.RESPONSE_ACCESS_TOKEN
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.RESPONSE_ERROR
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.RESPONSE_ID_TOKEN
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.SESSION_ACCESS_TOKEN
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.SESSION_AUTH_REQ_ID
import io.curity.identityserver.plugins.attributes.ValidatedJwtAttributes
import io.curity.identityserver.plugins.oidc.OpenIdDiscoveryConfiguration
import io.curity.identityserver.plugins.oidc.OpenIdDiscoveryManagedObject
import java.util.Optional
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

/** Backchannel authentication handler for Vipps CIBA flow */
class VippsBackchannelAuthenticationHandler(
        private val config: VippsAuthenticatorConfig,
        private val vippsOpenIdManagedObject:
                OpenIdDiscoveryManagedObject<OpenIdDiscoveryConfiguration>,
) : BackchannelAuthenticationHandler {
    private val logger: Logger =
            LoggerFactory.getLogger(VippsBackchannelAuthenticationHandler::class.java)
    private val sessionManager = config.sessionManager
    private val client: VippsBackchannelClient =
            VippsBackchannelClient(config, vippsOpenIdManagedObject)

    private val STANDARD_JWT_CLAIMS = setOf("sub", "aud", "iss", "azp", "iat", "exp", "nonce")

    /**
     * Start the backchannel authentication flow with Vipps
     *
     * @param authReqId The Curity authentication request ID
     * @param authRequest The backchannel authentication request containing subject and binding
     * message
     * @return Result indicating success or failure
     */
    override fun startAuthentication(
            authReqId: String,
            authRequest: BackchannelAuthenticationRequest
    ): BackchannelStartAuthenticationResult {
        logger.debug(
                "Starting Vipps backchannel authentication for subject: ${authRequest.subject}"
        )

        return try {
            // Initiate backchannel authentication with Vipps
            val vippsAuthReqId =
                    client.initiateBackchannelAuthentication(
                            authRequest.subject,
                            config.scopes,
                            authRequest.bindingMessage,
                    )

            // Store the Vipps auth_req_id in session
            sessionManager.put(Attribute.of(SESSION_AUTH_REQ_ID, vippsAuthReqId))

            logger.debug(
                    "Vipps backchannel authentication started successfully with auth_req_id: $vippsAuthReqId"
            )
            BackchannelStartAuthenticationResult.ok()
        } catch (e: RuntimeException) {
            logger.warn("Failed to start Vipps backchannel authentication: ${e.message}", e)
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
    override fun checkAuthenticationStatus(
            authReqId: String
    ): Optional<BackchannelAuthenticationResult> {
        logger.debug("Checking Vipps authentication status for authReqId: $authReqId")

        val vippsAuthReqIdAttr =
                sessionManager.get(SESSION_AUTH_REQ_ID)
                        ?: return Optional.of(
                                        BackchannelAuthenticationResult(
                                                null,
                                                BackchannelAuthenticatorState.UNKNOWN
                                        )
                                )
                                .also {
                                    logger.debug(
                                            "No auth_req_id found in session for authReqId: $authReqId"
                                    )
                                }

        val vippsAuthReqId = vippsAuthReqIdAttr.value.toString()

        return try {
            val response = client.pollTokenEndpoint(vippsAuthReqId)
            Optional.of(processTokenResponse(response))
        } catch (e: RuntimeException) {
            logger.warn("Error checking authentication status: ${e.message}", e)
            Optional.of(
                    BackchannelAuthenticationResult(null, BackchannelAuthenticatorState.UNKNOWN)
            )
        }
    }

    /**
     * Cancel an ongoing authentication request
     *
     * @param authReqId The Curity authentication request ID
     */
    override fun cancelAuthenticationRequest(authReqId: String) {
        logger.debug("Canceling Vipps authentication for authReqId: $authReqId")

        // Clean up session data
        clearSession()
    }

    /** Process the token endpoint response and determine authentication state */
    private fun processTokenResponse(response: Map<String, Any>): BackchannelAuthenticationResult {
        val error = response[RESPONSE_ERROR]?.toString()

        return when {
            error == null -> handleSuccessfulAuthentication(response)
            error in listOf(ERROR_AUTHORIZATION_PENDING, ERROR_SLOW_DOWN) ->
                    handlePendingAuthentication(error)
            error == ERROR_EXPIRED_TOKEN -> handleExpiredAuthentication()
            error == ERROR_ACCESS_DENIED -> handleDeniedAuthentication()
            else -> handleUnknownError(error)
        }
    }

    private fun handleSuccessfulAuthentication(
            response: Map<String, Any>
    ): BackchannelAuthenticationResult {
        val idToken =
                response[RESPONSE_ID_TOKEN]?.toString()
                        ?: run {
                            logger.warn("Token response missing id_token")
                            return BackchannelAuthenticationResult(
                                    null,
                                    BackchannelAuthenticatorState.FAILED
                            )
                        }

        val accessToken = response[RESPONSE_ACCESS_TOKEN]?.toString()
        val contextAttributes = accessToken?.let { mapOf("vipps_access_token" to it) } ?: emptyMap()

        val validatedAttributes = validateIdToken(idToken)
        val authenticationAttributes =
                AuthenticationAttributes.of(
                        SubjectAttributes.of(
                                validatedAttributes.subject,
                                validatedAttributes.removeAttributes(STANDARD_JWT_CLAIMS)
                        ),
                        ContextAttributes.of(contextAttributes),
                )

        clearSession()
        return BackchannelAuthenticationResult(
                authenticationAttributes,
                BackchannelAuthenticatorState.SUCCEEDED
        )
    }

    private fun handlePendingAuthentication(error: String): BackchannelAuthenticationResult {
        logger.debug(
                if (error == ERROR_SLOW_DOWN) "Slow down requested"
                else "Authorization still pending"
        )
        return BackchannelAuthenticationResult(null, BackchannelAuthenticatorState.STARTED)
    }

    private fun handleExpiredAuthentication(): BackchannelAuthenticationResult {
        logger.info("Authentication request expired")
        clearSession()
        return BackchannelAuthenticationResult(null, BackchannelAuthenticatorState.EXPIRED)
    }

    private fun handleDeniedAuthentication(): BackchannelAuthenticationResult {
        logger.debug("User denied authentication")
        clearSession()
        return BackchannelAuthenticationResult(null, BackchannelAuthenticatorState.FAILED)
    }

    private fun handleUnknownError(error: String): BackchannelAuthenticationResult {
        logger.warn("Unknown error from Vipps token endpoint: $error")
        return BackchannelAuthenticationResult(null, BackchannelAuthenticatorState.UNKNOWN)
    }

    private fun clearSession() {
        sessionManager.remove(SESSION_AUTH_REQ_ID)
        sessionManager.remove(SESSION_ACCESS_TOKEN)
    }

    /** Validate the ID token received from Vipps and extract subject and attributes */
    private fun validateIdToken(idToken: String): ValidatedJwtAttributes {
        return vippsOpenIdManagedObject.jwtValidator.validateJwt(
                idToken,
                vippsOpenIdManagedObject.getConfigurationValueOfType(String::class.java, "issuer"),
                config.clientId
        )
    }
}
