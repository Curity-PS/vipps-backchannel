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

import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.DEFAULT_SCOPE
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.GRANT_TYPE_CIBA
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.HEADER_AUTHORIZATION
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.PARAM_AUTH_REQ_ID
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.PARAM_BINDING_MESSAGE
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.PARAM_GRANT_TYPE
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.PARAM_LOGIN_HINT
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.PARAM_SCOPE
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.RESPONSE_AUTH_REQ_ID
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.RESPONSE_ERROR
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.RESPONSE_ERROR_DESCRIPTION
import io.curity.identityserver.plugins.oidc.OpenIdDiscoveryConfiguration
import io.curity.identityserver.plugins.oidc.OpenIdDiscoveryManagedObject
import java.net.URI
import java.util.Base64
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import se.curity.identityserver.sdk.errors.ErrorCode
import se.curity.identityserver.sdk.errors.OAuthError
import se.curity.identityserver.sdk.errors.OAuthError.access_denied
import se.curity.identityserver.sdk.errors.OAuthError.invalid_request
import se.curity.identityserver.sdk.errors.OAuthError.unknown_user_id
import se.curity.identityserver.sdk.http.HttpRequest
import se.curity.identityserver.sdk.http.HttpResponse
import se.curity.identityserver.sdk.service.WebServiceClient

/** Client for interacting with Vipps CIBA endpoints */
class VippsBackchannelClient(
        private val config: VippsAuthenticatorConfig,
        private val vippsManagedObject: OpenIdDiscoveryManagedObject<OpenIdDiscoveryConfiguration>
) {
    private val logger: Logger = LoggerFactory.getLogger(VippsBackchannelClient::class.java)
    private val json = config.json
    private val exceptionFactory = config.exceptionFactory
    private val basicAuthenticationHeader: String =
            createBasicAuthHeader(config.clientId, config.clientSecret)

    /**
     * Initiate a backchannel authentication request with Vipps
     *
     * @param loginHint The user identifier (phone number)
     * @param bindingMessage Optional binding message to display to user
     * @return The auth_req_id from Vipps
     */
    fun initiateBackchannelAuthentication(
            loginHint: String,
            scope: List<String>,
            bindingMessage: String?
    ): String {
        logger.debug("Initiating backchannel authentication for user: $loginHint")

        val scopeWithDefault = scope.toMutableList()
        if (!scopeWithDefault.contains(DEFAULT_SCOPE)) {
            logger.debug("Adding '$DEFAULT_SCOPE' to requested scopes since it was missing")
            scopeWithDefault.add(DEFAULT_SCOPE)
        }

        val requestBody =
                buildMap<String, Any> {
                    put(PARAM_LOGIN_HINT, loginHint)
                    put(PARAM_SCOPE, scopeWithDefault.joinToString(" "))
                    bindingMessage?.let { put(PARAM_BINDING_MESSAGE, it) }
                }

        val httpResponse =
                getWebserviceClientFor(vippsManagedObject.backChannelAuthenticationEndpoint)
                        .request()
                        .contentType("application/x-www-form-urlencoded")
                        .header(HEADER_AUTHORIZATION, basicAuthenticationHeader)
                        .body(HttpRequest.createFormUrlEncodedBodyProcessor(requestBody))
                        .post()
                        .response()

        return handleBackchannelAuthenticationResponse(httpResponse)
    }

    /**
     * Poll the token endpoint to check authentication status
     *
     * @param authReqId The auth_req_id from the initial backchannel authentication request
     * @return Map containing the response data (may include tokens or error information)
     */
    fun pollTokenEndpoint(authReqId: String): Map<String, Any> {
        logger.debug("Polling token endpoint for auth_req_id: $authReqId")

        val requestBody = buildMap {
            put(PARAM_GRANT_TYPE, GRANT_TYPE_CIBA)
            put(PARAM_AUTH_REQ_ID, authReqId)
        }

        val httpResponse =
                getWebserviceClientFor(vippsManagedObject.tokenEndpoint)
                        .request()
                        .contentType("application/x-www-form-urlencoded")
                        .header(HEADER_AUTHORIZATION, basicAuthenticationHeader)
                        .body(HttpRequest.createFormUrlEncodedBodyProcessor(requestBody))
                        .post()
                        .response()

        return handleTokenResponse(httpResponse)
    }

    /**
     * Fetch user claims from the userinfo endpoint
     *
     * @param accessToken The access token received from the token endpoint
     * @return Map containing user claims (sub, name, email, etc.)
     */
    fun fetchUserInfo(accessToken: String): Map<String, Any> {
        logger.debug("Fetching user info from userinfo endpoint")

        val userInfoEndpoint = vippsManagedObject.getConfigurationValueOfType(
                URI::class.java,
                "userinfo_endpoint"
        )

        val httpResponse =
                getWebserviceClientFor(userInfoEndpoint)
                        .request()
                        .header(HEADER_AUTHORIZATION, "Bearer $accessToken")
                        .get()
                        .response()

        return handleUserInfoResponse(httpResponse)
    }

    private fun handleBackchannelAuthenticationResponse(httpResponse: HttpResponse): String {
        val statusCode = httpResponse.statusCode()
        val responseBody = httpResponse.body(HttpResponse.asString())

        logger.debug("Backchannel authentication response: status = {}, body = {}",
                statusCode, responseBody)

        return when (statusCode) {
            200 -> {
                val responseMap = json.fromJson(responseBody)
                responseMap[RESPONSE_AUTH_REQ_ID] as? String
                        ?: throw exceptionFactory.internalServerException(
                                ErrorCode.EXTERNAL_SERVICE_ERROR,
                                "Missing auth_req_id in response"
                        )
            }
            in 400..499 -> {
                // Parse error response from Vipps
                val errorResponse = json.fromJson(responseBody)
                val errorDescription = errorResponse[RESPONSE_ERROR_DESCRIPTION] as? String
                when (errorResponse[RESPONSE_ERROR]) {
                    unknown_user_id.toString() -> {
                        logger.debug("Vipps backchannel authentication failed: invalid user")
                        throw VippsBackchannelException(unknown_user_id, errorDescription)
                    }
                    invalid_request.toString() -> {
                        logger.debug("Vipps backchannel authentication failed: invalid request")
                        throw VippsBackchannelException(invalid_request, errorDescription)
                    }
                    else -> throw VippsBackchannelException(access_denied, errorDescription)
                }

            }
            else -> {
                logger.warn(
                        "Unexpected response code $statusCode from Vipps backchannel authentication endpoint"
                )
                throw VippsBackchannelException(invalid_request, "Unexpected response from Vipps")
            }
        }
    }

    private fun handleTokenResponse(httpResponse: HttpResponse): Map<String, Any> {
        val statusCode = httpResponse.statusCode()
        val responseBody = httpResponse.body(HttpResponse.asString())

        logger.debug("Token response: status = {}, body = {}", statusCode, responseBody)

        return when (statusCode) {
            200 -> json.fromJson(responseBody)
            400 -> {
                // CIBA polling errors are returned as 400 with error codes
                val errorResponse = json.fromJson(responseBody)
                if (errorResponse.containsKey(RESPONSE_ERROR)) {
                    errorResponse
                } else {
                    throw exceptionFactory.badRequestException(ErrorCode.INVALID_INPUT)
                }
            }
            in 401..499 ->
                    throw exceptionFactory.unauthorizedException(ErrorCode.AUTHENTICATION_FAILED)
            else -> {
                logger.warn("Unexpected response code $statusCode from Vipps token endpoint")
                throw exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR)
            }
        }
    }

    private fun handleUserInfoResponse(httpResponse: HttpResponse): Map<String, Any> {
        val statusCode = httpResponse.statusCode()
        val responseBody = httpResponse.body(HttpResponse.asString())

        logger.debug("UserInfo response: status = {}, body = {}", statusCode, responseBody)

        return when (statusCode) {
            200 -> json.fromJson(responseBody)
            401, 403 -> {
                logger.warn("Access denied to userinfo endpoint: $statusCode")
                throw exceptionFactory.unauthorizedException(ErrorCode.AUTHENTICATION_FAILED)
            }
            else -> {
                logger.warn("Unexpected response code $statusCode from Vipps userinfo endpoint")
                throw exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR)
            }
        }
    }

    private fun getWebserviceClientFor(uri: URI): WebServiceClient {
        logger.debug("Creating WebServiceClient for URI: {}", uri)
        return config.webServiceClientFactory
                .create(vippsManagedObject.httpClient)
                .withHost("${uri.host}:${uri.port}")
                .withPath(uri.path)
    }

    private fun createBasicAuthHeader(clientId: String, clientSecret: String): String {
        val credentials = "$clientId:$clientSecret".toByteArray()
        return "Basic ${Base64.getEncoder().encodeToString(credentials)}"
    }
}
