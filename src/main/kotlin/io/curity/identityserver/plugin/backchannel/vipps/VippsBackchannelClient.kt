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

import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.Companion.DEFAULT_SCOPE
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.Companion.GRANT_TYPE_CIBA
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.Companion.HEADER_AUTHORIZATION
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.Companion.MSISDN_PREFIX
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.Companion.PARAM_AUTH_REQ_ID
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.Companion.PARAM_BINDING_MESSAGE
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.Companion.PARAM_GRANT_TYPE
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.Companion.PARAM_LOGIN_HINT
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.Companion.PARAM_SCOPE
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.Companion.RESPONSE_AUTH_REQ_ID
import io.curity.identityserver.plugin.backchannel.vipps.VippsConstants.Companion.RESPONSE_ERROR
import io.curity.identityserver.plugins.oidc.OpenIdDiscoveryConfiguration
import io.curity.identityserver.plugins.oidc.OpenIdDiscoveryManagedObject
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import se.curity.identityserver.sdk.errors.ErrorCode
import se.curity.identityserver.sdk.http.HttpRequest
import se.curity.identityserver.sdk.http.HttpResponse
import se.curity.identityserver.sdk.service.WebServiceClient
import java.net.URI
import java.util.Base64

/** Client for interacting with Vipps CIBA endpoints */
class VippsBackchannelClient(
    private val _config: VippsAuthenticatorConfig,
    private val _vippsManagedObject: OpenIdDiscoveryManagedObject<OpenIdDiscoveryConfiguration>
) {
    private val _logger: Logger = LoggerFactory.getLogger(VippsBackchannelClient::class.java)
    private val _json = _config.json
    private val _exceptionFactory = _config.exceptionFactory
    private val _basicAuthenticationHeader: String =
        "Basic " +
                Base64.getEncoder()
                    .encodeToString(
                        "${_config.clientId}:${_config.clientSecret}".toByteArray()
                    )

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
        _logger.debug("Initiating backchannel authentication for user: $loginHint")

        val formattedLoginHint = if (loginHint.startsWith(MSISDN_PREFIX)) {
            loginHint
        } else {
            _logger.debug("Converting login_hint to MSISDN format: $loginHint -> $MSISDN_PREFIX$loginHint")
            "$MSISDN_PREFIX$loginHint"
        }

        val scopeWithDefault = scope.toMutableList()
        if (!scopeWithDefault.contains(DEFAULT_SCOPE)) {
            _logger.debug("Adding '$DEFAULT_SCOPE' to requested scopes since it was missing")
            scopeWithDefault.add(DEFAULT_SCOPE)
        }

        val requestBody =
            buildMap<String, Any> {
                put(PARAM_LOGIN_HINT, formattedLoginHint)
                put(PARAM_SCOPE, scopeWithDefault.joinToString(" "))
                bindingMessage?.let { put(PARAM_BINDING_MESSAGE, it) }
            }

        val httpResponse =
            getWebserviceClientFor(_vippsManagedObject.backChannelAuthenticationEndpoint)
                .request()
                .contentType("application/x-www-form-urlencoded")
                .header(HEADER_AUTHORIZATION, _basicAuthenticationHeader)
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
        _logger.debug("Polling token endpoint for auth_req_id: $authReqId")

        val requestBody = buildMap {
            put(PARAM_GRANT_TYPE, GRANT_TYPE_CIBA)
            put(PARAM_AUTH_REQ_ID, authReqId)
        }

        val httpResponse = getWebserviceClientFor(_vippsManagedObject.tokenEndpoint)
            .request()
            .contentType("application/x-www-form-urlencoded")
            .header(HEADER_AUTHORIZATION, _basicAuthenticationHeader)
            .body(HttpRequest.createFormUrlEncodedBodyProcessor(requestBody))
            .post()
            .response()

        return handleTokenResponse(httpResponse)
    }

    private fun handleBackchannelAuthenticationResponse(httpResponse: HttpResponse): String {
        val statusCode = httpResponse.statusCode()
        val responseBody = httpResponse.body(HttpResponse.asString())

        _logger.debug(
            "Backchannel authentication response: status = {}, body = {}",
            statusCode,
            responseBody
        )

        return when (statusCode) {
            200 -> {
                val responseMap = _json.fromJson(responseBody)
                responseMap[RESPONSE_AUTH_REQ_ID]?.toString()
                    ?: throw _exceptionFactory.internalServerException(
                        ErrorCode.EXTERNAL_SERVICE_ERROR,
                        "Missing auth_req_id in response"
                    )
            }

            in 400..499 -> {
                throw _exceptionFactory.unauthorizedException(ErrorCode.AUTHENTICATION_FAILED)
            }

            else -> {
                _logger.warn(
                    "Unexpected response code $statusCode from Vipps backchannel authentication endpoint"
                )
                throw _exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR)
            }
        }
    }

    private fun handleTokenResponse(httpResponse: HttpResponse): Map<String, Any> {
        val statusCode = httpResponse.statusCode()
        val responseBody = httpResponse.body(HttpResponse.asString())

        _logger.debug("Token response: status = {}, body = {}", statusCode, responseBody)

        return when (statusCode) {
            200 -> _json.fromJson(responseBody)
            400 -> {
                // CIBA polling errors are returned as 400 with error codes
                val errorResponse = _json.fromJson(responseBody)
                if (errorResponse.containsKey(RESPONSE_ERROR)) {
                    errorResponse
                } else {
                    throw _exceptionFactory.badRequestException(ErrorCode.INVALID_INPUT)
                }
            }

            in 401..499 ->
                throw _exceptionFactory.unauthorizedException(ErrorCode.AUTHENTICATION_FAILED)

            else -> {
                _logger.warn("Unexpected response code $statusCode from Vipps token endpoint")
                throw _exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR)
            }
        }
    }

    fun getWebserviceClientFor(uri: URI): WebServiceClient {
        _logger.debug("Creating WebServiceClient for URI: {}", uri)
        return _config.webServiceClientFactory
            .create(_vippsManagedObject.httpClient)
            .withHost("${uri.host}:${uri.port}")
            .withPath(uri.path)
    }
}
