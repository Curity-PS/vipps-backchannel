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

package io.curity.identityserver.plugin.backchannel.vipps.integration

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder
import com.github.tomakehurst.wiremock.client.WireMock
import com.github.tomakehurst.wiremock.core.WireMockConfiguration
import com.github.tomakehurst.wiremock.extension.ResponseDefinitionTransformerV2
import com.github.tomakehurst.wiremock.http.ResponseDefinition
import com.github.tomakehurst.wiremock.stubbing.Scenario
import com.github.tomakehurst.wiremock.stubbing.ServeEvent
import groovy.json.JsonOutput
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.testcontainers.Testcontainers

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse
import static com.github.tomakehurst.wiremock.client.WireMock.get
import static com.github.tomakehurst.wiremock.client.WireMock.post
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo
/**
 * Mock Vipps service backed by WireMock.
 *
 * Provides stubs for the Vipps OpenID Connect discovery endpoint and the
 * backchannel authentication (CIBA) endpoint so that integration tests can
 * run without reaching the real Vipps API.
 *
 * The token endpoint dynamically inspects incoming requests: the {@code sub}
 * claim in the ID token is taken from the {@code login_hint} sent in the
 * bc-authorize request, and the {@code aud} claim is the {@code client_id}
 * from the Basic auth header on the token request.
 *
 * Usage:
 * <pre>
 * def vipps = new MockVippsService()
 * vipps.start()
 * // … start Curity container, run tests …
 * vipps.stop()
 * </pre>
 */
class MockVippsService {

    private static final String BASE_PATH = "/access-management-1.0/access"
    private static final int DEFAULT_PORT = 8888
    private static final String BC_AUTHORIZE_TRANSFORMER = "bc-authorize-capture"
    private static final String TOKEN_TRANSFORMER = "ciba-token-transformer"
    private static final String USERINFO_TRANSFORMER = "userinfo-transformer"
    private static  Logger _logger= LoggerFactory.getLogger(MockVippsService.class)


    private final int port
    private WireMockServer server

    /** Maps auth_req_id to login_hint (subject) */
    private static final Map<String, String> authnRequests = [:].asSynchronized()
    /** Maps access_token to login_hint (subject) for userinfo lookups */
    private static final Map<String, String> accessTokens = [:].asSynchronized()
    private static final Set<String> registeredUsers = ([] as Set).asSynchronized()

    private static final MSISDN_PATTERN = ~/^urn:msisdn:(46|45|47|358|299)\d+$/

    MockVippsService(int port = DEFAULT_PORT) {
        this.port = port
    }

    /**
     * Register a user so that the mock will accept bc-authorize requests for
     * this {@code login_hint}. The hint must be in {@code urn:msisdn:} format.
     */
    void registerUser(String loginHint) {
        registeredUsers.add(loginHint)
    }

    /**
     * Start the mock service and expose the port to Testcontainers.
     *
     * Automatically registers the OpenID Connect discovery stub so the
     * Curity container can resolve endpoints on startup.
     */
    void start() {
        server = new WireMockServer(WireMockConfiguration.options()
            .port(port)
            .extensions(new BcAuthorizeCaptureTransformer(), new CibaTokenTransformer(), new UserInfoTransformer()))
        server.start()
        WireMock.configureFor("localhost", port)

        Testcontainers.exposeHostPorts(port)

        stubDiscoveryEndpoint()
    }

    void stop() {
        server?.stop()
    }

    /** Reset recorded requests between tests while keeping stubs intact. */
    void resetRequests() {
        server.resetRequests()
        authnRequests.clear()
        accessTokens.clear()
        registeredUsers.clear()
    }

    /** Remove all stubs and requests, then re-register the discovery stub. */
    void reset() {
        server.resetAll()
        authnRequests.clear()
        accessTokens.clear()
        registeredUsers.clear()
        stubDiscoveryEndpoint()
    }

    /**
     * The base URL that the Curity container should use to reach this mock.
     * Uses the special Testcontainers hostname so traffic from inside a
     * container is routed to the host machine.
     */
    String getContainerBaseUrl() {
        "http://host.testcontainers.internal:${port}${BASE_PATH}"
    }

    // ------------------------------------------------------------------ stubs

    /**
     * Stub a successful backchannel authentication (CIBA) response.
     *
     * The {@code login_hint} from the request body is captured so that it
     * can be used as the {@code sub} claim in the ID token returned by the
     * token endpoint.
     *
     * @param authReqId  The {@code auth_req_id} to return
     * @param expiresIn  Lifetime in seconds (default 600)
     * @param interval   Polling interval in seconds (default 5)
     */
    void stubStartAuthentication(String authReqId = "VYGaaAMRkI6SyAm_uIywhxsN2K0",
                                 int expiresIn = 600,
                                 int interval = 5) {
        server.stubFor(post(urlEqualTo("${BASE_PATH}/bc-authorize"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(JsonOutput.toJson([
                    auth_req_id: authReqId,
                    expires_in : expiresIn,
                    interval   : interval
                ]))
                .withTransformers(BC_AUTHORIZE_TRANSFORMER)))
    }

    /**
     * Stub the token endpoint with stateful CIBA polling behaviour.
     *
     * Uses WireMock's {@link Scenario} API to return
     * {@code authorization_pending} for the first {@code pendingCount} polls
     * and then a dynamically generated token response. The ID token's
     * {@code sub} claim comes from the {@code login_hint} of the preceding
     * bc-authorize request, and the {@code aud} claim comes from the
     * {@code client_id} in the Basic auth header.
     *
     * @param pendingCount  Number of polls that return {@code authorization_pending} (default 1)
     * @param accessToken   The {@code access_token} value in the success response
     * @param expiresIn     Lifetime of the access token in seconds (default 300)
     */
    void stubTokenEndpoint(int pendingCount = 1) {

        def scenarioName = "CIBA Token Polling"
        def tokenPath = "${BASE_PATH}/token"

        def pendingBody = JsonOutput.toJson([
            error            : "authorization_pending",
            error_description: "The authorization request is still pending"
        ])

        // Register pending responses, each transitioning to the next state
        for (int i = 0; i < pendingCount; i++) {
            def currentState = (i == 0) ? Scenario.STARTED : "PENDING_${i}"
            def nextState = "PENDING_${i + 1}"

            server.stubFor(post(urlEqualTo(tokenPath))
                .inScenario(scenarioName)
                .whenScenarioStateIs(currentState)
                .willSetStateTo(nextState)
                .willReturn(aResponse()
                    .withStatus(400)
                    .withHeader("Content-Type", "application/json")
                    .withBody(pendingBody)))
        }

        // Register the success response with the dynamic transformer
        def finalState = "PENDING_${pendingCount}"
        server.stubFor(post(urlEqualTo(tokenPath))
            .inScenario(scenarioName)
            .whenScenarioStateIs(finalState)
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withTransformers(TOKEN_TRANSFORMER)))
    }

    /**
     * Stub the userinfo endpoint to return user claims.
     * The subject is looked up from the access token issued by the token endpoint.
     */
    void stubUserInfoEndpoint() {
        server.stubFor(get(urlEqualTo("${BASE_PATH}/userinfo"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withTransformers(USERINFO_TRANSFORMER)))
    }

    // ----------------------------------------------------- private stubs

    private void stubDiscoveryEndpoint() {
        def baseUrl = "http://host.testcontainers.internal:${port}${BASE_PATH}"

        def discoveryDocument = [
            issuer                                    : "${baseUrl}/",
            authorization_endpoint                    : "${baseUrl}/authorize",
            token_endpoint                            : "${baseUrl}/token",
            userinfo_endpoint                         : "${baseUrl}/userinfo",
            jwks_uri                                  : "${baseUrl}/jwks",
            backchannel_authentication_endpoint       : "${baseUrl}/bc-authorize",
            response_types_supported                  : ["code"],
            subject_types_supported                   : ["pairwise"],
            grant_types_supported                     : ["authorization_code", "urn:openid:params:grant-type:ciba"],
            backchannel_token_delivery_modes_supported: ["poll"]
        ]

        server.stubFor(get(urlEqualTo("${BASE_PATH}/.well-known/openid-configuration"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(JsonOutput.toJson(discoveryDocument))))

        // JWKS endpoint (required by OpenIdDiscoveryManagedObject even though we use userinfo)
        server.stubFor(get(urlEqualTo("${BASE_PATH}/jwks"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(JsonOutput.toJson([keys: []]))))
    }

    // ------------------------------------------------- form body parsing

    private static Map<String, String> parseFormBody(String body) {
        if (!body) return [:]
        body.split("&").collectEntries { param ->
            def parts = param.split("=", 2)
            [(URLDecoder.decode(parts[0], "UTF-8")): parts.length > 1 ? URLDecoder.decode(parts[1], "UTF-8") : ""]
        }
    }

    private static String extractClientId(String authHeader) {
        if (!authHeader?.startsWith("Basic ")) return null
        def decoded = new String(Base64.decoder.decode(authHeader.substring(6)))
        decoded.split(":", 2)[0]
    }

    // ------------------------------------------- WireMock transformers

    /**
     * Captures the {@code login_hint} from bc-authorize requests and stores
     * it so the token transformer can use it as the ID token subject.
     *
     * Validates that:
     * <ul>
     *   <li>The {@code login_hint} is present</li>
     *   <li>The {@code login_hint} matches the {@code urn:msisdn:} format</li>
     *   <li>The user is registered (added via {@link MockVippsService#registerUser})</li>
     * </ul>
     */
    private class BcAuthorizeCaptureTransformer implements ResponseDefinitionTransformerV2 {

        @Override
        ResponseDefinition transform(ServeEvent serveEvent) {
            def body = serveEvent.request.bodyAsString
            _logger.info("Incoming authentication request: $body")

            def params = parseFormBody(body)
            if (!params.login_hint) {
                return new ResponseDefinitionBuilder()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json")
                        .withBody(JsonOutput.toJson([
                                error: "invalid_request",
                                error_description : "Missing login_hint",
                        ]))
                        .build()
            }

            def loginHint = params.login_hint

            // Validate login_hint format
            if (!(loginHint ==~ MSISDN_PATTERN)) {
                _logger.info("Invalid login_hint format: $loginHint")
                return new ResponseDefinitionBuilder()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json")
                        .withBody(JsonOutput.toJson([
                                error            : "invalid_request",
                                error_description: "login_hint.value : Invalid login_hint. login_hint must be in format: 'urn:msisdn:46|45|47|358|299{phonenumber}'.",
                        ]))
                        .build()
            }

            // Check that the user is registered
            if (!registeredUsers.contains(loginHint)) {
                _logger.info("Unregistered user: $loginHint")
                return new ResponseDefinitionBuilder()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json")
                        .withBody(JsonOutput.toJson([
                                error            : "unknown_user_id",
                                error_description: "To log in with Vipps you need to have an active Vipps app on your phone and be at least 15 years old.",
                        ]))
                        .build()
            }

            def authReqId = UUID.randomUUID().toString()
            _logger.info("Storing authn request with id $authReqId for subject $loginHint")
            authnRequests.put(authReqId, loginHint)
            return new ResponseDefinitionBuilder()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(JsonOutput.toJson([
                            auth_req_id: authReqId,
                            expires_in : 300,
                            interval   : 5
                    ]))
                    .build()

        }

        @Override
        String getName() { BC_AUTHORIZE_TRANSFORMER }

        @Override
        boolean applyGlobally() { false }
    }

    /**
     * Dynamically builds the token success response.
     * Stores the access token → subject mapping so that the userinfo
     * endpoint can return the correct claims.
     */
    private class CibaTokenTransformer implements ResponseDefinitionTransformerV2 {

        @Override
        ResponseDefinition transform(ServeEvent serveEvent) {
            def request = serveEvent.request
            def params = parseFormBody(request.bodyAsString)
            _logger.info("Incoming token request params: $params")

            def authReqId = params.auth_req_id
            if(!authnRequests.containsKey(authReqId)) {
                _logger.info("Unknown auth_req_id $authReqId. Denying authentication")
                return new ResponseDefinitionBuilder()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json")
                        .withBody(JsonOutput.toJson([
                                error: "access_denied",
                                error_description : "unknown auth_req_id $authReqId",
                        ]))
                        .build()
            }

            def subject = authnRequests.remove(authReqId)
            def accessToken = UUID.randomUUID().toString()
            def expiresIn = 300

            // Store access token → subject mapping for userinfo lookups
            accessTokens.put(accessToken, subject)
            _logger.info("Issued access token $accessToken for subject $subject")

            def responseBody = JsonOutput.toJson([
                access_token: accessToken,
                token_type  : "Bearer",
                expires_in  : expiresIn
            ])

            return new ResponseDefinitionBuilder()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(responseBody)
                .build()
        }

        @Override
        String getName() { TOKEN_TRANSFORMER }

        @Override
        boolean applyGlobally() { false }
    }

    /**
     * Returns user claims based on the access token in the Authorization header.
     */
    private class UserInfoTransformer implements ResponseDefinitionTransformerV2 {

        @Override
        ResponseDefinition transform(ServeEvent serveEvent) {
            def request = serveEvent.request
            def authHeader = request.getHeader("Authorization")
            _logger.info("Incoming userinfo request with Authorization: $authHeader")

            if (!authHeader?.startsWith("Bearer ")) {
                _logger.info("Missing or invalid Bearer token")
                return new ResponseDefinitionBuilder()
                        .withStatus(401)
                        .withHeader("Content-Type", "application/json")
                        .withBody(JsonOutput.toJson([
                                error: "invalid_token",
                                error_description: "Missing or invalid Bearer token"
                        ]))
                        .build()
            }

            def accessToken = authHeader.substring(7)
            def subject = accessTokens.get(accessToken)

            if (!subject) {
                _logger.info("Unknown access token: $accessToken")
                return new ResponseDefinitionBuilder()
                        .withStatus(401)
                        .withHeader("Content-Type", "application/json")
                        .withBody(JsonOutput.toJson([
                                error: "invalid_token",
                                error_description: "Unknown or expired access token"
                        ]))
                        .build()
            }

            _logger.info("Returning userinfo for subject: $subject")
            def responseBody = JsonOutput.toJson([
                sub: subject
            ])

            return new ResponseDefinitionBuilder()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(responseBody)
                .build()
        }

        @Override
        String getName() { USERINFO_TRANSFORMER }

        @Override
        boolean applyGlobally() { false }
    }
}
