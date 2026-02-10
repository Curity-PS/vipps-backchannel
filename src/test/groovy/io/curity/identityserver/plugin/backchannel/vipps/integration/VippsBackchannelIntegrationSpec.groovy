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

import groovy.json.JsonSlurper
import io.curity.identityserver.test.utils.CurityServerContainer
import spock.lang.Shared
import spock.lang.Specification

import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.SecureRandom
import java.security.cert.X509Certificate

/**
 * Integration test for Vipps Backchannel Authentication plugin
 *
 * This test starts a Curity Identity Server container with the plugin installed
 * and runs end-to-end CIBA flow tests.
 */
class VippsBackchannelIntegrationSpec extends Specification {

    static final String CLIENT_ID = "ciba-client"
    static final String CLIENT_SECRET = "ciba-secret"
    static final String SUBJECT = "4671234567"
    static final String SUBJECT_MSISDN = "urn:msisdn:$SUBJECT"

    @Shared
    MockVippsService mockVipps = new MockVippsService()

    @Shared
    CurityServerContainer curityServer

    @Shared
    HttpClient httpClient

    def setupSpec() {
        httpClient = HttpClient.newBuilder()
                .sslContext(createTrustAllSslContext())
                .build()

        mockVipps.start()
        mockVipps.stubStartAuthentication()
        mockVipps.stubTokenEndpoint()
        mockVipps.stubUserInfoEndpoint()

        curityServer = new CurityServerContainer(
                "src/test/resources/vipps-config.xml",
                "build/release/vipps-backchannel"
        )
        curityServer.start()
    }

    def setup() {
        mockVipps.resetRequests()
        mockVipps.registerUser(SUBJECT_MSISDN)
    }

    def cleanupSpec() {
        curityServer?.stop()
        mockVipps?.stop()
    }

    def "Full CIBA flow completes after polling"() {
        given: "server is configured with Vipps authenticator"
        def runtimeUrl = curityServer.runtimeUrl

        when: "initiating backchannel authentication"
        def bcResponse = startCibaFlow(runtimeUrl, SUBJECT_MSISDN)
        def bcBody = parseJson(bcResponse)
        def authReqId = bcBody.auth_req_id as String

        then: "a valid auth_req_id is returned"
        bcResponse.statusCode() == 200
        authReqId != null

        when: "polling the token endpoint"
        def firstPoll = pollTokenEndpoint(runtimeUrl, authReqId)
        def firstPollBody = parseJson(firstPoll)

        then: "The first poll return authorization_pending"
        firstPoll.statusCode() == 400
        firstPollBody.error == "authorization_pending"

        when: "Polling a second time"
        def secondPoll = pollTokenEndpoint(runtimeUrl, authReqId)
        def secondPollBody = parseJson(secondPoll)

        then: "Poll returns tokens"
        secondPoll.statusCode() == 200
        secondPollBody.access_token != null
        secondPollBody.token_type == "bearer"
        secondPollBody.expires_in != null
    }

    def "login_hint already in urn:msisdn format is accepted"() {
        given: "a registered user and a properly formatted login_hint"
        def runtimeUrl = curityServer.runtimeUrl

        when: "initiating backchannel authentication with urn:msisdn format"
        def bcResponse = startCibaFlow(runtimeUrl, SUBJECT_MSISDN)
        def bcBody = parseJson(bcResponse)

        then: "Vipps accepts the request"
        bcResponse.statusCode() == 200
        bcBody.auth_req_id != null
    }

    def "Unregistered user is rejected by Vipps"() {
        given: "a user that is not registered with Vipps"
        def runtimeUrl = curityServer.runtimeUrl

        when: "initiating backchannel authentication for an unknown user"
        def bcResponse = startCibaFlow(runtimeUrl, "urn:msisdn:4799999999")

        then: "the request is rejected"
        bcResponse.statusCode() == 400
        parseJson(bcResponse)?.error == "unknown_user"
    }

    def "Invalid login_hint format is rejected by Vipps"() {
        given: "a login_hint that does not match the urn:msisdn format"
        def runtimeUrl = curityServer.runtimeUrl

        when: "initiating backchannel authentication with an invalid login_hint"
        def bcResponse = startCibaFlow(runtimeUrl, "invalid_hint")

        then: "the request is rejected"
        bcResponse.statusCode() == 400
        parseJson(bcResponse)?.error == "unknown_user"
    }

    private HttpResponse<String> startCibaFlow(String runtimeUrl, String loginHint = SUBJECT) {
        def request = HttpRequest.newBuilder()
                .uri(URI.create("${runtimeUrl}/oauth/v2/oauth-backchannel-authentication"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", basicAuth())
                .POST(HttpRequest.BodyPublishers.ofString("scope=openid&login_hint=$loginHint"))
                .build()

        httpClient.send(request, HttpResponse.BodyHandlers.ofString())
    }

    private HttpResponse<String> pollTokenEndpoint(String runtimeUrl, String authReqId) {
        def body = "grant_type=urn:openid:params:grant-type:ciba&auth_req_id=${authReqId}"
        def request = HttpRequest.newBuilder()
                .uri(URI.create("${runtimeUrl}/oauth/v2/oauth-token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", basicAuth())
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build()

        httpClient.send(request, HttpResponse.BodyHandlers.ofString())
    }

    private static String basicAuth() {
        "Basic ${"${CLIENT_ID}:${CLIENT_SECRET}".bytes.encodeBase64()}"
    }

    private static Map parseJson(HttpResponse<String> response) {
        new JsonSlurper().parseText(response.body()) as Map
    }

    private static SSLContext createTrustAllSslContext() {
        def trustAllCerts = [
                new X509TrustManager() {
                    X509Certificate[] getAcceptedIssuers() { null }

                    void checkClientTrusted(X509Certificate[] certs, String authType) {}

                    void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
        ] as TrustManager[]

        def sc = SSLContext.getInstance("TLS")
        sc.init(null, trustAllCerts, new SecureRandom())
        return sc
    }
}
