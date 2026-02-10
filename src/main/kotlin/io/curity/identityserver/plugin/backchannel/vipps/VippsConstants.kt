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

/** Constants used throughout the Vipps authenticator plugin */
object VippsConstants {
    // Session keys
    const val SESSION_AUTH_REQ_ID = "vipps-auth-req-id"
    const val SESSION_ACCESS_TOKEN = "vipps-access-token"

    // HTTP Headers
    const val HEADER_AUTHORIZATION = "Authorization"

    const val PARAM_SCOPE = "scope"
    const val PARAM_LOGIN_HINT = "login_hint"
    const val PARAM_BINDING_MESSAGE = "binding_message"
    const val PARAM_GRANT_TYPE = "grant_type"
    const val PARAM_AUTH_REQ_ID = "auth_req_id"

    const val RESPONSE_AUTH_REQ_ID = "auth_req_id"
    const val RESPONSE_ACCESS_TOKEN = "access_token"
    const val RESPONSE_ID_TOKEN = "id_token"
    const val RESPONSE_ERROR = "error"
    const val RESPONSE_ERROR_DESCRIPTION = "error_description"

    // CIBA grant type
    const val GRANT_TYPE_CIBA = "urn:openid:params:grant-type:ciba"

    // CIBA error codes
    const val ERROR_AUTHORIZATION_PENDING = "authorization_pending"
    const val ERROR_SLOW_DOWN = "slow_down"
    const val ERROR_EXPIRED_TOKEN = "expired_token"
    const val ERROR_ACCESS_DENIED = "access_denied"
    const val ERROR_UNKNOWN_USER = "unknown_user"

    // Default scope
    const val DEFAULT_SCOPE = "openid"

    // Login hint format
    const val MSISDN_PREFIX = "urn:msisdn:"
}
