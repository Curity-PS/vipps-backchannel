# Agent Instructions for Vipps Backchannel Authenticator

This document provides context for AI agents working on this codebase.

## Project Overview

This is a **Vipps Backchannel Authenticator Plugin** for the Curity Identity Server. It implements the CIBA (Client-Initiated Backchannel Authentication) flow using Vipps as the authentication provider.

### What is CIBA?

CIBA allows a client to initiate authentication of a user on a different device. The flow:
1. Client sends a backchannel authentication request with a `login_hint` (phone number)
2. The authentication server forwards this to Vipps
3. User receives a push notification on their phone to approve
4. Client polls the token endpoint until authentication completes
5. On success, tokens are returned

### Key Technologies

- **Kotlin** - Main implementation language
- **Curity SDK** - Plugin framework (`se.curity.identityserver:identityserver.sdk`)
- **Groovy/Spock** - Testing framework
- **TestContainers** - Integration testing with real Curity server
- **WireMock** - Mocking Vipps endpoints in tests
- **Gradle** - Build system with `io.curity.gradle.curity-plugin-dev` plugin

## Project Structure

```
src/
├── main/kotlin/io/curity/identityserver/plugin/backchannel/vipps/
│   ├── VippsBackchannelAuthenticatorPluginDescriptor.kt  # Plugin registration
│   ├── VippsAuthenticatorConfig.kt                       # Configuration interface
│   ├── VippsBackchannelAuthenticationHandler.kt          # Main CIBA handler
│   ├── VippsBackchannelClient.kt                         # HTTP client for Vipps API
│   └── VippsConstants.kt                                 # Constants
├── main/resources/
│   └── META-INF/services/                                # Plugin service loader config
└── test/
    ├── groovy/.../integration/
    │   ├── VippsBackchannelIntegrationSpec.groovy        # E2E integration tests
    │   └── MockVippsService.groovy                       # WireMock-based mock Vipps
    └── resources/
        └── vipps-config.xml                              # Test Curity configuration
```

## Development Commands

### Building

```bash
./gradlew build          # Full build with tests
./gradlew compileKotlin  # Compile only
./gradlew jar            # Build plugin JAR
```

### Testing

```bash
# Unit tests (fast, no external dependencies)
./gradlew test

# Integration tests (requires LICENSE_KEY, starts Docker containers)
./gradlew integrationTest
```

**Integration Test Requirements:**
- Docker must be running
- `LICENSE_KEY` environment variable must be set with a valid Curity license
- Tests start a real Curity Identity Server container
- WireMock mocks the Vipps API on port 8888

**Test Naming Convention:**
- Unit tests: `*Test.groovy` or `*Spec.groovy` (not in `integration` package)
- Integration tests: `*IntegrationSpec.groovy` (in `integration` package)

### Deployment

```bash
# Deploy to local Curity server
./gradlew deployToLocal
# Requires: IDSVR_HOME environment variable pointing to Curity installation

# Create release package
./gradlew createReleaseDir
# Output: build/vipps-backchannel/ (copy to $IDSVR_HOME/usr/share/plugins/)
```

## Key Implementation Details

### Authentication Flow

1. **startAuthentication()** - Called when CIBA request received
   - Validates `login_hint` has `urn:msisdn:` prefix (Norwegian phone number format)
   - Calls Vipps `/bc-authorize` endpoint
   - Stores Vipps `auth_req_id` in session

2. **checkAuthenticationStatus()** - Called on each poll from client
   - Retrieves `auth_req_id` from session
   - Polls Vipps token endpoint with CIBA grant type
   - Handles responses: `authorization_pending`, `slow_down`, success, or failure
   - On success: fetches user claims from userinfo endpoint

3. **User Claims** - Vipps returns claims returned from userinfo endpoint (not in ID token)
   - Plugin calls userinfo with access_token as Bearer
   - Extracts `sub` claim for subject
   - Additional claims become subject attributes

### Configuration

The plugin is configured in Curity admin UI or XML:

```xml
<backchannel-authenticator>
    <id>vipps</id>
    <vipps-backchannel xmlns="https://curity.se/ns/ext-conf/vipps-backchannel">
        <client-id>your-client-id</client-id>
        <client-secret>your-client-secret</client-secret>
        <scopes>nin</scopes>  <!-- Optional additional scopes -->
        <openid-configuration>
            <http-client><id>default</id></http-client>
            <issuer>https://api.vipps.no/access-management-1.0/access/</issuer>
        </openid-configuration>
    </vipps-backchannel>
</backchannel-authenticator>
```

### Vipps API Endpoints (via OpenID Discovery)

- `backchannel_authentication_endpoint` - POST `/bc-authorize`
- `token_endpoint` - POST `/token` (CIBA polling)
- `userinfo_endpoint` - GET `/userinfo` (user claims)
- `jwks_uri` - GET `/jwks` (required by SDK, but not used for ID token validation)

### Login Hint Format

Vipps requires phone numbers in `urn:msisdn:{country_code}{number}` format:
- `urn:msisdn:4712345678` (Norway +47)
- Supported country codes: 46 (Sweden), 45 (Denmark), 47 (Norway), 358 (Finland), 299 (Greenland)

## Testing Architecture

### MockVippsService

WireMock-based mock that simulates Vipps CIBA behavior:

- Uses `ResponseDefinitionTransformerV2` for dynamic responses
- Captures `login_hint` from bc-authorize, uses as `sub` in userinfo
- Simulates polling with configurable pending count
- Validates login_hint format and registered users

Key methods:
```groovy
mockVipps.registerUser("urn:msisdn:4712345678")  // Must register before auth
mockVipps.stubStartAuthentication()              // Stub bc-authorize
mockVipps.stubTokenEndpoint(pendingCount: 1)     // Stub token with polling
mockVipps.stubUserInfoEndpoint()                 // Stub userinfo
```

### Integration Test Pattern

```groovy
def setupSpec() {
    mockVipps.start()
    mockVipps.stubStartAuthentication()
    mockVipps.stubTokenEndpoint()
    mockVipps.stubUserInfoEndpoint()

    curityServer = new CurityServerContainer(
        "src/test/resources/vipps-config.xml",
        "build/vipps-backchannel"
    )
    curityServer.start()
}

def setup() {
    mockVipps.resetRequests()
    mockVipps.registerUser(SUBJECT_MSISDN)
}
```

## Dependencies

### Runtime (compileOnly - provided by Curity)
- `se.curity.identityserver:identityserver.sdk:10.7.1`
- `org.jetbrains.kotlin:kotlin-stdlib`
- `org.slf4j:slf4j-api`

### Implementation
- `io.curity:curity-ps-sdk-commons:0.3.0` - Shared utilities including `OpenIdDiscoveryManagedObject`

### Test
- `org.spockframework:spock-core:2.3-groovy-4.0`
- `org.testcontainers:testcontainers:2.0.3`
- `org.wiremock:wiremock:3.12.0`

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `LICENSE_KEY` | Integration tests | Curity license key |
| `IDSVR_HOME` | deployToLocal | Path to Curity installation |
| `GITHUB_ACTOR` | Build | GitHub username for private repos |
| `GITHUB_TOKEN` | Build | GitHub PAT for private repos |

## Common Issues

### Port 8888 Already in Use
MockVippsService uses port 8888. If tests fail with bind errors:
```bash
lsof -i :8888  # Find process
kill <PID>     # Kill it
```

### Missing jwks_uri Error
The OpenIdDiscoveryManagedObject requires `jwks_uri` in discovery document, even though this plugin uses userinfo instead of ID token validation. The mock returns an empty JWKS (`{"keys": []}`).

### Container Timeout
If CurityServerContainer times out:
- Ensure Docker is running
- Check LICENSE_KEY is valid
- Increase timeout in test if needed

## Curity SDK Concepts

### BackchannelAuthenticatorPluginDescriptor
Registers the plugin with Curity. Returns:
- `pluginImplementationType` - Unique identifier ("vipps-backchannel")
- `backchannelAuthenticationHandlerType` - Handler class
- `configurationType` - Config interface
- `createManagedObject` - Returns OpenIdDiscoveryManagedObject for OIDC metadata

### BackchannelAuthenticationHandler
Interface for CIBA authentication:
- `startAuthentication(authReqId, request)` - Initiate auth
- `checkAuthenticationStatus(authReqId)` - Poll status
- `cancelAuthenticationRequest(authReqId)` - Cancel

### BackchannelAuthenticatorState
- `STARTED` - Waiting for user approval
- `SUCCEEDED` - Authentication successful
- `FAILED` - Authentication denied/failed
- `EXPIRED` - Request timed out
- `UNKNOWN` - Error state

### OpenIdDiscoveryManagedObject
Handles OIDC discovery document fetching and caching. Provides:
- `tokenEndpoint` - Token endpoint URI
- `backChannelAuthenticationEndpoint` - CIBA endpoint URI
- `getConfigurationValueOfType(type, key)` - Get custom values (e.g., userinfo_endpoint)
- `httpClient` - Configured HTTP client for API calls