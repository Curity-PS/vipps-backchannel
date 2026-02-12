# Vipps Backchannel Authenticator Plugin

A Backchannel Authenticator plugin for the [Curity Identity Server](https://curity.io) that integrates with [Vipps](https://vipps.no) using the CIBA (Client Initiated Backchannel Authentication) polling flow.

## Functionality

The plugin acts as an authenticator for CIBA flows and creates an authentication transaction for the user to approve in the Vipps mobile app.

- **Mobile Authentication**: Creates authentication transactions that users approve in the Vipps mobile app
- **Binding Messages**: Supports sending binding messages that are displayed to the user in the app for additional context and security
- **Login Hint Format**: Clients are expected to send `login_hint` in MSISDN format (e.g., `urn:msisdn:4712345678` for Norwegian mobile phone numbers)

The authenticator will call the Vipps `userinfo` endpoint to retrieve user claims after successful authentication. The `login_hint` is used as the subject identifier in Curity, and additional claims are added as subject attributes.

## Configuration

Configure the following parameters in the Curity Identity Server admin UI when setting up the Vipps Backchannel Authenticator:

### Required Parameters

- **Client ID** — Your Vipps client identifier obtained from the Vipps developer portal
- **Client Secret** — Your Vipps client secret for authentication

### OpenID Configuration

- **HTTP Client** — Optionally select an HTTP client to use for communication with Vipps
- **Issuer** — The Vipps issuer URL:
  - **Test environment**: `https://apitest.vipps.no/access-management-1.0/access/`
  - **Production environment**: `https://api.vipps.no/access-management-1.0/access/`

### Optional Parameters

- **Scopes** — Additional scopes to request from Vipps (e.g., `nin` for Norwegian national identity number). The `openid` scope is always included in the request.

## Deployment

### Option 1 — Download a release

Download the latest release archive from the [Releases](../../releases) page, unzip it, and copy the folder to your Curity installation:

```
/opt/idsvr/usr/share/plugins/vipps-backchannel
```

Restart the Curity Identity Server to load the plugin.

### Option 2 — Build from source

#### Prerequisites

This project uses dependencies hosted on GitHub Packages. You need to configure your GitHub credentials in `~/.gradle/gradle.properties`:

1. Create a [GitHub Personal Access Token](https://github.com/settings/tokens) with the `read:packages` scope.

2. Add the following to your `~/.gradle/gradle.properties` file (create it if it doesn't exist):

   ```properties
   gpr.user=YOUR_GITHUB_USERNAME
   gpr.token=YOUR_GITHUB_TOKEN
   ```

#### Build

```bash
./gradlew createReleaseDir
```

Then copy the output folder to your server:

```bash
cp -r build/release/vipps-backchannel /opt/idsvr/usr/share/plugins/
```

### Option 3 — Deploy to a local server

```bash
IDSVR_HOME=/opt/idsvr ./gradlew deployToLocal
```

## Testing

Run unit tests:

```bash
./gradlew test
```

Run integration tests (requires a valid Curity license key and Docker):

```bash
LICENSE_KEY=<license-jwt> ./gradlew integrationTest
```

### Using a `.env` file

Instead of passing environment variables on the command line you can create a `.env` file in the project root:

```
LICENSE_KEY=<license-jwt>
IDSVR_HOME=/opt/idsvr
```

The `.env` file is listed in `.gitignore` and will not be committed.

## More Information

Visit [curity.io](https://curity.io) for documentation and guides on the Curity Identity Server.

## License

This plugin is licensed under the [Apache License 2.0](LICENSE).
