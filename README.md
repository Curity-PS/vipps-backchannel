# Vipps Backchannel Authenticator Plugin

A Backchannel Authenticator plugin for the [Curity Identity Server](https://curity.io) that integrates with [Vipps](https://vipps.no) using the CIBA (Client Initiated Backchannel Authentication) polling flow.

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
