package io.curity.identityserver.plugin.backchannel.vipps

import io.curity.identityserver.plugins.oidc.OpenIdDiscoveryManagedObject
import java.util.Optional
import se.curity.identityserver.sdk.authentication.BackchannelAuthenticationHandler
import se.curity.identityserver.sdk.plugin.descriptor.BackchannelAuthenticatorPluginDescriptor

/**
 * Plugin descriptor for Vipps backchannel authenticator
 *
 * This descriptor registers the Vipps CIBA authenticator with the Curity Identity Server
 */
class VippsBackchannelAuthenticatorPluginDescriptor :
        BackchannelAuthenticatorPluginDescriptor<VippsAuthenticatorConfig> {
    /** Returns the unique plugin implementation type identifier */
    override fun getPluginImplementationType(): String = "vipps-backchannel"

    /** Returns the backchannel authentication handler class */
    override fun getBackchannelAuthenticationHandlerType():
            Class<out BackchannelAuthenticationHandler> =
            VippsBackchannelAuthenticationHandler::class.java

    /** Returns the configuration interface class */
    override fun getConfigurationType(): Class<out VippsAuthenticatorConfig> =
            VippsAuthenticatorConfig::class.java

    override fun createManagedObject(configuration: VippsAuthenticatorConfig) =
            Optional.of(
                    OpenIdDiscoveryManagedObject(configuration, configuration.openidConfiguration)
            )
}
