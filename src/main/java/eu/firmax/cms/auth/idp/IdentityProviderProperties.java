package eu.firmax.cms.auth.idp;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Configures the properties to update the configuration of configured identity providers.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "companyx.auth.idp")
public class IdentityProviderProperties {

    /**
     * Cache duration of the identity provider information.
     * The default value is one day.
     */
    private Duration identityProviderCacheDuration = Duration.ofDays(1);
}
