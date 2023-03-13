package eu.firmax.cms.auth.local;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Configures the properties that are related to the configuration of the local authentication.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "companyx.auth.local")
public class LocalAuthenticationProperties {

    /**
     * Cache duration of the local authentication settings.
     * The default value is one day.
     */
    private Duration localAuthenticationSettingsCacheDuration = Duration.ofDays(1);

    /**
     * Cache duration of the local authentication provider instance.
     * Authentication provider instances are created based upon the local authentication settings also loaded from
     * a cache.
     * So set {@link #localAuthenticationSettingsCacheDuration} accordingly.
     * The default value is one day.
     */
    private Duration authenticationProviderInstanceCacheDuration = Duration.ofDays(1);


}
