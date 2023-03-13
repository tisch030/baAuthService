package eu.firmax.cms.auth.idp.openid;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;


/**
 * Configures the properties to update the configuration of OIDC identity providers.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "companyx.auth.idp.oidc")
public class OidcIdentityProviderProperties {

    /**
     * Each OIDC Identity Provider has metadata which it uses to provide us with information about its URLs and
     * certificates.
     * Since the certificates have a limited lifetime and URLs can change, the metadata must be updated regularly,
     * although not in very short intervals.
     * The default value is one day.
     */
    private Duration refreshMetadataInterval = Duration.ofDays(1);
}
