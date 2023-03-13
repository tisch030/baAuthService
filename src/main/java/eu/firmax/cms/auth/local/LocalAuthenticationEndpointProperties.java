package eu.firmax.cms.auth.local;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configures the properties for endpoints that are related to the local authentication.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "companyy.auth.endpoint.local")
public class LocalAuthenticationEndpointProperties {

    /**
     * Relative URL to perform a local login (i.e. send to login form to).
     */
    private String loginEndpoint = "/api/auth/login";

}
