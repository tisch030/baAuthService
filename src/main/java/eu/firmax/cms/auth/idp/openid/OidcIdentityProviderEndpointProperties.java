package eu.firmax.cms.auth.idp.openid;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configures the properties for endpoints that are related to a OIDC identity provider.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "companyx.auth.endpoint.oidc")
public class OidcIdentityProviderEndpointProperties {

    /**
     * Relative URL which acts as a base for the actual login endpoint.
     * The login endpoint which must be called to start the OpenID Connect authentication adds /{idpName} to that URL.
     */
    private String loginInitiateEndpoint = "/api/auth/sso/oidc/login";

    /**
     * Relative URL which is called by the OIDC Identity Provider after a login containing the response.
     */
    private String loginProcessingEndpoint = "/api/auth/sso/oidc/response/{registrationId}";
}
