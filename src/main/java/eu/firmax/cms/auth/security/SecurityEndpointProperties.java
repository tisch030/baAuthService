package eu.firmax.cms.auth.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configures the properties for endpoints that are related to the security functionality of the authorization server.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "companyx.auth.endpoint.security")
public class SecurityEndpointProperties {

    /**
     * Relative URL used to start an authentication.
     * This endpoint will redirect the user to the page which handles the authentication depending on the configuration.
     */
    private String authorizeEndpoint = "/api/auth/authorize";

    /**
     * Relative URL used to retrieve the access/id tokens.
     */
    private String tokenEndpoint = "/api/auth/token";

    /**
     * Relative URL used to retrieve the currently active JWK Set.
     */
    private String jwksEndpoint = "/api/auth/jwks";

    /**
     * Relative URL used to handle the correct issuing of the authorization code.
     * We have to make sure that the user f.e provided a mapping from identity provider
     * authentication information to a local authentication before issuing the code.
     */
    private String loginResultEndpoint = "/api/auth/result";

    /**
     * Relative URL used to perform a logout for an already authenticated user.
     */
    private String logoutInitiateEndpoint = "/api/auth/logout";

    /**
     * Relative URL used to display the mapping form where users can associate
     * their authentication with an identity provider with their local access.
     */
    private String idpMapperEndpoint = "/api/auth/idp-mapping";

}
