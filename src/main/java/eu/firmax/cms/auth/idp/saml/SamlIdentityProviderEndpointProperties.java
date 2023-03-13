package eu.firmax.cms.auth.idp.saml;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configures the properties for endpoints that are related to a SAML identity provider.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "companyx.auth.endpoint.saml")
public class SamlIdentityProviderEndpointProperties {

    /**
     * Relative URL used to start a SAML authentication procedure.
     */
    private String loginInitiateEndpoint = "/api/auth/sso/saml/login/{idpName}";

    /**
     * Relative URL called by the identity provider after a successful authentication with the SAML response.
     */
    private String loginProcessingEndpoint = "/api/auth/sso/saml/response/{registrationId}";

    /**
     * Relative URL called by the identity provider to initiate a logout (used for single sign-out).
     */
    private String logoutRequestEndpoint = "/api/auth/sso/saml/logout/";

    /**
     * Relative URL called by the identity provider after a successful logout which was initiated by us.
     */
    private String logoutResponseEndpoint = "/api/auth/sso/saml/logout/";

    /**
     * Relative URL used to retrieve the SAML metadata which need to be known the by identity provider.
     */
    private String spMetaDataEndpoint = "/.well-known/saml-metadata/{registrationId}";
}
