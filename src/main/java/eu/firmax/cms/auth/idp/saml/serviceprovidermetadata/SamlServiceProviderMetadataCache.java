package eu.firmax.cms.auth.idp.saml.serviceprovidermetadata;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.security.authenticationConfiguration.AuthenticationConfigurationUpdatedCacheInvalidator;

/**
 * Base interface for classes/interfaces which implement a cache for {@link SamlServiceProviderMetadata}.
 */
public interface SamlServiceProviderMetadataCache extends AuthenticationConfigurationUpdatedCacheInvalidator {

    /**
     * Returns the cached {@link SamlServiceProviderMetadata}.
     *
     * @return the cached {@link SamlServiceProviderMetadata}.
     */
    @NonNull
    SamlServiceProviderMetadata getMetadata();
}
