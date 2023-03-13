package eu.firmax.cms.auth.idp;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.security.authenticationConfiguration.AuthenticationConfigurationUpdatedCacheInvalidator;

import java.util.List;

/**
 * Base interface for classes/interfaces which implement a cache for {@link IdentityProvider}s.
 */
public interface IdentityProviderCache extends AuthenticationConfigurationUpdatedCacheInvalidator {

    /**
     * Returns all {@link IdentityProvider}s that are cached.
     *
     * @return all {@link IdentityProvider}s that are cached.
     */
    @NonNull
    List<IdentityProvider> getIdentityProviders();

    /**
     * Returns the id of the given identity provider name that is cached.
     *
     * @return the id of the given identity provider name that is cached.
     */
    @NonNull
    String getIdentityProviderId(@NonNull final String identityProviderName);
}
