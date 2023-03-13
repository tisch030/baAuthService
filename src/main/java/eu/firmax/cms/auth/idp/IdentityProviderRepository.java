package eu.firmax.cms.auth.idp;

import edu.umd.cs.findbugs.annotations.NonNull;

import java.util.List;

/**
 * Base interface for classes/interfaces which implement a repository for {@link IdentityProvider} information.
 */
public interface IdentityProviderRepository {

    /**
     * Returns a list of all enabled {@link IdentityProvider}s sorted by priority in ascending order.
     *
     * @return a list of all enabled {@link IdentityProvider}s sorted by priority in ascending order.
     */
    @NonNull
    List<IdentityProvider> loadEnabledIdentityProvidersOrderedByPriority();

    /**
     * Returns the id of the given {@link IdentityProvider}s name.
     *
     * @return the id of the given {@link IdentityProvider}s name.
     */
    @NonNull
    String loadIdentityProviderId(@NonNull final String identityProviderName);
}
