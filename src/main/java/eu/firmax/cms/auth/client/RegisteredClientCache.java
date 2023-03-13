package eu.firmax.cms.auth.client;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.security.authenticationConfiguration.AuthenticationConfigurationUpdatedCacheInvalidator;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

/**
 * Base interface for classes/interfaces which implement a cache for {@link RegisteredClient}s.
 */
public interface RegisteredClientCache extends AuthenticationConfigurationUpdatedCacheInvalidator {

    /**
     * Returns the {@link RegisteredClient} which matches the given registeredClientId.
     *
     * @param registeredClientId The id of the {@link RegisteredClient} which should be returned.
     * @return the {@link RegisteredClient} which matches the given registeredClientId.
     */
    @Nullable
    RegisteredClient getRegisteredClientById(@NonNull final String registeredClientId);
}
